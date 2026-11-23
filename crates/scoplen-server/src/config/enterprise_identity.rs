// SPDX-License-Identifier: AGPL-3.0-only
//! Deployment-only trust configuration for Organization login tests.

use std::{collections::HashSet, fmt, fs, net::IpAddr, path::PathBuf};

use ipnet::IpNet;
use scoplen_api::auth_connection_draft::validate_issuer;
use serde::Deserialize;

use super::ConfigError;

/// Operator trust for the optional enterprise connection, empty by default.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnterpriseIdentitySettings {
    /// Exact issuers and the networks the deployment operator explicitly admits.
    pub trusted_issuers: Vec<TrustedIssuerSettings>,
}

/// Trust for one exact issuer, with an optional deployment CA.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedIssuerSettings {
    /// Exact HTTPS issuer, including its path and trailing slash if present.
    pub issuer: String,
    /// Nonempty list of admitted address CIDRs.
    pub addresses: Vec<String>,
    /// PEM CA bundle supplementing system trust.
    pub ca_certificate: Option<PathBuf>,
}

impl fmt::Debug for TrustedIssuerSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("TrustedIssuerSettings").finish_non_exhaustive()
    }
}

impl EnterpriseIdentitySettings {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        let mut issuers = HashSet::new();
        for (index, entry) in self.trusted_issuers.iter().enumerate() {
            let invalid = |field: &str, detail: &str| {
                ConfigError::Invalid(format!(
                    "enterprise_identity.trusted_issuers[{index}].{field} {detail}"
                ))
            };
            validate_issuer(&entry.issuer)
                .map_err(|_| invalid("issuer", "must be a valid HTTPS issuer"))?;
            if !issuers.insert(&entry.issuer) {
                return Err(invalid("issuer", "duplicates another trusted issuer"));
            }
            entry
                .networks()
                .map_err(|()| invalid("addresses", "must contain valid IPv4 or IPv6 CIDRs"))?;
            entry.read_ca().map_err(|()| {
                invalid("ca_certificate", "must be a readable PEM certificate bundle")
            })?;
        }
        Ok(())
    }
}

pub(crate) struct IssuerCa {
    pub(crate) pem: Vec<u8>,
    pub(crate) certificates: Vec<rustls::pki_types::CertificateDer<'static>>,
}

impl TrustedIssuerSettings {
    pub(crate) fn networks(&self) -> Result<Vec<IpNet>, ()> {
        let mut networks = Vec::new();
        for value in &self.addresses {
            let mut network = value.parse::<IpNet>().map_err(|_| ())?.trunc();
            if let IpNet::V6(v6) = network
                && let Some(ip) = v6.addr().to_ipv4_mapped()
            {
                network = IpNet::new(IpAddr::V4(ip), v6.prefix_len() - 96).map_err(|_| ())?;
            }
            networks.push(network);
        }
        if networks.is_empty() {
            return Err(());
        }
        networks.sort_unstable();
        networks.dedup();
        Ok(networks)
    }

    pub(crate) fn read_ca(&self) -> Result<Option<IssuerCa>, ()> {
        let Some(path) = &self.ca_certificate else { return Ok(None) };
        if !path.metadata().map_err(|_| ())?.is_file() {
            return Err(());
        }
        let pem = fs::read(path).map_err(|_| ())?;
        let mut roots = rustls::RootCertStore::empty();
        let mut certificates = Vec::new();
        for item in rustls_pemfile::read_all(&mut pem.as_slice()) {
            let rustls_pemfile::Item::X509Certificate(certificate) = item.map_err(|_| ())? else {
                return Err(());
            };
            roots.add(certificate.clone()).map_err(|_| ())?;
            certificates.push(certificate);
        }
        if certificates.is_empty() {
            return Err(());
        }
        Ok(Some(IssuerCa { pem, certificates }))
    }
}

#[cfg(test)]
mod tests {
    use crate::Config;

    const CONFIG: &str = r#"
        [[enterprise_identity.trusted_issuers]]
        issuer = "https://auth.example.test/issuer/"
        addresses = ["192.0.2.10/32", "2001:db8::10/128"]
    "#;

    #[test]
    fn issuer_trust_defaults_closed_and_preserves_exact_distinct_paths() {
        assert!(Config::default().enterprise_identity.trusted_issuers.is_empty());
        let second = CONFIG.replace("/issuer/", "/issuer");
        let config: Config = toml::from_str(&format!("{CONFIG}{second}")).expect("parse trust");
        config.validate().expect("validate trust offline");
        let entries = &config.enterprise_identity.trusted_issuers;
        assert_eq!(entries[0].issuer, "https://auth.example.test/issuer/");
        assert_eq!(entries[1].issuer, "https://auth.example.test/issuer");
        assert!(!format!("{config:?}").contains("auth.example.test"));
        assert!(!format!("{config:?}").contains("192.0.2.10"));
    }

    #[test]
    fn issuer_trust_rejects_duplicate_issuers_missing_networks_and_bad_values() {
        for (source, field) in [
            (format!("{CONFIG}{CONFIG}"), "issuer"),
            (CONFIG.replace("https:", "http:"), "issuer"),
            (CONFIG.replace("/issuer/", "/issuer?extra=1"), "issuer"),
            (CONFIG.replace("\"192.0.2.10/32\", \"2001:db8::10/128\"", ""), "addresses"),
            (CONFIG.replace("2001:db8::10/128", "2001:db8::10/129"), "addresses"),
            (CONFIG.replace("192.0.2.10/32", "192.0.2.10"), "addresses"),
        ] {
            let config: Config = toml::from_str(&source).expect("parse invalid trust values");
            let error = config.validate().expect_err("reject invalid trust").to_string();
            assert!(error.starts_with("enterprise_identity.trusted_issuers["));
            assert!(error.contains(&format!("].{field} ")));
            assert!(!error.contains("example.test"));
        }
        assert!(toml::from_str::<Config>(&format!("{CONFIG}\naddress = []")).is_err());
    }

    #[test]
    fn issuer_trust_validates_the_private_ca_file_without_disclosing_its_path() {
        let mut config: Config = toml::from_str(CONFIG).expect("parse trust");
        let path =
            std::env::temp_dir().join(format!("scoplen-issuer-trust-{}.pem", uuid::Uuid::new_v4()));
        config.enterprise_identity.trusted_issuers[0].ca_certificate = Some(path.clone());
        let missing = config.validate().expect_err("missing CA").to_string();
        let mut params = rcgen::CertificateParams::new(Vec::new()).expect("fixture parameters");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().expect("fixture key");
        let ca = params.self_signed(&key).expect("fixture CA").pem();
        std::fs::write(&path, &ca).expect("write CA fixture");
        let accepted = config.validate();
        std::fs::write(&path, format!("{ca}{}", key.serialize_pem()))
            .expect("write invalid bundle");
        let malformed = config.validate();
        std::fs::remove_file(&path).expect("remove CA fixture");

        accepted.expect("valid private CA");
        for error in [missing, malformed.expect_err("reject private key in CA bundle").to_string()]
        {
            assert!(error.contains("enterprise_identity.trusted_issuers[0].ca_certificate"));
            assert!(!error.contains("scoplen-issuer-trust-"));
        }
    }
}
