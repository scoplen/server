// SPDX-License-Identifier: AGPL-3.0-only
//! Operator-controlled network and TLS admission for a draft login provider.

use std::{io, net::IpAddr, sync::Arc, time::Duration};

use ipnet::IpNet;
use reqwest::{Certificate, Client, StatusCode, dns, header};
use scoplen_api::auth_connection_draft::validate_issuer;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::{Host, Url};

use crate::EnterpriseIdentitySettings;

use super::{ProviderMetadata, parse_discovery};

const DISCOVERY_LIMIT: usize = 65_536;

/// Fixed diagnostics for the draft login's outbound admission.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum DiscoveryError {
    /// This exact issuer is absent from the operator's trust policy.
    #[error("issuer is not trusted by this deployment")]
    Untrusted,
    /// The operator's trust material is no longer usable.
    #[error("issuer trust is unavailable")]
    InvalidTrust,
    /// An admitted provider could not be contacted or returned a transient failure.
    #[error("identity provider is unavailable")]
    Unavailable,
    /// The provider does not meet the draft login profile.
    #[error("identity provider metadata is incompatible")]
    Incompatible,
}

/// An immutable snapshot of trust for one exact issuer.
pub struct TrustedIssuer {
    issuer: String,
    url: Url,
    fingerprint: [u8; 32],
    client: Client,
}

impl TrustedIssuer {
    /// Load the operator's current network rules and trust anchors without resolving the issuer.
    ///
    /// # Errors
    /// Returns an error for an unapproved issuer, invalid trust material or a denied literal address.
    pub fn from_settings(
        settings: &EnterpriseIdentitySettings,
        issuer: &str,
    ) -> Result<Self, DiscoveryError> {
        let mut matching = settings.trusted_issuers.iter().filter(|item| item.issuer == issuer);
        let selected = matching.next().ok_or(DiscoveryError::Untrusted)?;
        if matching.next().is_some() {
            return Err(DiscoveryError::InvalidTrust);
        }
        validate_issuer(issuer).map_err(|_| DiscoveryError::InvalidTrust)?;
        let url = Url::parse(issuer).map_err(|_| DiscoveryError::InvalidTrust)?;
        let networks = selected.networks().map_err(|()| DiscoveryError::InvalidTrust)?;
        // HTTP connectors bypass DNS for IP literals.
        let literal = match url.host() {
            Some(Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
            Some(Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
            _ => None,
        };
        if literal.is_some_and(|ip| !allows(&networks, ip)) {
            return Err(DiscoveryError::Unavailable);
        }
        let ca = selected.read_ca().map_err(|()| DiscoveryError::InvalidTrust)?;
        let fingerprint = fingerprint(issuer, &networks, ca.as_ref().map(|ca| ca.pem.as_slice()));
        let mut builder = Client::builder()
            .tls_backend_rustls()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .retry(reqwest::retry::never())
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .dns_resolver(Arc::new(AdmittedResolver(networks.into())));
        if let Some(ca) = ca {
            let certificates = ca.certificates.iter().map(|der| Certificate::from_der(der));
            let certificates: Result<Vec<_>, _> = certificates.collect();
            builder =
                builder.tls_certs_merge(certificates.map_err(|_| DiscoveryError::InvalidTrust)?);
        }
        let client = builder.build().map_err(|_| DiscoveryError::InvalidTrust)?;
        Ok(Self { issuer: issuer.to_owned(), url, fingerprint, client })
    }

    /// Fingerprint for rechecking this snapshot against current deployment trust.
    #[must_use]
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Fetch bounded, credential-free metadata for the admitted HTTPS issuer.
    ///
    /// # Errors
    /// Returns a fixed error for transport failure, incompatible metadata or a denied destination.
    pub async fn discover(&self) -> Result<ProviderMetadata, DiscoveryError> {
        let discovery =
            format!("{}/.well-known/openid-configuration", self.issuer.trim_end_matches('/'));
        let mut response = self
            .client
            .get(discovery)
            .header(header::ACCEPT, "application/json")
            .header(header::ACCEPT_ENCODING, "identity")
            .send()
            .await
            .map_err(|_| DiscoveryError::Unavailable)?;
        let status = response.status();
        if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
            return Err(DiscoveryError::Unavailable);
        }
        if status != StatusCode::OK || !json_content_type(response.headers()) {
            return Err(DiscoveryError::Incompatible);
        }
        if response.content_length().is_some_and(|length| length > DISCOVERY_LIMIT as u64) {
            return Err(DiscoveryError::Incompatible);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| DiscoveryError::Unavailable)? {
            if chunk.len() > DISCOVERY_LIMIT - body.len() {
                return Err(DiscoveryError::Incompatible);
            }
            body.extend_from_slice(&chunk);
        }
        let document = parse_discovery(&body).map_err(|_| DiscoveryError::Incompatible)?;
        document
            .check(&self.issuer, Some(&self.url.origin()))
            .map_err(|_| DiscoveryError::Incompatible)?;
        Ok(document.into_metadata())
    }
}

fn json_content_type(headers: &header::HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn fingerprint(issuer: &str, networks: &[IpNet], ca: Option<&[u8]>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"scoplen/oidc-trusted-issuer/v1\0");
    hash.update((issuer.len() as u64).to_be_bytes());
    hash.update(issuer);
    hash.update((networks.len() as u64).to_be_bytes());
    for network in networks {
        match network {
            IpNet::V4(v4) => {
                hash.update([4, v4.prefix_len()]);
                hash.update(v4.addr().octets());
            }
            IpNet::V6(v6) => {
                hash.update([6, v6.prefix_len()]);
                hash.update(v6.addr().octets());
            }
        }
    }
    hash.update(ca.unwrap_or_default());
    hash.finalize().into()
}

struct AdmittedResolver(Arc<[IpNet]>);

impl dns::Resolve for AdmittedResolver {
    fn resolve(&self, name: dns::Name) -> dns::Resolving {
        let networks = Arc::clone(&self.0);
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((name.as_str(), 0)).await?;
            let admitted: Vec<_> =
                addresses.filter(|address| allows(&networks, address.ip())).collect();
            if admitted.is_empty() {
                return Err(io::Error::other("no permitted issuer address").into());
            }
            Ok(Box::new(admitted.into_iter()) as dns::Addrs)
        })
    }
}

fn allows(networks: &[IpNet], ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    if ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_link_local() || v4.is_broadcast() || networks.iter().any(|network| {
                matches!(network, IpNet::V4(range) if range.prefix_len() < 31 && v4 == range.broadcast())
            }) {
                return false;
            }
        }
        IpAddr::V6(v6) if v6.is_unicast_link_local() => return false,
        IpAddr::V6(_) => {}
    }
    let exact_prefix = if ip.is_ipv4() { 32 } else { 128 };
    networks.iter().any(|network| {
        network.contains(&ip) && (!ip.is_loopback() || network.prefix_len() == exact_prefix)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_admission_excludes_non_unicast_and_requires_exact_loopback() {
        let broad =
            ["0.0.0.0/0", "::/0", "192.0.2.0/24"].map(|value| value.parse().expect("fixture CIDR"));
        for denied in [
            "0.0.0.0",
            "::",
            "169.254.1.2",
            "fe80::1",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            "192.0.2.255",
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!allows(&broad, denied.parse().expect("fixture IP")), "{denied}");
        }
        for allowed in ["192.0.2.4", "::ffff:192.0.2.4", "2001:db8::1"] {
            assert!(allows(&broad, allowed.parse().expect("fixture IP")));
        }
        let exact = ["127.0.0.1/32", "::1/128"].map(|value| value.parse().expect("fixture CIDR"));
        for allowed in ["127.0.0.1", "::ffff:127.0.0.1", "::1"] {
            assert!(allows(&exact, allowed.parse().expect("fixture IP")));
        }
    }
}
