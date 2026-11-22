// SPDX-License-Identifier: AGPL-3.0-only
//! Read-only discovery and manual registration settings for an enterprise issuer.

use std::{path::PathBuf, process::ExitCode};

use clap::Subcommand;
use reqwest::{StatusCode, Url, header};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::diagnostic_http::{diagnostic_client, read_body, request_failure};

#[derive(Subcommand)]
pub enum Command {
    /// Check the instance's human sign-in metadata without registering a client.
    CheckInstance {
        /// Exact HTTPS issuer URL, including its path, if any.
        #[arg(long)]
        issuer: String,
        /// Add a private PEM CA to system trust.
        #[arg(long)]
        ca_certificate: Option<PathBuf>,
    },
    /// Print the confidential web client settings for manual registration, offline.
    RegistrationSettings {
        /// Existing local server configuration with the deployment's public HTTPS origin.
        #[arg(long, default_value = "spl-server.toml", env = "SPL_CONFIG")]
        config: PathBuf,
        /// Exact HTTPS issuer URL used for this registration.
        #[arg(long)]
        issuer: String,
    },
}

pub async fn run(command: Command) -> ExitCode {
    let result = match command {
        Command::CheckInstance { issuer, ca_certificate } => {
            check_instance(&issuer, ca_certificate.as_deref()).await.map(|()|
                "PASS: compatible human sign-in metadata. Register the application and verify a browser login before enabling access.".to_owned()
            )
        }
        Command::RegistrationSettings { config, issuer } => registration_settings(&config, &issuer),
    };
    match result {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("FAIL: {reason}");
            ExitCode::FAILURE
        }
    }
}

fn registration_settings(config: &std::path::Path, issuer: &str) -> Result<String, &'static str> {
    validate_issuer(issuer)?;
    let origin = crate::doctor::configured_origin(config)?;
    let hash = Sha256::digest(issuer.as_bytes());
    let settings = serde_json::json!({
        "redirect_uri": format!("{origin}/api/v1/auth/enterprise/oidc/{hash:x}/callback"),
        "response_type": "code",
        "grant_type": "authorization_code",
        "code_challenge_method": "S256",
        "scope": "openid",
        "token_endpoint_auth_method": "client_secret_basic"
    });
    Ok(format!("{settings:#}"))
}

fn https_url(value: &str) -> Option<Url> {
    if value.bytes().any(|b| b.is_ascii_control() || b == b' ' || b == b'\\') {
        return None;
    }
    let (_, tail) = value.split_once("://")?;
    let authority = tail.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let url = Url::parse(value).ok()?;
    (url.scheme() == "https"
        && url.has_host()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none())
    .then_some(url)
}

fn validate_issuer(issuer: &str) -> Result<(), &'static str> {
    if https_url(issuer).is_none_or(|url| url.query().is_some()) {
        return Err("provide an absolute HTTPS issuer without credentials, query or fragment.");
    }
    Ok(())
}

async fn check_instance(issuer: &str, ca: Option<&std::path::Path>) -> Result<(), &'static str> {
    validate_issuer(issuer)?;
    let client = diagnostic_client(ca)?;
    let discovery = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let response = client
        .get(discovery)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|err| request_failure(&err))?;
    if response.status() != StatusCode::OK {
        return Err(
            "discovery did not return HTTP 200; check the issuer and reverse-proxy routing.",
        );
    }
    if !response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(
            "discovery must return application/json; check the instance and proxy configuration.",
        );
    }
    let body = read_body(response, 65_536, "discovery exceeds the 64 KiB limit.").await?;
    let document: Discovery = serde_json::from_slice(&body).map_err(
        |_| "invalid discovery document; check its JSON, field types and required endpoints.",
    )?;
    document.check(issuer)
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    response_types_supported: Vec<String>,
    grant_types_supported: Option<Vec<String>>,
    #[serde(default = "default_token_auth_methods")]
    token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    scopes_supported: Vec<String>,
    #[serde(default)]
    subject_types_supported: Vec<String>,
    #[serde(default)]
    id_token_signing_alg_values_supported: Vec<String>,
}

fn default_token_auth_methods() -> Vec<String> {
    vec!["client_secret_basic".to_owned()]
}

impl Discovery {
    fn check(&self, expected_issuer: &str) -> Result<(), &'static str> {
        if self.issuer != expected_issuer {
            return Err("issuer mismatch; use the exact issuer configured by the instance.");
        }
        for endpoint in [
            &self.authorization_endpoint,
            &self.token_endpoint,
            &self.userinfo_endpoint,
            &self.jwks_uri,
        ] {
            if https_url(endpoint).is_none() {
                return Err(
                    "an advertised endpoint is invalid; require absolute HTTPS endpoints without credentials or fragments.",
                );
            }
        }
        if self
            .grant_types_supported
            .as_ref()
            .is_some_and(|grants| !grants.iter().any(|g| g == "authorization_code"))
        {
            return Err("the instance does not advertise the authorization code grant.");
        }
        for (values, expected, reason) in [
            (
                &self.token_endpoint_auth_methods_supported,
                "client_secret_basic",
                "the instance must support client_secret_basic for confidential web clients.",
            ),
            (
                &self.response_types_supported,
                "code",
                "the instance must advertise the code response type.",
            ),
            (
                &self.code_challenge_methods_supported,
                "S256",
                "the instance must advertise S256 PKCE.",
            ),
            (
                &self.scopes_supported,
                "openid",
                "the instance must advertise the openid scope for human login.",
            ),
            (
                &self.subject_types_supported,
                "public",
                "the instance must advertise public human subjects.",
            ),
            (
                &self.id_token_signing_alg_values_supported,
                "ES256",
                "the instance must advertise ES256 ID tokens.",
            ),
        ] {
            if !values.iter().any(|v| v == expected) {
                return Err(reason);
            }
        }
        Ok(())
    }
}
