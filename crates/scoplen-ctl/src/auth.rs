// SPDX-License-Identifier: AGPL-3.0-only
//! Read-only discovery and manual registration settings for an enterprise issuer.

use std::{path::PathBuf, process::ExitCode};

use clap::Subcommand;
use reqwest::{StatusCode, header};
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

fn validate_issuer(issuer: &str) -> Result<(), &'static str> {
    scoplen_api::auth_connection_draft::validate_issuer(issuer).map_err(|_| {
        "provide an absolute HTTPS issuer of at most 2,048 bytes without credentials, query, fragment, backslashes, whitespace or control characters."
    })
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
    scoplen_server::oidc::check_discovery(&body, issuer)
}
