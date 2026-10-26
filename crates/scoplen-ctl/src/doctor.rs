// SPDX-License-Identifier: AGPL-3.0-only
//! Read-only deployment checks through the configured public HTTPS endpoints.

use std::{fs::File, io::Read, path::Path, time::Duration};

use reqwest::{Certificate, Client, StatusCode};
use scoplen_server::{Config, resolve_roles};

const RESPONSE_LIMIT: usize = 1_024;
const CA_BYTES_LIMIT: u64 = 65_536;
const CA_CERTIFICATE_LIMIT: usize = 16;
const DEFERRED: &str = "NOT CHECKED remaining diagnostics: external reachability; ACME management; clock offset; local storage permissions and capacity; direct database/object/KMS probes; backup recency; schema and gateway/host-agent compatibility; console parity.";

pub async fn run(path: &Path, ca_path: Option<&Path>) -> bool {
    let origin = match configured_origin(path) {
        Ok(origin) => {
            println!("PASS configuration: configuration and selected roles are valid.");
            origin
        }
        Err(finding) => {
            println!("FAIL configuration: {finding}");
            println!("NOT CHECKED health: fix configuration before checking public HTTPS.");
            println!("NOT CHECKED readiness: fix configuration before checking public HTTPS.");
            println!("{DEFERRED}");
            return false;
        }
    };
    let client = match diagnostic_client(ca_path) {
        Ok(client) => client,
        Err(finding) => {
            println!("FAIL trust: {finding}");
            println!("NOT CHECKED health: fix trust settings before checking public HTTPS.");
            println!("NOT CHECKED readiness: fix trust settings before checking public HTTPS.");
            println!("{DEFERRED}");
            return false;
        }
    };
    let mut passed = true;
    for (check, path, expected) in
        [("health", "/healthz", b"ok".as_slice()), ("readiness", "/readyz", b"ready".as_slice())]
    {
        match check_endpoint(&client, &format!("{origin}{path}"), expected).await {
            Ok(()) => {
                println!("PASS {check}: trusted public HTTPS returned the expected response.");
            }
            Err(finding) => {
                println!("FAIL {check}: {finding}");
                passed = false;
            }
        }
    }
    println!("{DEFERRED}");
    passed
}

fn configured_origin(path: &Path) -> Result<String, &'static str> {
    if !path.is_file() {
        return Err(
            "configuration file is missing or unreadable; provide an existing file with --config.",
        );
    }
    let config = Config::load(path).map_err(
        |_| "configuration could not be read or parsed; check the TOML file and SPL_ overrides.",
    )?;
    let roles = resolve_roles(&config.roles.names)
        .map_err(|_| "selected roles are invalid; check roles.names and SPL_ROLES_NAMES.")?;
    config.validate_for_roles(&roles).map_err(|_| {
        "configuration is invalid; check deployment settings, selected roles and SPL_ overrides."
    })?;
    config.public_origin().map_err(
        |_| "public HTTPS origin is invalid; check server.public_host and server.public_port.",
    )
}

fn diagnostic_client(ca_path: Option<&Path>) -> Result<Client, &'static str> {
    let mut builder = Client::builder()
        .tls_backend_rustls()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(3))
        .read_timeout(Duration::from_secs(5));
    if let Some(path) = ca_path {
        builder = builder.tls_certs_merge(load_ca(path)?);
    }
    builder.build().map_err(|_| {
        "could not prepare system trust and optional CA certificates; check the trust store and PEM CA file."
    })
}

fn load_ca(path: &Path) -> Result<Vec<Certificate>, &'static str> {
    const INVALID: &str = "CA file is missing, unreadable, malformed or over its limit; provide 1 to 16 PEM certificates in at most 64 KiB.";
    let file = File::open(path).map_err(|_| INVALID)?;
    let metadata = file.metadata().map_err(|_| INVALID)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > CA_BYTES_LIMIT {
        return Err(INVALID);
    }
    let mut bytes = Vec::new();
    file.take(CA_BYTES_LIMIT).read_to_end(&mut bytes).map_err(|_| INVALID)?;
    let certificates = Certificate::from_pem_bundle(&bytes).map_err(|_| INVALID)?;
    if certificates.is_empty() || certificates.len() > CA_CERTIFICATE_LIMIT {
        return Err(INVALID);
    }
    Ok(certificates)
}

async fn check_endpoint(client: &Client, url: &str, expected: &[u8]) -> Result<(), &'static str> {
    let mut response = client.get(url).send().await.map_err(|error| request_failure(&error))?;
    if response.status() == StatusCode::SERVICE_UNAVAILABLE {
        return Err(
            "endpoint is unavailable; check server logs and database, object storage and notification readiness.",
        );
    }
    if response.status() != StatusCode::OK {
        return Err(
            "endpoint did not return HTTP 200; check public HTTPS reverse-proxy routing and server logs.",
        );
    }
    if response.content_length().is_some_and(|length| length > RESPONSE_LIMIT as u64) {
        return Err(
            "response exceeds 1,024 bytes; check reverse-proxy routing and endpoint configuration.",
        );
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| request_failure(&error))? {
        if chunk.len() > RESPONSE_LIMIT - body.len() {
            return Err(
                "response exceeds 1,024 bytes; check reverse-proxy routing and endpoint configuration.",
            );
        }
        body.extend_from_slice(&chunk);
    }
    if body != expected {
        return Err(
            "endpoint returned an unexpected response; check reverse-proxy routing and server logs.",
        );
    }
    Ok(())
}

fn request_failure(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "HTTPS check timed out; check public host resolution, port reachability and server responsiveness."
    } else if error.is_connect() {
        "could not establish trusted HTTPS; check DNS, the public port, certificate chain and hostname, or explicitly supply the deployment CA."
    } else {
        "HTTPS exchange failed; check reverse-proxy routing, TLS configuration and server logs."
    }
}
