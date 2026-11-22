// SPDX-License-Identifier: AGPL-3.0-only
//! Read-only deployment checks through the configured public HTTPS endpoints.

use std::path::Path;

use crate::diagnostic_http::{diagnostic_client, read_body, request_failure};
use reqwest::{Client, StatusCode};
use scoplen_server::{Config, resolve_roles};

const RESPONSE_LIMIT: usize = 1_024;
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

pub(crate) fn configured_origin(path: &Path) -> Result<String, &'static str> {
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

async fn check_endpoint(client: &Client, url: &str, expected: &[u8]) -> Result<(), &'static str> {
    let response = client.get(url).send().await.map_err(|error| request_failure(&error))?;
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
    let body = read_body(
        response,
        RESPONSE_LIMIT,
        "response exceeds 1,024 bytes; check reverse-proxy routing and endpoint configuration.",
    )
    .await?;
    if body != expected {
        return Err(
            "endpoint returned an unexpected response; check reverse-proxy routing and server logs.",
        );
    }
    Ok(())
}
