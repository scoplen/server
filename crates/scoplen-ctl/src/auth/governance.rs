// SPDX-License-Identifier: AGPL-3.0-only
//! Read-only preflight of the delegated application credential and selected Auth Space.

use std::{
    io::{self, IsTerminal as _, Read as _},
    path::Path,
};

use reqwest::{Client, StatusCode, Url, header};
use serde::{Deserialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::diagnostic_http::{diagnostic_client, read_body, request_failure};

const CHECK_PERMISSION: &str = "auth.authz:check";
const INPUT_LIMIT: usize = 1_024;
const RESPONSE_LIMIT: usize = 65_536;

#[derive(Deserialize)]
struct KeyIdentity {
    application_id: String,
    client_id: String,
    grants: Vec<String>,
    restrict_to: Vec<Restriction>,
    allow_subject_assertion: bool,
}

#[derive(Deserialize)]
struct Restriction {
    space_id: String,
    include_descendants: bool,
}

#[derive(Deserialize)]
struct Installation {
    id: String,
    application_id: String,
    space_id: String,
    scope: String,
    status: String,
    anchor_group_id: Option<String>,
    approved_permissions: Vec<String>,
}

#[derive(Deserialize)]
struct Envelope<T> {
    data: T,
    next_cursor: Option<String>,
}

pub(super) async fn check(
    origin: &str,
    client_id: &str,
    space_id: &str,
    ca: Option<&Path>,
) -> Result<String, &'static str> {
    let url = Url::parse(origin).map_err(|_| "provide the exact HTTPS server-plane origin.")?;
    if url.scheme() != "https" || url.origin().ascii_serialization() != origin {
        return Err("provide the exact HTTPS server-plane origin without a path or credentials.");
    }
    if !valid_id(space_id, "spc_") || client_id.is_empty() || client_id.len() > 512 {
        return Err("provide the exact selected Space ID and the reviewed OIDC client ID.");
    }
    let client = diagnostic_client(ca)?;
    let authorization = read_authorization()?;

    let key: Envelope<KeyIdentity> = get(&client, origin, "/server/v1/key", &authorization).await?;
    if key.data.client_id != client_id || !valid_id(&key.data.application_id, "app_") {
        return Err("the API key does not belong to the reviewed OIDC application.");
    }
    if !key.data.allow_subject_assertion || key.data.grants.as_slice() != [CHECK_PERMISSION] {
        return Err("use a dedicated API key with by-ID assertions and only auth.authz:check.");
    }
    let [restriction] = key.data.restrict_to.as_slice() else {
        return Err("restrict the API key to exactly the selected Space.");
    };
    if restriction.space_id != space_id || restriction.include_descendants {
        return Err("restrict the API key to the selected Space without descendants.");
    }

    let page: Envelope<Vec<Installation>> =
        get(&client, origin, "/server/v1/installations?limit=100", &authorization).await?;
    if page.next_cursor.is_some() {
        return Err("the provider did not return a complete installation result.");
    }
    let [installation] = page.data.as_slice() else {
        return Err("the provider must report one current installation in the selected Space.");
    };
    if !valid_id(&installation.id, "ins_")
        || installation.application_id != key.data.application_id
        || installation.space_id != space_id
        || installation.status != "active"
        || installation.scope != "space"
        || installation.anchor_group_id.as_deref().is_some_and(|anchor| !anchor.is_empty())
        || !installation.approved_permissions.iter().any(|grant| grant == CHECK_PERMISSION)
    {
        return Err(
            "the installation does not approve authorization checks in the selected Space.",
        );
    }
    let report = serde_json::json!({
        "application_id": key.data.application_id,
        "installation_id": installation.id,
        "space_id": installation.space_id,
    });
    Ok(format!("{report:#}"))
}

fn valid_id(value: &str, prefix: &str) -> bool {
    value.len() <= 128
        && value.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

fn read_authorization() -> Result<header::HeaderValue, &'static str> {
    const INVALID: &str = "pipe one dedicated application API key to standard input.";
    let input = io::stdin();
    if input.is_terminal() {
        return Err(INVALID);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    input.take((INPUT_LIMIT + 1) as u64).read_to_end(&mut bytes).map_err(|_| INVALID)?;
    if bytes.len() > INPUT_LIMIT {
        return Err(INVALID);
    }
    let key = std::str::from_utf8(&bytes).map_err(|_| INVALID)?.trim_ascii();
    let (prefix, secret) = key.split_once('.').ok_or(INVALID)?;
    let valid_segment = |value: &str| {
        !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    };
    if !prefix.strip_prefix("ply_sk_").is_some_and(valid_segment) || !valid_segment(secret) {
        return Err(INVALID);
    }
    let value = Zeroizing::new(format!("Bearer {key}"));
    let mut authorization = header::HeaderValue::from_str(&value).map_err(|_| INVALID)?;
    authorization.set_sensitive(true);
    Ok(authorization)
}

async fn get<T: DeserializeOwned>(
    client: &Client,
    origin: &str,
    path: &str,
    authorization: &header::HeaderValue,
) -> Result<Envelope<T>, &'static str> {
    let response = client
        .get(format!("{origin}{path}"))
        .header(header::ACCEPT, "application/json")
        .header(header::AUTHORIZATION, authorization.clone())
        .send()
        .await
        .map_err(|error| request_failure(&error))?;
    if response.status() != StatusCode::OK {
        return Err(
            "the Auth server plane did not accept the check; verify its origin and API key.",
        );
    }
    if !response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err("the Auth server plane did not return application/json.");
    }
    let bytes = Zeroizing::new(
        read_body(response, RESPONSE_LIMIT, "the governance preflight response exceeds 64 KiB.")
            .await?,
    );
    serde_json::from_slice(&bytes)
        .map_err(|_| "the Auth server plane returned an invalid preflight response.")
}
