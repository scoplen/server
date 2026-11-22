// SPDX-License-Identifier: AGPL-3.0-only
//! TLS trust, deadlines and bounded response reads for local deployment diagnostics.

use std::{fs::File, io::Read, path::Path, time::Duration};

use reqwest::{Certificate, Client, Response};

const CA_BYTES_LIMIT: u64 = 65_536;
const CA_CERTIFICATE_LIMIT: usize = 16;

pub(super) fn diagnostic_client(ca_path: Option<&Path>) -> Result<Client, &'static str> {
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

pub(super) fn request_failure(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "HTTPS check timed out; check public host resolution, port reachability and server responsiveness."
    } else if error.is_connect() {
        "could not establish trusted HTTPS; check DNS, the public port, certificate chain and hostname, or explicitly supply the deployment CA."
    } else {
        "HTTPS exchange failed; check reverse-proxy routing, TLS configuration and server logs."
    }
}

pub(super) async fn read_body(
    mut response: Response,
    limit: usize,
    oversize: &'static str,
) -> Result<Vec<u8>, &'static str> {
    if response.content_length().is_some_and(|length| length > limit as u64) {
        return Err(oversize);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| request_failure(&error))? {
        if chunk.len() > limit - body.len() {
            return Err(oversize);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
