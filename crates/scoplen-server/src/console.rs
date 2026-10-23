// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded production console assets, independent of API and readiness availability.

use std::{collections::BTreeMap, path::Path, sync::Arc};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Path as RoutePath, State},
    http::{StatusCode, header},
    response::Response,
    routing::get,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::{fs::File, io::AsyncReadExt};

const MAX_MANIFEST_BYTES: usize = 65_536;
const MAX_ASSET_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'";
const UNAVAILABLE: &str = "The Scoplen console is unavailable. Build it with pnpm --dir web/console build and configure console.assets_dir (SPL_CONSOLE_ASSETS_DIR) to the shipped dist directory. Public APIs remain available.\n";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    assets: Vec<ManifestAsset>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestAsset {
    path: String,
    bytes: usize,
    sha256: String,
}

#[derive(Clone)]
struct Asset {
    content: Bytes,
    content_type: &'static str,
}

#[derive(Clone)]
struct Assets(Option<Arc<BTreeMap<String, Asset>>>);

pub(crate) async fn router(directory: &Path, api_enabled: bool) -> Router {
    if !api_enabled {
        return Router::new();
    }
    let assets = match load(directory).await {
        Ok(assets) => Assets(Some(Arc::new(assets))),
        Err(reason) => {
            tracing::warn!(
                reason,
                "console assets unavailable; build and configure console.assets_dir"
            );
            Assets(None)
        }
    };
    Router::new()
        .route("/", get(entry))
        .route("/setup", get(entry))
        .route("/assets/{name}", get(asset))
        .with_state(assets)
}

async fn entry(State(assets): State<Assets>) -> Response {
    respond(&assets, "index.html")
}

async fn asset(State(assets): State<Assets>, RoutePath(name): RoutePath<String>) -> Response {
    respond(&assets, &format!("assets/{name}"))
}

fn respond(assets: &Assets, path: &str) -> Response {
    let (status, content_type, content) = match &assets.0 {
        Some(files) => match files.get(path) {
            Some(asset) => (StatusCode::OK, asset.content_type, asset.content.clone()),
            None => (
                StatusCode::NOT_FOUND,
                "text/plain; charset=utf-8",
                Bytes::from_static(b"Not found\n"),
            ),
        },
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain; charset=utf-8",
            Bytes::from_static(UNAVAILABLE.as_bytes()),
        ),
    };
    let mut response = Response::new(Body::from(content));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, content_type.parse().expect("static content type"));
    headers.insert(header::CACHE_CONTROL, "no-store".parse().expect("static cache policy"));
    headers.insert(header::CONTENT_SECURITY_POLICY, CSP.parse().expect("static CSP"));
    headers.insert(header::REFERRER_POLICY, "no-referrer".parse().expect("static referrer policy"));
    headers
        .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().expect("static content policy"));
    response
}

fn content_type(path: &str) -> Option<&'static str> {
    if path == "index.html" {
        return Some("text/html; charset=utf-8");
    }
    let name = path.strip_prefix("assets/")?;
    if name.is_empty()
        || name.len() > 160
        || name.starts_with('.')
        || !name.bytes().all(|part| part.is_ascii_alphanumeric() || b"_.-".contains(&part))
    {
        return None;
    }
    match name.rsplit('.').next()? {
        "js" => Some("text/javascript; charset=utf-8"),
        "css" => Some("text/css; charset=utf-8"),
        "woff2" => Some("font/woff2"),
        _ => None,
    }
}

async fn read_bounded(root: &Path, path: &str, maximum: usize) -> Result<Vec<u8>, &'static str> {
    let path = tokio::fs::canonicalize(root.join(path)).await.map_err(|_| "asset missing")?;
    if !path.starts_with(root) {
        return Err("asset outside configured directory");
    }
    let file = File::open(path).await.map_err(|_| "asset unreadable")?;
    if !file.metadata().await.map_err(|_| "asset unreadable")?.is_file() {
        return Err("asset is not a file");
    }
    let mut content = Vec::new();
    file.take(u64::try_from(maximum).map_err(|_| "invalid asset limit")? + 1)
        .read_to_end(&mut content)
        .await
        .map_err(|_| "asset unreadable")?;
    if content.len() > maximum {
        return Err("asset exceeds size limit");
    }
    Ok(content)
}

async fn load(directory: &Path) -> Result<BTreeMap<String, Asset>, &'static str> {
    let root = tokio::fs::canonicalize(directory).await.map_err(|_| "asset directory missing")?;
    let manifest: Manifest =
        serde_json::from_slice(&read_bounded(&root, "manifest.json", MAX_MANIFEST_BYTES).await?)
            .map_err(|_| "invalid asset manifest")?;
    if manifest.version != 1 || manifest.assets.is_empty() || manifest.assets.len() > 256 {
        return Err("unsupported asset manifest");
    }
    let mut files = BTreeMap::new();
    let mut total = 0;
    for asset in manifest.assets {
        let content_type = content_type(&asset.path).ok_or("invalid asset path")?;
        if asset.bytes == 0
            || asset.bytes > MAX_ASSET_BYTES
            || files.contains_key(&asset.path)
            || asset.sha256.len() != 64
            || !asset
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("invalid asset metadata");
        }
        total += asset.bytes;
        if total > MAX_TOTAL_BYTES {
            return Err("console exceeds size limit");
        }
        let content = read_bounded(&root, &asset.path, asset.bytes).await?;
        if content.len() != asset.bytes || format!("{:x}", Sha256::digest(&content)) != asset.sha256
        {
            return Err("asset integrity mismatch");
        }
        files.insert(asset.path, Asset { content: content.into(), content_type });
    }
    if !files.contains_key("index.html") {
        return Err("console entry missing");
    }
    Ok(files)
}

#[cfg(test)]
mod tests;
