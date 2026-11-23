// SPDX-License-Identifier: AGPL-3.0-only
//! Owned HTTPS provider fixture for the draft login exchange.

use std::{
    collections::BTreeMap,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::Query,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::{get, post},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use scoplen_api::auth_connection_draft::{
    callback::callback_path, test_login::DraftLoginCredentials,
};
use scoplen_crypto::{P256SigningKey, SecretBytes, SecretVec};
use scoplen_store::organizations::auth_draft_login::{DraftLoginMaterial, DraftLoginProvider};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use url::form_urlencoded;

use crate::{EnterpriseIdentitySettings, TrustedIssuerSettings};

#[path = "../../../scoplen-ctl/tests/common/https.rs"]
mod https;

const CLIENT_ID: &str = "draft+id:";
const CLIENT_SECRET: &str = " secret:+% ";
pub(crate) const NONCE: [u8; 32] = [31; 32];
const VERIFIER: [u8; 32] = [32; 32];

pub(crate) struct Provider {
    directory: PathBuf,
    server: tokio::task::JoinHandle<()>,
    requests: Arc<[AtomicUsize; 4]>,
    original_ca: Vec<u8>,
    pub(crate) settings: EnterpriseIdentitySettings,
    pub(crate) issuer: String,
}

impl Provider {
    pub(crate) async fn start(directory: PathBuf, origin: &'static str) -> Self {
        std::fs::create_dir(&directory).unwrap();
        let requests = Arc::new(std::array::from_fn(|_| AtomicUsize::new(0)));
        let counts = Arc::clone(&requests);
        let ca_file = directory.join("ca.pem");
        let live_ca = ca_file.clone();
        let (port, server) = https::start(&directory, false, move |port| {
            let issuer = format!("https://127.0.0.1:{port}/tenant/");
            let key = Arc::new(P256SigningKey::from_bytes(&[33; 32]).unwrap());
            let sec1 = key.public_key_sec1();
            let keys = json!({"keys":[{
                "kid":"test-signing-key", "kty":"EC", "crv":"P-256", "alg":"ES256", "use":"sig",
                "x":URL_SAFE_NO_PAD.encode(&sec1[1..33]), "y":URL_SAFE_NO_PAD.encode(&sec1[33..]),
            }]});
            let browser = Arc::new(Mutex::new(None));
            let routes = browser_routes(&issuer, origin, Arc::clone(&browser), Arc::clone(&counts));
            let (token, jwks, unexpected) = (Arc::clone(&counts), Arc::clone(&counts), counts);
            routes
                .route(
                    "/tenant/token",
                    post(move |headers: HeaderMap, body: Bytes| {
                        token[0].fetch_add(1, Ordering::SeqCst);
                        let issuer = issuer.clone();
                        let key = Arc::clone(&key);
                        let live_ca = live_ca.clone();
                        let browser = Arc::clone(&browser);
                        async move {
                            token_reply(&headers, &body, &key, &issuer, origin, &live_ca, &browser)
                        }
                    }),
                )
                .route(
                    "/tenant/jwks",
                    get(move |headers: HeaderMap| {
                        jwks[1].fetch_add(1, Ordering::SeqCst);
                        let keys = keys.clone();
                        async move {
                            assert!(!has_session_headers(&headers));
                            assert!(!headers.contains_key(header::AUTHORIZATION));
                            ([(header::CONTENT_TYPE, "application/jwk-set+json")], keys.to_string())
                        }
                    }),
                )
                .fallback(move || {
                    unexpected[2].fetch_add(1, Ordering::SeqCst);
                    async { StatusCode::NOT_FOUND }
                })
        })
        .await;
        let issuer = format!("https://127.0.0.1:{port}/tenant/");
        let original_ca = std::fs::read(&ca_file).unwrap();
        let settings = EnterpriseIdentitySettings {
            trusted_issuers: vec![TrustedIssuerSettings {
                issuer: issuer.clone(),
                addresses: vec!["127.0.0.1/32".into()],
                ca_certificate: Some(ca_file),
            }],
        };
        Self { directory, server, requests, original_ca, settings, issuer }
    }

    pub(crate) fn counts(&self) -> [usize; 3] {
        std::array::from_fn(|index| self.requests[index].load(Ordering::SeqCst))
    }

    pub(crate) fn discoveries(&self) -> usize {
        self.requests[3].load(Ordering::SeqCst)
    }

    pub(crate) async fn navigate(&self, authorization_url: &str) -> url::Url {
        let ca = reqwest::Certificate::from_pem(&self.original_ca).unwrap();
        let response = reqwest::Client::builder()
            .no_proxy()
            .https_only(true)
            .tls_certs_merge([ca])
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
            .get(authorization_url)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        url::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap()
    }

    pub(crate) fn metadata(&self) -> DraftLoginProvider {
        let issuer = &self.issuer;
        DraftLoginProvider {
            authorization_endpoint: format!("{issuer}authorize"),
            token_endpoint: format!("{issuer}token"),
            userinfo_endpoint: format!("{issuer}userinfo"),
            jwks_uri: format!("{issuer}jwks"),
            response_issuer_required: false,
        }
    }

    pub(crate) fn login_material() -> DraftLoginMaterial {
        DraftLoginMaterial {
            credentials: DraftLoginCredentials {
                client_id: SecretVec::new(CLIENT_ID.as_bytes().to_vec()),
                client_secret: SecretVec::new(CLIENT_SECRET.as_bytes().to_vec()),
            },
            verifier: SecretBytes::new(VERIFIER),
        }
    }

    pub(crate) fn restore_ca(&self) {
        std::fs::write(self.directory.join("ca.pem"), &self.original_ca).unwrap();
    }

    pub(crate) async fn close(self) {
        self.server.abort();
        let _ = self.server.await;
        crate::test_support::remove_test_directory(self.directory).await;
    }
}

struct BrowserProof {
    nonce: String,
    challenge: String,
}

fn browser_routes(
    issuer: &str,
    origin: &'static str,
    browser: Arc<Mutex<Option<BrowserProof>>>,
    requests: Arc<[AtomicUsize; 4]>,
) -> Router {
    let discovery = json!({
        "issuer":issuer, "authorization_endpoint":format!("{issuer}authorize"),
        "token_endpoint":format!("{issuer}token"), "jwks_uri":format!("{issuer}jwks"),
        "userinfo_endpoint":format!("{issuer}userinfo"), "response_types_supported":["code"],
        "grant_types_supported":["authorization_code"], "code_challenge_methods_supported":["S256"],
        "token_endpoint_auth_methods_supported":["client_secret_basic"], "scopes_supported":["openid"],
        "subject_types_supported":["public"], "id_token_signing_alg_values_supported":["ES256"],
        "authorization_response_iss_parameter_supported":true,
    });
    let redirect = format!("{origin}{}", callback_path(issuer).unwrap());
    let issuer = issuer.to_owned();
    Router::new()
        .route(
            "/tenant/.well-known/openid-configuration",
            get(move |headers: HeaderMap| {
                requests[3].fetch_add(1, Ordering::SeqCst);
                let discovery = discovery.clone();
                async move {
                    assert!(!has_session_headers(&headers));
                    assert!(!headers.contains_key(header::AUTHORIZATION));
                    Json(discovery)
                }
            }),
        )
        .route(
            "/tenant/authorize",
            get(move |Query(params): Query<BTreeMap<String, String>>| {
                assert_eq!(params.len(), 8);
                assert_eq!(params["redirect_uri"], redirect);
                assert_eq!(params["response_type"], "code");
                assert_eq!(params["scope"], "openid");
                assert_eq!(params["code_challenge_method"], "S256");
                assert_eq!(params["client_id"], CLIENT_ID);
                assert!(
                    browser
                        .lock()
                        .unwrap()
                        .replace(BrowserProof {
                            nonce: params["nonce"].clone(),
                            challenge: params["code_challenge"].clone(),
                        })
                        .is_none()
                );
                let mut callback = url::Url::parse(&redirect).unwrap();
                callback
                    .query_pairs_mut()
                    .append_pair("code", "browser-fixture")
                    .append_pair("state", &params["state"])
                    .append_pair("iss", &issuer);
                async move { (StatusCode::FOUND, [(header::LOCATION, String::from(callback))]) }
            }),
        )
}

fn has_session_headers(headers: &HeaderMap) -> bool {
    headers.contains_key(header::COOKIE)
        || headers.contains_key(header::REFERER)
        || headers.contains_key(header::ORIGIN)
        || headers.contains_key("dpop")
}

fn token_reply(
    headers: &HeaderMap,
    body: &Bytes,
    key: &P256SigningKey,
    issuer: &str,
    origin: &str,
    live_ca: &Path,
    browser: &Mutex<Option<BrowserProof>>,
) -> Response {
    assert!(!has_session_headers(headers));
    assert_eq!(headers[header::CONTENT_TYPE], "application/x-www-form-urlencoded");
    let expected = format!("Basic {}", STANDARD.encode("draft%2Bid%3A:+secret%3A%2B%25+"));
    assert!(headers.get(header::AUTHORIZATION).is_some_and(|value| value == &expected));
    let form: Vec<_> = form_urlencoded::parse(body).into_owned().collect();
    let [(grant, kind), (code, value), (redirect, uri), (verifier, proof)] = form.as_slice() else {
        panic!("unexpected token request form fields");
    };
    assert!(grant == "grant_type" && kind == "authorization_code" && code == "code");
    assert!(
        redirect == "redirect_uri" && uri == &format!("{origin}{}", callback_path(issuer).unwrap())
    );
    assert_eq!(verifier, "code_verifier");
    let nonce = if value == "browser-fixture" {
        let browser = browser.lock().unwrap().take().unwrap();
        assert_eq!(URL_SAFE_NO_PAD.encode(Sha256::digest(proof.as_bytes())), browser.challenge);
        browser.nonce
    } else {
        assert_eq!(proof, &URL_SAFE_NO_PAD.encode(VERIFIER));
        URL_SAFE_NO_PAD.encode(if value == "wrong-nonce" { [0; 32] } else { NONCE })
    };
    match value.as_str() {
        "redirect" => {
            return (StatusCode::FOUND, [(header::LOCATION, "/unexpected")]).into_response();
        }
        "large" => {
            return ([(header::CONTENT_TYPE, "application/json")], "x".repeat(65_537))
                .into_response();
        }
        "updated-ca" => {
            // Change the fingerprint without invalidating the PEM or its certificate.
            std::fs::OpenOptions::new()
                .append(true)
                .open(live_ca)
                .unwrap()
                .write_all(b"\n")
                .unwrap();
        }
        "verified+code" | "wrong-nonce" | "browser-fixture" => (),
        _ => panic!("unexpected fixture code"),
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"test-signing-key","typ":"JWT"}"#);
    let claims = URL_SAFE_NO_PAD.encode(
        json!({
            "iss":issuer, "sub":"opaque-human", "aud":CLIENT_ID,"iat":now,"exp":now+60,
            "nonce":nonce,
        })
        .to_string(),
    );
    let input = format!("{header}.{claims}");
    let signature = URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()));
    Json(json!({"id_token":format!("{input}.{signature}"), "access_token":"fixture-access", "token_type":"Bearer"})).into_response()
}
