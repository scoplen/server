// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    convert::Infallible,
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::Path,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::get,
};
use scoplen_api::auth_connection_draft::callback::IssuerIdentification;
use scoplen_server::{
    EnterpriseIdentitySettings, TrustedIssuerSettings,
    oidc::{DiscoveryError, TrustedIssuer},
};
use serde_json::json;

#[path = "../../scoplen-ctl/tests/common/https.rs"]
mod https;

struct Fixture {
    directory: PathBuf,
    port: u16,
    server: tokio::task::JoinHandle<()>,
    requests: Arc<AtomicUsize>,
}

impl Fixture {
    async fn start() -> Self {
        let directory =
            std::env::temp_dir().join(format!("spl-oidc-discovery-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).expect("create fixture directory");
        let requests = Arc::new(AtomicUsize::new(0));
        let received = Arc::clone(&requests);
        let (port, server) = https::start(&directory, false, move |_| {
            let unexpected = Arc::clone(&received);
            Router::new()
                .route(
                    "/{case}/.well-known/openid-configuration",
                    get(move |Path(case): Path<String>, headers: HeaderMap| {
                        received.fetch_add(1, Ordering::SeqCst);
                        metadata(case, headers)
                    }),
                )
                .fallback(move || {
                    unexpected.fetch_add(1, Ordering::SeqCst);
                    async { StatusCode::NOT_FOUND }
                })
        })
        .await;
        Self { directory, port, server, requests }
    }

    fn issuer(&self, host: &str, scenario: &str) -> String {
        format!("https://{host}:{}/{scenario}/", self.port)
    }

    fn policy(&self, issuer: &str, networks: &[&str]) -> EnterpriseIdentitySettings {
        EnterpriseIdentitySettings {
            trusted_issuers: vec![TrustedIssuerSettings {
                issuer: issuer.to_owned(),
                addresses: networks.iter().map(|value| (*value).to_owned()).collect(),
                ca_certificate: Some(self.directory.join("ca.pem")),
            }],
        }
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        let _ = fs::remove_file(self.directory.join("ca.pem"));
        let _ = fs::remove_dir(&self.directory);
    }
}

async fn metadata(scenario: String, headers: HeaderMap) -> Response {
    if [header::AUTHORIZATION, header::COOKIE, header::HeaderName::from_static("dpop")]
        .iter()
        .any(|header| headers.contains_key(header))
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let authority =
        headers.get(header::HOST).expect("fixture authority").to_str().expect("HTTP host");
    let issuer = format!("https://{authority}/{scenario}/");
    let mut document = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}authorize"),
        "token_endpoint": format!("{issuer}token"),
        "userinfo_endpoint": format!("{issuer}userinfo"),
        "jwks_uri": format!("{issuer}jwks"),
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
    });
    match scenario.as_str() {
        "identified" => document["authorization_response_iss_parameter_supported"] = json!(true),
        "cross-origin" => document["jwks_uri"] = json!("https://other.example.test/jwks"),
        "query" => document["token_endpoint"] = json!(format!("{issuer}token?extra=1")),
        "issuer-mismatch" => document["issuer"] = json!(issuer.trim_end_matches('/')),
        "unsupported" => document["code_challenge_methods_supported"] = json!(["plain"]),
        "redirect" => {
            return (StatusCode::FOUND, [(header::LOCATION, "/another-path")]).into_response();
        }
        "unavailable" => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        "oversized" => {
            let chunks = [Bytes::from(vec![b' '; 33_000]), Bytes::from(vec![b' '; 33_000])];
            let stream = futures_util::stream::iter(chunks.into_iter().map(Ok::<_, Infallible>));
            return ([(header::CONTENT_TYPE, "application/json")], Body::from_stream(stream))
                .into_response();
        }
        "slow" => tokio::time::sleep(Duration::from_secs(12)).await,
        _ => {}
    }
    Json(document).into_response()
}

#[tokio::test]
async fn trusted_discovery_requires_exact_issuer_and_admitted_socket_with_valid_tls() {
    let fixture = Fixture::start().await;
    let issuer = fixture.issuer("localhost", "identified");
    let broad = fixture.policy(&issuer, &["127.0.0.0/8", "::/0"]);
    let trusted = fixture.policy(&issuer, &["127.0.0.1/32"]);
    assert!(matches!(
        TrustedIssuer::from_settings(&trusted, issuer.trim_end_matches('/')),
        Err(DiscoveryError::Untrusted)
    ));
    assert!(matches!(
        TrustedIssuer::from_settings(&EnterpriseIdentitySettings::default(), &issuer),
        Err(DiscoveryError::Untrusted)
    ));
    let denied_dns = TrustedIssuer::from_settings(&broad, &issuer).expect("load trust policy");
    assert!(matches!(denied_dns.discover().await, Err(DiscoveryError::Unavailable)));
    let literal = fixture.issuer("127.0.0.1", "identified");
    assert!(matches!(
        TrustedIssuer::from_settings(&fixture.policy(&literal, &["127.0.0.0/8"]), &literal),
        Err(DiscoveryError::Unavailable)
    ));

    let mut no_private_ca = trusted.clone();
    no_private_ca.trusted_issuers[0].ca_certificate = None;
    let wrong_trust =
        TrustedIssuer::from_settings(&no_private_ca, &issuer).expect("load system trust");
    assert!(matches!(wrong_trust.discover().await, Err(DiscoveryError::Unavailable)));
    assert_eq!(fixture.request_count(), 0);

    let provider = TrustedIssuer::from_settings(&trusted, &issuer).expect("load private trust");
    let valid = provider.discover().await.expect("verified HTTPS discovery");
    assert_eq!(valid.authorization_endpoint, format!("{issuer}authorize"));
    assert_eq!(valid.token_endpoint, format!("{issuer}token"));
    assert_eq!(valid.userinfo_endpoint, format!("{issuer}userinfo"));
    assert_eq!(valid.jwks_uri, format!("{issuer}jwks"));
    assert_eq!(valid.issuer_identification, IssuerIdentification::ResponseParameter);
    assert_eq!(fixture.request_count(), 1);

    let issuer = fixture.issuer("127.0.0.1", "exclusive");
    let configured = fixture.policy(&issuer, &["127.0.0.1/32"]);
    let provider = TrustedIssuer::from_settings(&configured, &issuer).expect("admitted literal");
    let valid = provider.discover().await.expect("verified HTTPS discovery");
    assert_eq!(valid.issuer_identification, IssuerIdentification::ExclusiveCallback);
    assert_eq!(fixture.request_count(), 2);
}

#[tokio::test]
async fn trusted_discovery_rejects_redirects_incompatible_metadata_and_oversized_bodies() {
    let fixture = Fixture::start().await;
    for scenario in [
        "redirect",
        "cross-origin",
        "query",
        "issuer-mismatch",
        "unsupported",
        "oversized",
        "unavailable",
        "slow",
    ] {
        let issuer = fixture.issuer("127.0.0.1", scenario);
        let configured = fixture.policy(&issuer, &["127.0.0.1/32"]);
        let provider =
            TrustedIssuer::from_settings(&configured, &issuer).expect("load private trust");
        let before = fixture.request_count();
        let expected = if matches!(scenario, "unavailable" | "slow") {
            DiscoveryError::Unavailable
        } else {
            DiscoveryError::Incompatible
        };
        assert!(matches!(provider.discover().await, Err(error) if error == expected), "{scenario}");
        assert_eq!(fixture.request_count(), before + 1, "{scenario}");
    }
}

#[tokio::test]
async fn trust_fingerprint_binds_exact_issuer_normalized_networks_and_private_ca_bytes() {
    let fixture = Fixture::start().await;
    let issuer = fixture.issuer("localhost", "identified");
    let policy = fixture.policy(&issuer, &["192.0.2.26/24", "127.0.0.1/32", "192.0.2.1/24"]);
    let equivalent = fixture.policy(&issuer, &["::ffff:127.0.0.1/128", "192.0.2.0/24"]);
    let narrower = fixture.policy(&issuer, &["127.0.0.1/32"]);
    let read = |policy: &EnterpriseIdentitySettings, issuer: &str| {
        TrustedIssuer::from_settings(policy, issuer).expect("load trust").fingerprint()
    };
    let original = read(&policy, &issuer);
    assert_eq!(original, read(&equivalent, &issuer));
    assert_ne!(original, read(&narrower, &issuer));
    let different = fixture.issuer("localhost", "other");
    assert_ne!(
        original,
        read(&fixture.policy(&different, &["127.0.0.1/32", "192.0.2.0/24"]), &different)
    );

    let ca_path = fixture.directory.join("ca.pem");
    let mut pem = fs::read(&ca_path).expect("fixture PEM");
    pem.extend_from_slice(b"\n");
    fs::write(ca_path, pem).expect("update fixture CA bytes");
    assert_ne!(original, read(&policy, &issuer));
    assert_eq!(fixture.request_count(), 0);
}
