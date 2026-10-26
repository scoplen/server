// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    convert::Infallible,
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    http::{Response, StatusCode},
    routing::get,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tokio::{net::TcpListener, task::JoinSet};
use tokio_rustls::TlsAcceptor;

#[derive(Clone, Copy)]
enum Mode {
    Healthy,
    Unready,
    Redirect,
    WrongBody,
    Oversize,
    StreamedOversize,
    SlowRead,
    SlowWholeRequest,
}

struct Fixture {
    directory: PathBuf,
    config: PathBuf,
    ca: PathBuf,
    data: PathBuf,
    server: tokio::task::JoinHandle<()>,
    requests: Arc<AtomicUsize>,
}

impl Fixture {
    async fn start(mode: Mode, wrong_hostname: bool) -> Self {
        let directory =
            std::env::temp_dir().join(format!("scoplen-doctor-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).expect("owned fixture directory");
        let root_key = KeyPair::generate().expect("fixture CA key");
        let mut root_params = CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.distinguished_name.push(DnType::CommonName, "Doctor test root CA");
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root = root_params.self_signed(&root_key).expect("fixture CA");
        let key = KeyPair::generate().expect("fixture server key");
        let name = if wrong_hostname { "wrong.example.test" } else { "127.0.0.1" };
        let mut params =
            CertificateParams::new(vec![name.into()]).expect("fixture certificate parameters");
        params.distinguished_name.push(DnType::CommonName, "Doctor test HTTPS endpoint");
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let certificate = params.signed_by(&key, &root, &root_key).expect("fixture certificate");
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone(), root.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .expect("fixture TLS");
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("owned TLS listener");
        let port = listener.local_addr().expect("fixture address").port();
        let requests = Arc::new(AtomicUsize::new(0));
        let health_requests = requests.clone();
        let ready_requests = requests.clone();
        let router = Router::new()
            .route(
                "/healthz",
                get(move || {
                    let requests = health_requests.clone();
                    async move {
                        requests.fetch_add(1, Ordering::SeqCst);
                        if matches!(mode, Mode::Redirect) {
                            Response::builder()
                                .status(StatusCode::FOUND)
                                .header("location", "/readyz")
                                .body(Body::from("private-redirect-body"))
                                .expect("redirect")
                        } else {
                            Response::new(Body::from("ok"))
                        }
                    }
                }),
            )
            .route(
                "/readyz",
                get(move || {
                    let requests = ready_requests.clone();
                    async move {
                        requests.fetch_add(1, Ordering::SeqCst);
                        readiness_response(mode).await
                    }
                }),
            );
        let server = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    incoming = listener.accept() => {
                        let Ok((tcp, _)) = incoming else { break };
                        let acceptor = acceptor.clone();
                        let router = router.clone();
                        connections.spawn(async move {
                            if let Ok(tls) = acceptor.accept(tcp).await {
                                let _ = Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls), TowerToHyperService::new(router)).await;
                            }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        let config = directory.join("server.toml");
        let ca = directory.join("ca.pem");
        let data = directory.join("must-remain-absent");
        fs::write(&ca, root.pem()).expect("fixture CA file");
        fs::write(&config, format!("[server]\npublic_host = '127.0.0.1'\npublic_port = {port}\ndata_dir = '{}'\n[storage]\nbackend = 'postgres'\ndatabase_url = 'postgres://private-config-marker@unreachable.example.test/unused'\n", data.to_str().expect("fixture path").replace('\\', "/"))).expect("fixture configuration");
        Self { directory, config, ca, data, server, requests }
    }

    async fn doctor(&self, ca: Option<PathBuf>) -> Output {
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || {
            let mut command = cli();
            command.args(["doctor", "--config"]).arg(config);
            if let Some(ca) = ca {
                command.arg("--ca-certificate").arg(ca);
            }
            command.output().expect("public doctor CLI")
        })
        .await
        .expect("CLI task")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        assert!(!self.data.exists(), "doctor cannot create deployment state");
        fs::remove_dir_all(&self.directory).expect("remove owned fixture files");
    }
}

async fn readiness_response(mode: Mode) -> Response<Body> {
    match mode {
        Mode::Healthy | Mode::Redirect => Response::new(Body::from("ready")),
        Mode::Unready => Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Body::from("private-dependency-marker"))
            .expect("unready"),
        Mode::WrongBody => Response::new(Body::from("private-wrong-body-marker")),
        Mode::Oversize => Response::new(Body::from(vec![b'x'; 1_025])),
        Mode::StreamedOversize => Response::new(Body::from_stream(futures_util::stream::iter([
            Ok::<_, Infallible>(vec![b'x'; 700]),
            Ok(vec![b'x'; 700]),
        ]))),
        Mode::SlowRead => {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Response::new(Body::from("ready"))
        }
        Mode::SlowWholeRequest => {
            Response::new(Body::from_stream(futures_util::stream::unfold(0, |count| async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Some((Ok::<_, Infallible>(vec![b'x']), count + 1))
            })))
        }
    }
}

fn cli() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_splctl"));
    for (key, _) in std::env::vars_os().filter(|(key, _)| key.to_string_lossy().starts_with("SPL_"))
    {
        command.env_remove(key);
    }
    command
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env("NO_PROXY", "");
    command
}

fn output_text(output: &Output) -> &str {
    assert!(output.stderr.is_empty(), "doctor findings use stdout only");
    let text = std::str::from_utf8(&output.stdout).expect("UTF-8 findings");
    for private in [
        "private-config-marker",
        "private-dependency-marker",
        "private-wrong-body-marker",
        "private-redirect-body",
        "127.0.0.1",
        "postgres://",
        "BEGIN CERTIFICATE",
    ] {
        assert!(!text.contains(private), "findings cannot disclose input or network content");
    }
    assert!(text.contains("NOT CHECKED remaining diagnostics:"));
    text
}

#[tokio::test]
async fn trusted_https_and_environment_overrides_pass_without_storage_or_proxy() {
    let fixture = Fixture::start(Mode::Healthy, false).await;
    let output = fixture.doctor(Some(fixture.ca.clone())).await;
    assert!(output.status.success(), "{}", output_text(&output));
    let text = output_text(&output);
    assert_eq!(text.lines().filter(|line| line.starts_with("PASS ")).count(), 3);
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 2);
    let config = fs::read_to_string(&fixture.config).expect("fixture configuration");
    let port = config
        .lines()
        .find_map(|line| line.strip_prefix("public_port = "))
        .expect("configured port")
        .to_owned();
    fs::write(&fixture.config, config.replace(&format!("public_port = {port}"), "public_port = 0"))
        .expect("invalid file value");
    let path = fixture.config.clone();
    let ca = fixture.ca.clone();
    let overridden = tokio::task::spawn_blocking(move || {
        cli()
            .args(["doctor", "--config"])
            .arg(path)
            .arg("--ca-certificate")
            .arg(ca)
            .env("SPL_SERVER_PUBLIC_PORT", port)
            .output()
            .expect("overridden CLI")
    })
    .await
    .expect("CLI task");
    assert!(overridden.status.success());
    output_text(&overridden);
}

#[tokio::test]
async fn system_trust_rejects_unknown_ca_and_added_ca_preserves_hostname_verification() {
    for wrong_hostname in [false, true] {
        let fixture = Fixture::start(Mode::Healthy, wrong_hostname).await;
        let ca = wrong_hostname.then(|| fixture.ca.clone());
        let output = fixture.doctor(ca).await;
        assert_eq!(output.status.code(), Some(1));
        assert!(output_text(&output).contains("could not establish trusted HTTPS"));
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn bad_status_redirect_body_and_limits_fail_without_disclosing_responses() {
    for (mode, finding) in [
        (Mode::Unready, "endpoint is unavailable"),
        (Mode::Redirect, "did not return HTTP 200"),
        (Mode::WrongBody, "unexpected response"),
        (Mode::Oversize, "exceeds 1,024 bytes"),
        (Mode::StreamedOversize, "exceeds 1,024 bytes"),
    ] {
        let fixture = Fixture::start(mode, false).await;
        let output = fixture.doctor(Some(fixture.ca.clone())).await;
        assert_eq!(output.status.code(), Some(1));
        assert!(output_text(&output).contains(finding), "{}", output_text(&output));
        assert_eq!(
            fixture.requests.load(Ordering::SeqCst),
            2,
            "redirects and failed checks are not retried"
        );
    }
}

#[tokio::test]
async fn read_and_whole_request_deadlines_bound_unresponsive_endpoints() {
    for mode in [Mode::SlowRead, Mode::SlowWholeRequest] {
        let fixture = Fixture::start(mode, false).await;
        let started = std::time::Instant::now();
        let output = fixture.doctor(Some(fixture.ca.clone())).await;
        assert_eq!(output.status.code(), Some(1));
        assert!(output_text(&output).contains("HTTPS check timed out"), "{}", output_text(&output));
        assert!(started.elapsed() < Duration::from_secs(20), "whole check must remain bounded");
    }
}

#[tokio::test]
async fn malformed_missing_empty_and_oversize_ca_fail_before_network() {
    let fixture = Fixture::start(Mode::Healthy, false).await;
    let ca_source = fs::read_to_string(&fixture.ca).expect("valid CA");
    for bytes in [
        Vec::new(),
        b"not a PEM certificate".to_vec(),
        b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n".to_vec(),
        b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n".to_vec(),
        vec![b'x'; 65_537],
        ca_source.repeat(17).into_bytes(),
    ] {
        fs::write(&fixture.ca, bytes).expect("invalid CA file");
        let output = fixture.doctor(Some(fixture.ca.clone())).await;
        assert_eq!(output.status.code(), Some(1));
        let text = output_text(&output);
        assert!(text.contains("FAIL trust:"));
        assert!(text.contains("NOT CHECKED health:"));
        assert!(!text.contains("PASS health:"));
    }
    let output = fixture.doctor(Some(fixture.directory.join("missing.pem"))).await;
    assert_eq!(output.status.code(), Some(1));
    assert!(output_text(&output).contains("FAIL trust:"));
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
    let mut boundary = ca_source.repeat(16).into_bytes();
    boundary.resize(65_536, b' ');
    fs::write(&fixture.ca, boundary).expect("CA bundle at both limits");
    let accepted = fixture.doctor(Some(fixture.ca.clone())).await;
    assert!(accepted.status.success(), "{}", output_text(&accepted));
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn config_failures_are_static_and_stopped_deployment_is_not_started() {
    let mut fixture = Fixture::start(Mode::Healthy, false).await;
    let valid = fs::read(&fixture.config).expect("valid config");
    for source in [
        "private-config-marker = [",
        "[storage]\nbackend = 'private-config-marker'",
        "[roles]\nnames = ['private-config-marker']",
    ] {
        fs::write(&fixture.config, source).expect("bad config");
        let output = fixture.doctor(Some(fixture.ca.clone())).await;
        assert_eq!(output.status.code(), Some(1));
        let text = output_text(&output);
        assert!(text.contains("FAIL configuration:"));
        assert!(text.contains("NOT CHECKED health:"));
    }
    fs::remove_file(&fixture.config).expect("remove fixture config");
    let missing = fixture.doctor(None).await;
    assert_eq!(missing.status.code(), Some(1));
    assert!(output_text(&missing).contains("provide an existing file"));
    fs::write(&fixture.config, valid).expect("restore fixture config");
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
    fixture.server.abort();
    let _ = (&mut fixture.server).await;
    let stopped = fixture.doctor(Some(fixture.ca.clone())).await;
    assert_eq!(stopped.status.code(), Some(1));
    assert!(output_text(&stopped).contains("could not establish trusted HTTPS"));
}

#[test]
fn public_help_and_usage_exit_are_explicit() {
    let help = cli().args(["doctor", "--help"]).output().expect("doctor help");
    assert!(help.status.success());
    let text = std::str::from_utf8(&help.stdout).expect("CLI help");
    assert!(text.contains("--config"));
    assert!(text.contains("--ca-certificate"));
    let invalid = cli().args(["doctor", "--unknown"]).output().expect("invalid usage");
    assert_eq!(invalid.status.code(), Some(2));
}
