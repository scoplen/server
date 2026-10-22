// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "postgres-integration")]
#[path = "support/lost_commit.rs"]
mod lost_commit;
#[path = "support/passkey.rs"]
mod passkey;
mod support;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_identity::operator_passkeys::{
    AssertionArtifacts, OperatorPasskeyVerifier, PasskeyError,
};
use scoplen_store::{
    RelationalStore, SqliteStore,
    operator_setup::{OperatorRegistration, OperatorSetupError, SetupDisclosure},
};
use sqlx::Row;
use webauthn_authenticator_rs::prelude::Url;

const ORIGIN: &str = "https://setup.example.com:9443";
fn jkt() -> String {
    URL_SAFE_NO_PAD.encode([7; 32])
}
fn token(disclosure: &SetupDisclosure) -> [u8; 32] {
    let link = disclosure.expose_link();
    URL_SAFE_NO_PAD
        .decode(link.split("#token=").nth(1).expect("fragment"))
        .expect("canonical token")
        .try_into()
        .expect("32 bytes")
}
async fn sqlite() -> (SqliteStore, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("scoplen-operator-setup-{}", uuid::Uuid::new_v4()));
    let store = SqliteStore::open(&dir.join("test.sqlite")).await.expect("SQLite fixture");
    (store, dir)
}

macro_rules! lifecycle {
    ($store:expr) => {{
        let store = &$store;
        let verifier = OperatorPasskeyVerifier::new(ORIGIN).expect("DNS verifier");
        let first = store
            .initialize_operator_setup(ORIGIN, false)
            .await
            .expect("initialize")
            .expect("winning token");
        assert!(format!("{first:?}").contains("REDACTED"));
        let old = token(&first);
        assert!(store.initialize_operator_setup(ORIGIN, false).await.expect("restart").is_none());
        let initial = store.operator_setup_options(&old, &jkt(), &verifier).await.expect("options");
        assert_eq!(initial.public_key["authenticatorSelection"]["residentKey"], "required");
        assert_eq!(initial.public_key["pubKeyCredParams"][0]["alg"], -7);
        assert_eq!(initial.public_key.as_object().expect("options object").len(), 8);
        assert!(initial.public_key.get("extensions").is_none());
        let mut authenticator = passkey::ResidentPasskey::authenticator();
        let registration = authenticator
            .do_registration(
                Url::parse(ORIGIN).expect("origin"),
                passkey::creation(&initial.public_key),
            )
            .expect("real software passkey");
        let binding = jkt();
        let make_input = |ceremony_id| OperatorRegistration {
            setup_token: &old,
            ceremony_id,
            browser_jkt: &binding,
            credential_id: registration.raw_id.as_ref(),
            client_data_json: registration.response.client_data_json.as_ref(),
            attestation_object: registration.response.attestation_object.as_ref(),
        };
        // A bad proof binding cannot burn the ceremony or entitlement.
        let other_jkt = URL_SAFE_NO_PAD.encode([8; 32]);
        let mut input = make_input(initial.ceremony_id);
        input.browser_jkt = &other_jkt;
        assert!(matches!(
            store.finish_operator_setup(&input, &verifier).await,
            Err(OperatorSetupError::WrongKey)
        ));
        input.browser_jkt = &binding;
        let replica = store.clone();
        let (first, second) = tokio::join!(
            store.finish_operator_setup(&input, &verifier),
            replica.finish_operator_setup(&input, &verifier)
        );
        let operator = match (first, second) {
            (Ok(id), Err(OperatorSetupError::Denied { consumed: false }))
            | (Err(OperatorSetupError::Denied { consumed: false }), Ok(id)) => id,
            results => panic!("exactly one concurrent setup must succeed: {results:?}"),
        };
        assert_eq!(operator.get_version_num(), 7);
        assert!(matches!(
            store.finish_operator_setup(&input, &verifier).await,
            Err(OperatorSetupError::Denied { consumed: false })
        ));
        assert!(matches!(
            store.initialize_operator_setup(ORIGIN, true).await,
            Err(OperatorSetupError::Denied { consumed: false })
        ));
        let row = sqlx::query("SELECT user_handle, credential_state FROM operator_credentials")
            .fetch_one(store.pool())
            .await
            .expect("stored credential");
        let handle: Vec<u8> = row.try_get("user_handle").expect("handle");
        assert_eq!(handle, operator.as_bytes());
        let credential: Vec<u8> = row.try_get("credential_state").expect("credential state");
        let login = verifier.authentication_options().expect("discoverable options");
        assert_eq!(login.public_key["allowCredentials"], serde_json::json!([]));
        let assertion = authenticator
            .do_authentication(
                Url::parse(ORIGIN).expect("origin"),
                passkey::authentication(&login.public_key),
            )
            .expect("real assertion signature");
        let handle: [u8; 16] = handle.try_into().expect("handle length");
        let artifact = AssertionArtifacts {
            credential_id: assertion.raw_id.as_ref(),
            client_data: assertion.response.client_data_json.as_ref(),
            authenticator_data: assertion.response.authenticator_data.as_ref(),
            signature: assertion.response.signature.as_ref(),
            user_handle: &handle,
        };
        let verified = verifier
            .verify_authentication(&login.state, &credential, &artifact)
            .expect("real signature verified");
        assert_eq!(verified.credential_id(), registration.raw_id.as_ref());
        let updated = verified.to_storage(&verifier).expect("credential encoding");
        assert!(
            matches!(
                verifier.verify_authentication(&login.state, &updated, &artifact),
                Err(PasskeyError::Denied)
            ),
            "non-increasing hardware counter denied"
        );
        let mut wrong_signature = assertion.response.signature.as_ref().to_vec();
        wrong_signature[5] ^= 1;
        let wrong = AssertionArtifacts { signature: &wrong_signature, ..artifact };
        assert!(matches!(
            verifier.verify_authentication(&login.state, &credential, &wrong),
            Err(PasskeyError::Denied)
        ));
        let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_accounts")
            .fetch_one(store.pool())
            .await
            .expect("account count");
        assert_eq!(accounts, 0, "operator does not create E2EE identity");
        sqlx::query("UPDATE deployment_operators SET active = 0")
            .execute(store.pool())
            .await
            .expect("revoke fixture");
        assert!(
            store
                .initialize_operator_setup(ORIGIN, false)
                .await
                .expect("revoked restart")
                .is_none()
        );
        assert!(matches!(
            store.initialize_operator_setup(ORIGIN, true).await,
            Err(OperatorSetupError::Denied { consumed: false })
        ));
    }};
}

#[tokio::test]
async fn sqlite_real_passkey_setup_and_assertion() {
    let (store, dir) = sqlite().await;
    lifecycle!(store);
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[tokio::test]
async fn sqlite_bad_embedded_response_consumes_only_ceremony_and_audit_is_atomic() {
    let (store, dir) = sqlite().await;
    let verifier = OperatorPasskeyVerifier::new(ORIGIN).expect("verifier");
    let disclosure =
        store.initialize_operator_setup(ORIGIN, false).await.expect("init").expect("token");
    let secret = token(&disclosure);
    let binding = jkt();
    let options =
        store.operator_setup_options(&secret, &binding, &verifier).await.expect("options");
    let input = OperatorRegistration {
        setup_token: &secret,
        ceremony_id: options.ceremony_id,
        browser_jkt: &binding,
        credential_id: b"key",
        client_data_json: b"{}",
        attestation_object: b"bad cbor",
    };
    let invalid_outer = OperatorRegistration { client_data_json: &[], ..input };
    assert!(matches!(
        store.finish_operator_setup(&invalid_outer, &verifier).await,
        Err(OperatorSetupError::InvalidRequest)
    ));
    // Mandatory denial-audit failure must roll back even ceremony consumption.
    sqlx::query("CREATE TRIGGER deny_operator_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT, 'fixture failure'); END").execute(store.pool()).await.expect("failure trigger");
    assert!(matches!(
        store.finish_operator_setup(&input, &verifier).await,
        Err(OperatorSetupError::Audit(_))
    ));
    let consumed: Option<i64> = sqlx::query_scalar("SELECT consumed_at_s FROM operator_ceremonies")
        .fetch_one(store.pool())
        .await
        .expect("read ceremony");
    assert!(consumed.is_none());
    sqlx::query("DROP TRIGGER deny_operator_audit")
        .execute(store.pool())
        .await
        .expect("remove fixture trigger");
    assert!(matches!(
        store.finish_operator_setup(&input, &verifier).await,
        Err(OperatorSetupError::Denied { consumed: true })
    ));
    assert!(matches!(
        store.finish_operator_setup(&input, &verifier).await,
        Err(OperatorSetupError::Denied { consumed: false })
    ));
    assert!(
        store.operator_setup_options(&secret, &binding, &verifier).await.is_ok(),
        "entitlement survives bad embedded data"
    );
    let replacement = store
        .initialize_operator_setup(ORIGIN, true)
        .await
        .expect("explicit local reissue")
        .expect("fresh link");
    assert_ne!(secret, token(&replacement));
    assert!(matches!(
        store.operator_setup_options(&secret, &binding, &verifier).await,
        Err(OperatorSetupError::Denied { consumed: false })
    ));
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[tokio::test]
async fn sqlite_restart_concurrency_expiry_and_state_version() {
    let (store, dir) = sqlite().await;
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store.initialize_operator_setup(ORIGIN, false).await.expect("concurrent initialize")
        }));
    }
    let mut disclosed = Vec::new();
    for task in tasks {
        if let Some(value) = task.await.expect("join") {
            disclosed.push(value);
        }
    }
    assert_eq!(disclosed.len(), 1);
    let secret = token(&disclosed[0]);
    let verifier = OperatorPasskeyVerifier::new(ORIGIN).expect("verifier");
    let binding = jkt();
    let options =
        store.operator_setup_options(&secret, &binding, &verifier).await.expect("options");
    sqlx::query("UPDATE operator_ceremonies SET library_state = $1")
        .bind(br#"{"version":2}"#.as_slice())
        .execute(store.pool())
        .await
        .expect("corrupt stored version");
    let mut auth = passkey::ResidentPasskey::authenticator();
    let result = auth
        .do_registration(
            Url::parse(ORIGIN).expect("origin"),
            passkey::creation(&options.public_key),
        )
        .expect("registration");
    let input = OperatorRegistration {
        setup_token: &secret,
        ceremony_id: options.ceremony_id,
        browser_jkt: &binding,
        credential_id: result.raw_id.as_ref(),
        client_data_json: result.response.client_data_json.as_ref(),
        attestation_object: result.response.attestation_object.as_ref(),
    };
    assert!(matches!(
        store.finish_operator_setup(&input, &verifier).await,
        Err(OperatorSetupError::Integrity)
    ));
    sqlx::query("UPDATE operator_setup SET issued_at_s = issued_at_s - 3601, expires_at_s = expires_at_s - 3601").execute(store.pool()).await.expect("expire fixture entitlement");
    assert!(
        store.initialize_operator_setup(ORIGIN, false).await.expect("expired restart").is_none()
    );
    assert!(matches!(
        store.operator_setup_options(&secret, &binding, &verifier).await,
        Err(OperatorSetupError::Denied { consumed: false })
    ));
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[test]
fn official_saved_policy_and_shared_public_options_agree() {
    use scoplen_api::operator_auth::{OperatorLoginOptionsResponse, OperatorSetupOptionsResponse};
    let verifier = OperatorPasskeyVerifier::new(ORIGIN).expect("verifier");
    for lifetime in [1, 300] {
        let operator = uuid::Uuid::now_v7();
        let options =
            verifier.registration_options(operator, lifetime).expect("registration options");
        let saved: serde_json::Value = serde_json::from_slice(&options.state).expect("saved state");
        assert_eq!(saved["library"]["challenge"], options.public_key["challenge"]);
        assert_eq!(saved["library"]["policy"], "required");
        assert_eq!(saved["library"]["credential_algorithms"], serde_json::json!(["ES256"]));
        assert_eq!(saved["library"]["require_resident_key"], true);
        assert_eq!(saved["library"]["allow_synchronised_authenticators"], true);
        assert_eq!(saved["library"]["authenticator_attachment"], serde_json::Value::Null);
        let wire=serde_json::to_vec(&serde_json::json!({"ceremony_id":uuid::Uuid::now_v7(),"expires_at":"2026-10-22T15:00:00Z","public_key":options.public_key})).expect("wire");
        let shared = OperatorSetupOptionsResponse::from_json(&wire).expect("shared options policy");
        assert_eq!(shared.operator_id, operator);
        assert_eq!(shared.timeout, lifetime * 1000);
        assert_eq!(shared.rp_id, "setup.example.com");
        assert_eq!(URL_SAFE_NO_PAD.encode(shared.challenge), saved["library"]["challenge"]);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&shared.to_json().expect("public writer"))
                .expect("public JSON")["public_key"],
            options.public_key
        );
    }
    let login = verifier.authentication_options().expect("authentication options");
    let saved: serde_json::Value = serde_json::from_slice(&login.state).expect("saved state");
    assert_eq!(saved["library"]["challenge"], login.public_key["challenge"]);
    assert_eq!(saved["library"]["policy"], "required");
    assert_eq!(saved["library"]["credentials"], serde_json::json!([]));
    let wire=serde_json::to_vec(&serde_json::json!({"ceremony_id":uuid::Uuid::now_v7(),"expires_at":"2026-10-22T15:00:00Z","public_key":login.public_key})).expect("wire");
    OperatorLoginOptionsResponse::from_json(&wire).expect("shared login options policy");
}

#[test]
fn real_registration_rejects_embedded_confusion_and_preserves_exact_signed_bytes() {
    let verifier = OperatorPasskeyVerifier::new(ORIGIN).expect("verifier");
    let options = verifier.registration_options(uuid::Uuid::now_v7(), 300).expect("options");
    let mut auth = passkey::ResidentPasskey::authenticator();
    let registration = auth
        .do_registration(
            Url::parse(ORIGIN).expect("origin"),
            passkey::creation(&options.public_key),
        )
        .expect("registration");
    let id = registration.raw_id.as_ref();
    let client = registration.response.client_data_json.as_ref();
    let attestation = registration.response.attestation_object.as_ref();
    verifier.verify_registration(&options.state, id, client, attestation).expect("valid baseline");
    let original: serde_json::Value = serde_json::from_slice(client).expect("client data");
    for (key, value) in [
        ("origin", serde_json::json!("https://setup.example.com")),
        ("crossOrigin", serde_json::json!(true)),
        ("crossOrigin", serde_json::json!("false")),
        ("topOrigin", serde_json::json!(ORIGIN)),
        ("type", serde_json::json!("webauthn.get")),
        ("challenge", serde_json::json!(URL_SAFE_NO_PAD.encode([42; 32]))),
    ] {
        let mut changed = original.clone();
        changed[key] = value;
        let changed = serde_json::to_vec(&changed).expect("modified client JSON");
        assert!(
            matches!(
                verifier.verify_registration(&options.state, id, &changed, attestation),
                Err(PasskeyError::Denied)
            ),
            "{key}"
        );
    }
    let mut duplicate = client.to_vec();
    duplicate.pop();
    duplicate.extend_from_slice(br#", "origin":"https://setup.example.com:9443"}"#);
    assert!(matches!(
        verifier.verify_registration(&options.state, id, &duplicate, attestation),
        Err(PasskeyError::Denied)
    ));
    let mut original_cbor: ciborium::value::Value =
        ciborium::de::from_reader(attestation).expect("attestation map");
    let ciborium::value::Value::Map(map) = &mut original_cbor else { panic!("map") };
    map.push(map[0].clone());
    let mut duplicate = Vec::new();
    ciborium::ser::into_writer(&original_cbor, &mut duplicate).expect("duplicate CBOR");
    assert!(matches!(
        verifier.verify_registration(&options.state, id, client, &duplicate),
        Err(PasskeyError::Denied)
    ));
    let mut trailing = attestation.to_vec();
    trailing.push(0);
    assert!(matches!(
        verifier.verify_registration(&options.state, id, client, &trailing),
        Err(PasskeyError::Denied)
    ));
    assert!(matches!(
        verifier.verify_registration(&options.state, b"other", client, attestation),
        Err(PasskeyError::Denied)
    ));
    assert!(
        matches!(
            verifier.verify_registration(br#"{"version":2}"#, id, b"{}", attestation),
            Err(PasskeyError::State)
        ),
        "stored integrity precedes submitted parsing"
    );
    assert!(OperatorPasskeyVerifier::new("https://127.0.0.1").is_err());
    assert!(OperatorPasskeyVerifier::new("https://[::1]").is_err());
}

#[tokio::test]
async fn sqlite_success_audit_rollback_and_locked_expiry_are_atomic() {
    let (store, dir) = sqlite().await;
    let verifier = OperatorPasskeyVerifier::new(ORIGIN).expect("verifier");
    let disclosure =
        store.initialize_operator_setup(ORIGIN, false).await.expect("init").expect("token");
    let secret = token(&disclosure);
    let binding = jkt();
    let options =
        store.operator_setup_options(&secret, &binding, &verifier).await.expect("options");
    let mut auth = passkey::ResidentPasskey::authenticator();
    let registration = auth
        .do_registration(
            Url::parse(ORIGIN).expect("origin"),
            passkey::creation(&options.public_key),
        )
        .expect("registration");
    let input = OperatorRegistration {
        setup_token: &secret,
        ceremony_id: options.ceremony_id,
        browser_jkt: &binding,
        credential_id: registration.raw_id.as_ref(),
        client_data_json: registration.response.client_data_json.as_ref(),
        attestation_object: registration.response.attestation_object.as_ref(),
    };
    sqlx::query("CREATE TRIGGER deny_operator_success BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT, 'fixture failure'); END")
        .execute(store.pool()).await.expect("failure trigger");
    assert!(matches!(
        store.finish_operator_setup(&input, &verifier).await,
        Err(OperatorSetupError::Audit(_))
    ));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_operators")
        .fetch_one(store.pool())
        .await
        .expect("operator count");
    assert_eq!(count, 0);
    let consumed: Option<i64> = sqlx::query_scalar("SELECT consumed_at_s FROM operator_ceremonies")
        .fetch_one(store.pool())
        .await
        .expect("ceremony");
    assert!(consumed.is_none());
    sqlx::query("DROP TRIGGER deny_operator_success")
        .execute(store.pool())
        .await
        .expect("remove trigger");
    let mut tx = store.pool().begin_with("BEGIN IMMEDIATE").await.expect("hold lock");
    sqlx::query(
        "UPDATE operator_ceremonies SET issued_at_s=issued_at_s-600, expires_at_s=expires_at_s-600",
    )
    .execute(&mut *tx)
    .await
    .expect("expire while locked");
    let replica = store.clone();
    let ceremony_id = input.ceremony_id;
    let mut finish = tokio::spawn(async move {
        let input = OperatorRegistration {
            setup_token: &secret,
            ceremony_id,
            browser_jkt: &binding,
            credential_id: registration.raw_id.as_ref(),
            client_data_json: registration.response.client_data_json.as_ref(),
            attestation_object: registration.response.attestation_object.as_ref(),
        };
        replica.finish_operator_setup(&input, &verifier).await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut finish).await.is_err(),
        "finish must wait for serialization lock"
    );
    tx.commit().await.expect("release expired state");
    assert!(matches!(
        finish.await.expect("finish task"),
        Err(OperatorSetupError::Denied { consumed: false })
    ));
    let consumed: Option<i64> = sqlx::query_scalar("SELECT consumed_at_s FROM operator_ceremonies")
        .fetch_one(store.pool())
        .await
        .expect("expired ceremony");
    assert!(consumed.is_none());
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[tokio::test]
async fn sqlite_attempted_finish_commit_failure_preserves_unknown_outcome() {
    let (store, dir) = sqlite().await;
    let verifier = OperatorPasskeyVerifier::new(ORIGIN).expect("verifier");
    let secret =
        token(&store.initialize_operator_setup(ORIGIN, false).await.expect("init").expect("token"));
    let binding = jkt();
    let options =
        store.operator_setup_options(&secret, &binding, &verifier).await.expect("options");
    sqlx::raw_sql("CREATE TABLE operator_commit_parent (id INTEGER PRIMARY KEY); CREATE TABLE operator_commit_child (id INTEGER REFERENCES operator_commit_parent (id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER operator_commit_failure AFTER UPDATE OF consumed_at_s ON operator_ceremonies BEGIN INSERT INTO operator_commit_child VALUES (1); END;")
        .execute(store.pool()).await.expect("deferred failure fixture");
    let input = OperatorRegistration {
        setup_token: &secret,
        ceremony_id: options.ceremony_id,
        browser_jkt: &binding,
        credential_id: b"key",
        client_data_json: b"{}",
        attestation_object: b"bad",
    };
    assert!(
        matches!(
            store.finish_operator_setup(&input, &verifier).await,
            Err(OperatorSetupError::CommitOutcomeUnknown)
        ),
        "attempted COMMIT failure must never claim a rollback"
    );
    let consumed: Option<i64> = sqlx::query_scalar("SELECT consumed_at_s FROM operator_ceremonies")
        .fetch_one(store.pool())
        .await
        .expect("readback only for test");
    assert!(consumed.is_none());
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_passkey_setup_and_assertion() {
    let (store, pool, schema, _) = postgres_fixture().await;
    lifecycle!(store);
    store.pool().close().await;
    remove_schema(pool, &schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_denial_audit_failure_rolls_back_ceremony_consumption() {
    let (store, pool, schema, _) = postgres_fixture().await;
    let verifier = OperatorPasskeyVerifier::new(ORIGIN).expect("verifier");
    let secret =
        token(&store.initialize_operator_setup(ORIGIN, false).await.expect("init").expect("token"));
    let binding = jkt();
    let options =
        store.operator_setup_options(&secret, &binding, &verifier).await.expect("options");
    sqlx::raw_sql("CREATE FUNCTION reject_operator_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit failure'; END; $$; CREATE TRIGGER reject_operator_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION reject_operator_audit();")
        .execute(store.pool()).await.expect("failure fixture");
    let input = OperatorRegistration {
        setup_token: &secret,
        ceremony_id: options.ceremony_id,
        browser_jkt: &binding,
        credential_id: b"key",
        client_data_json: b"{}",
        attestation_object: b"bad",
    };
    assert!(matches!(
        store.finish_operator_setup(&input, &verifier).await,
        Err(OperatorSetupError::Audit(_))
    ));
    let consumed: Option<i64> = sqlx::query_scalar("SELECT consumed_at_s FROM operator_ceremonies")
        .fetch_one(store.pool())
        .await
        .expect("consumption");
    assert!(consumed.is_none());
    sqlx::query("DROP TRIGGER reject_operator_audit ON deployment_audit_events")
        .execute(store.pool())
        .await
        .expect("remove trigger");
    assert!(matches!(
        store.finish_operator_setup(&input, &verifier).await,
        Err(OperatorSetupError::Denied { consumed: true })
    ));
    store.pool().close().await;
    remove_schema(pool, &schema).await;
}

#[cfg(feature = "postgres-integration")]
async fn postgres_fixture() -> (scoplen_store::PostgresStore, sqlx::PgPool, String, String) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("dedicated PG fixture URL");
    let pool = sqlx::PgPool::connect(&database).await.expect("fixture admin pool");
    let schema = format!("operator_setup_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&pool)
        .await
        .expect("isolated test schema");
    let mut url = url::Url::parse(&database).expect("fixture URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let database = url.to_string();
    let store = scoplen_store::PostgresStore::connect(&database).await.expect("PG fixture");
    (store, pool, schema, database)
}

#[cfg(feature = "postgres-integration")]
async fn remove_schema(pool: sqlx::PgPool, schema: &str) {
    assert!(
        schema.starts_with("operator_setup_")
            && schema.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .expect("remove owned fixture schema");
    pool.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_lost_commit_ack_preserves_uncertainty_without_disclosure() {
    use std::sync::atomic::Ordering;
    let (direct, pool, schema, database) = postgres_fixture().await;
    let proxy = lost_commit::LostCommitProxy::start(&database).await;
    let proxied =
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxied fixture");
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        proxied.initialize_operator_setup(ORIGIN, false).await,
        Err(OperatorSetupError::CommitOutcomeUnknown)
    ));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    assert!(
        direct.initialize_operator_setup(ORIGIN, false).await.expect("durable restart").is_none()
    );
    let disclosure = direct
        .initialize_operator_setup(ORIGIN, true)
        .await
        .expect("local explicit recovery")
        .expect("new entitlement");
    let secret = token(&disclosure);
    let verifier = OperatorPasskeyVerifier::new(ORIGIN).expect("verifier");
    let binding = jkt();
    let options =
        direct.operator_setup_options(&secret, &binding, &verifier).await.expect("options");
    let mut auth = passkey::ResidentPasskey::authenticator();
    let result = auth
        .do_registration(
            Url::parse(ORIGIN).expect("origin"),
            passkey::creation(&options.public_key),
        )
        .expect("registration");
    let input = OperatorRegistration {
        setup_token: &secret,
        ceremony_id: options.ceremony_id,
        browser_jkt: &binding,
        credential_id: result.raw_id.as_ref(),
        client_data_json: result.response.client_data_json.as_ref(),
        attestation_object: result.response.attestation_object.as_ref(),
    };
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        proxied.finish_operator_setup(&input, &verifier).await,
        Err(OperatorSetupError::CommitOutcomeUnknown)
    ));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 2);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_operators")
        .fetch_one(direct.pool())
        .await
        .expect("committed readback");
    assert_eq!(count, 1, "COMMIT succeeded even though no success was returned");
    assert!(matches!(
        direct.initialize_operator_setup(ORIGIN, true).await,
        Err(OperatorSetupError::Denied { consumed: false })
    ));
    proxied.pool().close().await;
    direct.pool().close().await;
    drop(proxy);
    remove_schema(pool, &schema).await;
}
