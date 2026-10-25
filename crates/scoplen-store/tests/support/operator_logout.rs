// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use scoplen_crypto::{OperatorAccessTokenClaims, VerifiedOperatorAccessToken};
use scoplen_store::operator_token_keys::OperatorTokenKeyring;

const ROUTE: &str = "/api/v1/auth/operator/logout";

fn verified(raw: &str, keyring: &OperatorTokenKeyring) -> VerifiedOperatorAccessToken {
    let mut trusted = TrustedOperatorAccessTokenKeys::new(ORIGIN).expect("origin");
    for key in keyring.verification_keys() {
        trusted.insert(&key.kid, &key.public_key).expect("trusted key");
    }
    OperatorAccessToken::parse(raw)
        .expect("token")
        .verify(&trusted, u64::try_from(millis() / 1000).expect("clock"))
        .expect("verified token")
}

fn logout_proof(raw: &str) -> DpopProof {
    DpopProof::sign(
        &key(1),
        &key(1).public_key_sec1(),
        &DpopTarget::new("POST", ORIGIN, ROUTE).expect("target"),
        DpopToken::Protected(raw),
        u64::try_from(millis() / 1000).expect("clock"),
        None,
    )
    .expect("fresh token-bound proof")
}

fn signed(
    claims: &OperatorAccessTokenClaims,
    keyring: &OperatorTokenKeyring,
    verified_at: u64,
) -> (String, VerifiedOperatorAccessToken) {
    let mut trusted = TrustedOperatorAccessTokenKeys::new(ORIGIN).expect("origin");
    for key in keyring.verification_keys() {
        trusted.insert(&key.kid, &key.public_key).expect("trusted key");
    }
    let token = OperatorAccessToken::sign(
        keyring.signing_key(),
        &trusted,
        keyring.signing_key().kid(),
        claims,
    )
    .expect("signed test token");
    let verified = token.verify(&trusted, verified_at).expect("stateless verification");
    (token.as_str().to_owned(), verified)
}

macro_rules! login {
    ($store:expr) => {{
        let store = &$store;
        let (verifier, mut auth, operator, binding) = setup!(store);
        let keyring = store.ensure_operator_token_keyring(&TestKms).await.expect("keyring");
        let handle = operator.into_bytes();
        let (options, assertion) = assertion!(store, auth, &verifier, &binding);
        let session = store
            .finish_operator_login(
                &input!(options, assertion, &binding, &handle),
                &verifier,
                &keyring,
            )
            .await
            .expect("real passkey login");
        let principal = verified(&session.browser().access_token, &keyring);
        (verifier, auth, operator, binding, keyring, session, principal)
    }};
}

macro_rules! claim {
    ($store:expr, $proof:expr, $raw:expr, $principal:expr) => {
        $store.claim_operator_dpop_proof(
            $proof,
            &DpopTarget::new("POST", ORIGIN, ROUTE).expect("target"),
            DpopToken::Protected($raw),
            &$principal.claims().cnf_jkt,
        )
    };
}

macro_rules! logout {
    ($store:expr, $raw:expr, $principal:expr) => {{
        let proof = logout_proof($raw);
        claim!($store, &proof, $raw, $principal).await.expect("durable fresh proof");
        $store.logout_operator(source(), $principal, ORIGIN).await
    }};
}

macro_rules! lifecycle {
    ($store:expr, $replica:expr) => {{
        let store = &$store;
        let replica = &$replica;
        let (verifier, mut auth, operator, _, keyring, session, principal) = login!(store);
        let raw = &session.browser().access_token;
        let original = cookie(&session);
        let rotated = store
            .refresh_operator(source(), ORIGIN, &original, proof(&key(1)).as_str(), &keyring)
            .await
            .expect("retain spent and current digests");
        let b_binding = dpop_jwk_thumbprint(&key(2).public_key_sec1()).expect("B binding");
        let (options, assertion) = assertion!(store, auth, &verifier, &b_binding);
        let handle = operator.into_bytes();
        let b = store
            .finish_operator_login(
                &input!(options, assertion, &b_binding, &handle),
                &verifier,
                &keyring,
            )
            .await
            .expect("independent B family");
        let b_principal = verified(&b.browser().access_token, &keyring);
        let digests: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT token_digest FROM operator_refresh_tokens ORDER BY token_digest",
        )
        .fetch_all(store.pool())
        .await
        .expect("all original digests");
        let first = logout_proof(raw);
        claim!(store, &first, raw, principal).await.expect("proof admitted once");
        store.logout_operator(source(), &principal, ORIGIN).await.expect("confirmed first logout");
        let timestamp: i64 = sqlx::query_scalar(
            "SELECT revoked_at_ms FROM operator_refresh_families WHERE family_id=$1",
        )
        .bind(principal.claims().sid.as_bytes().as_slice())
        .fetch_one(store.pool())
        .await
        .expect("revocation");
        assert!(store.current_operator_session(&principal).await.expect("A guard").is_none());
        let rotated_principal = verified(&rotated.browser().access_token, &keyring);
        assert!(
            store
                .current_operator_session(&rotated_principal)
                .await
                .expect("rotated A guard")
                .is_none()
        );
        for refresh in [&original, &cookie(&rotated)] {
            assert!(matches!(
                store
                    .refresh_operator(source(), ORIGIN, refresh, proof(&key(1)).as_str(), &keyring)
                    .await,
                Err(Error::Denied { changed: false })
            ));
            sqlx::query("UPDATE operator_auth_admission SET cooldown_until_ms=0 WHERE endpoint=5")
                .execute(store.pool())
                .await
                .expect("separate negative refresh attempts");
        }
        assert!(matches!(
            claim!(replica, &first, raw, principal).await,
            Err(scoplen_store::operator_admission::OperatorAdmissionError::InvalidDpopProof)
        ));
        logout!(replica, raw, &principal).expect("fresh-proof terminal confirmation");
        let retained_timestamp: i64 = sqlx::query_scalar(
            "SELECT revoked_at_ms FROM operator_refresh_families WHERE family_id=$1",
        )
        .bind(principal.claims().sid.as_bytes().as_slice())
        .fetch_one(store.pool())
        .await
        .expect("unchanged revocation");
        assert_eq!(timestamp, retained_timestamp);
        store.cleanup_refresh_families().await.expect("normal maintenance retains unexpired state");
        let retained: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT token_digest FROM operator_refresh_tokens ORDER BY token_digest",
        )
        .fetch_all(store.pool())
        .await
        .expect("retained digests");
        assert_eq!(digests, retained);
        let events: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT event_bytes FROM deployment_audit_events")
                .fetch_all(store.pool())
                .await
                .expect("audit events");
        let prefix = [b"spl-operator-session-v1".as_slice(), &[7]].concat();
        let revocations: Vec<_> =
            events.iter().filter(|event| event.starts_with(&prefix)).collect();
        assert_eq!(revocations.len(), 1);
        assert_eq!(revocations[0].len(), prefix.len() + 8 + 16 + 16 + 1);
        assert_eq!(&revocations[0][prefix.len() + 8..][..16], operator.as_bytes());
        assert_eq!(&revocations[0][prefix.len() + 24..][..16], principal.claims().sid.as_bytes());
        assert_eq!(revocations[0].last(), Some(&1));
        assert!(
            replica
                .current_operator_session(&b_principal)
                .await
                .expect("B remains current")
                .is_some()
        );
        replica
            .refresh_operator(source(), ORIGIN, &cookie(&b), proof(&key(2)).as_str(), &keyring)
            .await
            .expect("B still refreshes");
        let (options, assertion) = assertion!(store, auth, &verifier, &b_binding);
        let fresh = store
            .finish_operator_login(
                &input!(options, assertion, &b_binding, &handle),
                &verifier,
                &keyring,
            )
            .await
            .expect("fresh login after logout");
        assert_ne!(
            verified(&fresh.browser().access_token, &keyring).claims().sid,
            principal.claims().sid
        );
        store.verify_deployment_audit_chain().await.expect("audit chain");
    }};
}

macro_rules! eligibility {
    ($store:expr) => {{
        let store = &$store;
        let (verifier, _, _, binding, _, session, principal) = login!(store);
        let credential = sqlx::query("SELECT credential_id,credential_state FROM operator_credentials")
            .fetch_one(store.pool()).await.expect("stored credential");
        let id: Vec<u8> = credential.get("credential_id");
        let saved: Vec<u8> = credential.get("credential_state");
        verifier.validate_stored_credential(&saved, &id).expect("valid public validator");
        assert!(verifier.validate_stored_credential(&saved, &[0]).is_err());
        assert!(verifier.validate_stored_credential(b"{}", &id).is_err());
        let mut unverified: serde_json::Value = serde_json::from_slice(&saved).expect("fixture state");
        assert_eq!(unverified["library"]["user_verified"], serde_json::json!(true));
        unverified["library"]["user_verified"] = serde_json::json!(false);
        let unverified = serde_json::to_vec(&unverified).expect("corrupt credential");
        assert!(verifier.validate_stored_credential(&unverified, &id).is_err());
        let mut corrupt_key: serde_json::Value = serde_json::from_slice(&saved).expect("fixture state");
        let point = &mut corrupt_key["library"]["cred"]["key"]["EC_EC2"];
        assert!(point.is_object(), "the maintained credential stores an EC2 key");
        point["x"] = serde_json::json!(URL_SAFE_NO_PAD.encode([0_u8; 32]));
        point["y"] = serde_json::json!(URL_SAFE_NO_PAD.encode([0_u8; 32]));
        let corrupt_key = serde_json::to_vec(&corrupt_key).expect("off-curve credential");
        assert!(verifier.validate_stored_credential(&corrupt_key, &id).is_err());
        assert!(OperatorPasskeyVerifier::new("https://other.example.com").expect("other RP")
            .validate_stored_credential(&saved, &id).is_err());
        for terminal in [false, true] {
            if terminal { logout!(store, &session.browser().access_token, &principal).expect("terminal fixture"); }
            for (corrupt, restore) in [
                ("UPDATE deployment_operators SET active=0", "UPDATE deployment_operators SET active=1"),
                ("UPDATE operator_credentials SET active=0", "UPDATE operator_credentials SET active=1"),
                ("UPDATE operator_credentials SET rp_id='other.example.com'", "UPDATE operator_credentials SET rp_id='operator.example.com'"),
                ("UPDATE operator_credentials SET trusted_origin='https://other.example.com'", "UPDATE operator_credentials SET trusted_origin='https://operator.example.com:9443'"),
                ("UPDATE operator_refresh_families SET trusted_origin='https://other.example.com'", "UPDATE operator_refresh_families SET trusted_origin='https://operator.example.com:9443'"),
                ("UPDATE operator_refresh_families SET scope='other:scope'", "UPDATE operator_refresh_families SET scope='personal-invitation:issue'"),
            ] {
                sqlx::query("DELETE FROM operator_auth_admission WHERE endpoint=6").execute(store.pool()).await.expect("independent eligibility case");
                sqlx::raw_sql(corrupt).execute(store.pool()).await.expect("ineligible fixture");
                assert!(matches!(logout!(store, &session.browser().access_token, &principal), Err(Error::Denied { changed: false })), "both live and terminal reject {corrupt}");
                let private: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operator_auth_admission WHERE endpoint=6 AND kind=4")
                    .fetch_one(store.pool()).await.expect("no private selection for invalid current state");
                assert_eq!(private, 0);
                sqlx::raw_sql(restore).execute(store.pool()).await.expect("restore fixture");
            }
            for corrupt in [b"{}".as_slice(), unverified.as_slice(), corrupt_key.as_slice()] {
                sqlx::query("UPDATE operator_credentials SET credential_state=$1").bind(corrupt).execute(store.pool()).await.expect("corrupt library state");
                assert!(matches!(logout!(store, &session.browser().access_token, &principal), Err(Error::Denied { changed: false })));
            }
            sqlx::query("UPDATE operator_credentials SET credential_state=$1").bind(&saved).execute(store.pool()).await.expect("restore library state");
            sqlx::query("UPDATE operator_refresh_families SET dpop_jkt=$1")
                .bind(dpop_jwk_thumbprint(&key(2).public_key_sec1()).expect("wrong JKT"))
                .execute(store.pool()).await.expect("corrupt family binding");
            assert!(matches!(logout!(store, &session.browser().access_token, &principal), Err(Error::Denied { changed: false })));
            sqlx::query("UPDATE operator_refresh_families SET dpop_jkt=$1").bind(&binding)
                .execute(store.pool()).await.expect("restore family binding");
            sqlx::query("DELETE FROM operator_auth_admission WHERE endpoint=6").execute(store.pool()).await.expect("clear negative test cooldown");
        }
    }};
}

macro_rules! rollback {
    ($store:expr, $fail:expr, $clear:expr) => {{
        let store = &$store;
        let (_, _, _, _, _, session, principal) = login!(store);
        let raw = &session.browser().access_token;
        let proof = logout_proof(raw);
        claim!(store, &proof, raw, principal).await.expect("durable replay before mutation");
        sqlx::raw_sql($fail).execute(store.pool()).await.expect("audit failure");
        assert!(matches!(
            store.logout_operator(source(), &principal, ORIGIN).await,
            Err(Error::Audit)
        ));
        let revoked: Option<i64> =
            sqlx::query_scalar("SELECT revoked_at_ms FROM operator_refresh_families")
                .fetch_one(store.pool())
                .await
                .expect("revocation rolled back");
        assert!(revoked.is_none());
        assert!(matches!(
            claim!(store, &proof, raw, principal).await,
            Err(scoplen_store::operator_admission::OperatorAdmissionError::InvalidDpopProof)
        ));
        sqlx::query("UPDATE operator_credentials SET active=0")
            .execute(store.pool())
            .await
            .expect("ineligible denial fixture");
        let denied_proof = logout_proof(raw);
        claim!(store, &denied_proof, raw, principal).await.expect("independent denial proof");
        assert!(
            matches!(store.logout_operator(source(), &principal, ORIGIN).await, Err(Error::Audit)),
            "mandatory denial audit failure takes precedence"
        );
        sqlx::query("UPDATE operator_credentials SET active=1")
            .execute(store.pool())
            .await
            .expect("restore active credential");
        sqlx::raw_sql($clear).execute(store.pool()).await.expect("restore audit");
        logout!(store, raw, &principal).expect("explicit fresh-proof retry after rollback");
    }};
}

macro_rules! token_checks {
    ($store:expr) => {{
        let store = &$store;
        let (_, _, _, _, keyring, session, principal) = login!(store);
        for terminal in [false, true] {
            if terminal {
                sqlx::query("DELETE FROM operator_auth_admission WHERE endpoint=6")
                    .execute(store.pool())
                    .await
                    .expect("independent terminal case");
                logout!(store, &session.browser().access_token, &principal)
                    .expect("terminal fixture");
            }
            for case in 0..4 {
                let mut claims = principal.claims().clone();
                match case {
                    0 => claims.sid = Uuid::now_v7(),
                    1 => claims.sub = Uuid::now_v7(),
                    2 => {
                        claims.cnf_jkt =
                            dpop_jwk_thumbprint(&key(2).public_key_sec1()).expect("other JKT")
                    }
                    _ => {
                        claims.exp = u64::try_from(millis() / 1000).expect("clock");
                        claims.iat = claims.exp - 600;
                    }
                }
                let (_, wrong) = signed(&claims, &keyring, claims.iat);
                assert!(matches!(
                    store.logout_operator(source(), &wrong, ORIGIN).await,
                    Err(Error::Denied { changed: false })
                ));
            }
            assert_eq!(
                store.current_operator_session(&principal).await.expect("ordinary guard").is_none(),
                terminal
            );
            let revoked: Option<i64> =
                sqlx::query_scalar("SELECT revoked_at_ms FROM operator_refresh_families")
                    .fetch_one(store.pool())
                    .await
                    .expect("not revoked");
            assert_eq!(revoked.is_some(), terminal);
        }
    }};
}

macro_rules! terminal_quota {
    ($store:expr, $replica:expr) => {{
        let store = &$store;
        let replica = &$replica;
        let (_, _, _, _, _, session, principal) = login!(store);
        for attempt in 0..10 {
            let current = if attempt % 2 == 0 { store } else { replica };
            logout!(current, &session.browser().access_token, &principal).expect("each eligible confirmation consumes quota");
        }
        let before: (i64, i64, Option<i64>) = sqlx::query_as("SELECT attempts,failure_streak,cooldown_until_ms FROM operator_auth_admission WHERE endpoint=6 AND kind=4")
            .fetch_one(store.pool()).await.expect("private window");
        assert_eq!(before, (10, 0, None));
        assert!(matches!(logout!(replica, &session.browser().access_token, &principal), Err(Error::RateLimited(_))));
        let after: (i64, i64, Option<i64>) = sqlx::query_as("SELECT attempts,failure_streak,cooldown_until_ms FROM operator_auth_admission WHERE endpoint=6 AND kind=4")
            .fetch_one(store.pool()).await.expect("blocked quota unchanged");
        assert_eq!(before, after);
        let events: Vec<Vec<u8>> = sqlx::query_scalar("SELECT event_bytes FROM deployment_audit_events")
            .fetch_all(store.pool()).await.expect("one revocation audit");
        let prefix = [b"spl-operator-session-v1".as_slice(), &[7]].concat();
        assert_eq!(events.iter().filter(|event| event.starts_with(&prefix)).count(), 1);
    }};
}

macro_rules! expiry_after_lock {
    ($store:expr, $begin:expr, $hold:expr) => {{
        let store = &$store;
        let (_, _, _, _, _, session, principal) = login!(store);
        let raw = &session.browser().access_token;
        let principal = std::sync::Arc::new(principal);
        for terminal in [false, true] {
            if terminal { logout!(store, raw, &principal).expect("eligible terminal fixture"); }
            let original: (i64, i64, Option<i64>) = sqlx::query_as("SELECT created_at_ms,expires_at_ms,revoked_at_ms FROM operator_refresh_families")
                .fetch_one(store.pool()).await.expect("original family");
            let fresh = logout_proof(raw);
            claim!(store, &fresh, raw, principal).await.expect("fresh proof before lock wait");
            let mut tx = $begin;
            sqlx::query($hold).execute(&mut *tx).await.expect("hold session lock");
            let waiting = {
                let replica = store.clone();
                let principal = principal.clone();
                tokio::spawn(async move { replica.logout_operator(source(), &principal, ORIGIN).await })
            };
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            assert!(!waiting.is_finished(), "live and terminal checks share session serialization");
            let expired = millis() - 1;
            sqlx::query("UPDATE operator_refresh_families SET created_at_ms=$1,expires_at_ms=$2,revoked_at_ms=$3")
                .bind(expired - 2_592_000_000_i64).bind(expired).bind(original.2)
                .execute(&mut *tx).await.expect("expire while request waits");
            tx.commit().await.expect("release session lock");
            assert!(matches!(waiting.await.expect("waiter"), Err(Error::Denied { changed: false })));
            let revoked: Option<i64> = sqlx::query_scalar("SELECT revoked_at_ms FROM operator_refresh_families")
                .fetch_one(store.pool()).await.expect("no further revocation");
            assert_eq!(revoked, original.2);
            sqlx::query("UPDATE operator_refresh_families SET created_at_ms=$1,expires_at_ms=$2")
                .bind(original.0).bind(original.1).execute(store.pool()).await.expect("restore family");
            sqlx::query("DELETE FROM operator_auth_admission WHERE endpoint=6").execute(store.pool()).await.expect("independent lock scenario");
        }
    }};
}

#[tokio::test]
async fn sqlite_logout_is_family_bound_terminal_and_retains_all_digests() {
    let (store, dir) = sqlite().await;
    let replica = SqliteStore::open(&dir.join("store.sqlite")).await.expect("independent pool");
    lifecycle!(store, replica);
    store.pool().close().await;
    replica.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[tokio::test]
async fn sqlite_logout_checks_current_state_even_after_revocation() {
    let (store, dir) = sqlite().await;
    eligibility!(store);
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[tokio::test]
async fn sqlite_logout_audit_rollback_keeps_proof_consumed() {
    let (store, dir) = sqlite().await;
    rollback!(
        store,
        "CREATE TRIGGER deny_logout_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'fixture failure'); END",
        "DROP TRIGGER deny_logout_audit"
    );
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[tokio::test]
async fn sqlite_logout_rejects_mismatched_and_expired_token_claims() {
    let (store, dir) = sqlite().await;
    token_checks!(store);
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[tokio::test]
async fn sqlite_logout_rechecks_live_and_terminal_expiry_after_lock_wait() {
    let (store, dir) = sqlite().await;
    expiry_after_lock!(
        store,
        store.pool().begin_with("BEGIN IMMEDIATE").await.expect("writer"),
        "SELECT 1"
    );
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[tokio::test]
async fn sqlite_logout_terminal_confirmation_uses_independent_durable_quota() {
    let (store, dir) = sqlite().await;
    let replica = SqliteStore::open(&dir.join("store.sqlite")).await.expect("independent pool");
    terminal_quota!(store, replica);
    store.pool().close().await;
    replica.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_logout_lifecycle_current_state_and_audit_rollback() {
    for scenario in 0..6 {
        let (store, pool, schema, database) = postgres_fixture().await;
        let replica =
            scoplen_store::PostgresStore::connect(&database).await.expect("independent pool");
        match scenario {
            0 => lifecycle!(store, replica),
            1 => eligibility!(store),
            2 => rollback!(
                store,
                "CREATE FUNCTION deny_logout_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture failure'; END; $$; CREATE TRIGGER deny_logout_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION deny_logout_audit()",
                "DROP TRIGGER deny_logout_audit ON deployment_audit_events; DROP FUNCTION deny_logout_audit()"
            ),
            3 => token_checks!(store),
            4 => terminal_quota!(store, replica),
            _ => expiry_after_lock!(
                store,
                store.pool().begin().await.expect("holder"),
                "SELECT pg_advisory_xact_lock(1396916048,1397052243)"
            ),
        }
        replica.pool().close().await;
        cleanup(store, pool, schema).await;
    }
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_logout_unknown_commit_is_confirmed_only_by_fresh_proof_and_current_state() {
    use std::sync::atomic::Ordering;
    let (store, pool, schema, database) = postgres_fixture().await;
    let (_, _, _, _, _, session, principal) = login!(store);
    let raw = &session.browser().access_token;
    let proxy = lost_commit::LostCommitProxy::start(&database).await;
    let proxied =
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxy pool");
    let first = logout_proof(raw);
    claim!(store, &first, raw, principal).await.expect("proof already durable");
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        proxied.logout_operator(source(), &principal, ORIGIN).await,
        Err(Error::CommitOutcomeUnknown)
    ));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    let timestamp: i64 = sqlx::query_scalar("SELECT revoked_at_ms FROM operator_refresh_families")
        .fetch_one(store.pool())
        .await
        .expect("committed revocation");
    let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
        .fetch_one(store.pool())
        .await
        .expect("committed audit");
    assert!(matches!(
        claim!(store, &first, raw, principal).await,
        Err(scoplen_store::operator_admission::OperatorAdmissionError::InvalidDpopProof)
    ));
    logout!(store, raw, &principal).expect("explicit fresh-proof terminal confirmation");
    let after: i64 = sqlx::query_scalar("SELECT revoked_at_ms FROM operator_refresh_families")
        .fetch_one(store.pool())
        .await
        .expect("unchanged timestamp");
    assert_eq!(timestamp, after);
    let after_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
        .fetch_one(store.pool())
        .await
        .expect("unchanged audit");
    assert_eq!(events, after_events);
    sqlx::query("UPDATE operator_credentials SET active=0")
        .execute(store.pool())
        .await
        .expect("eligibility ends");
    assert!(matches!(logout!(store, raw, &principal), Err(Error::Denied { changed: false })));
    proxied.pool().close().await;
    drop(proxy);
    cleanup(store, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
async fn observed_store(database: &str) -> (scoplen_store::PostgresStore, String) {
    let application = format!("logout_{}", Uuid::new_v4().simple());
    let mut url = url::Url::parse(database).expect("database URL");
    url.query_pairs_mut().append_pair("application_name", &application);
    (scoplen_store::PostgresStore::connect(url.as_str()).await.expect("observed pool"), application)
}

#[cfg(feature = "postgres-integration")]
async fn wait_for_delay(pool: &sqlx::PgPool, application: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event='PgSleep')",
            ).bind(application).fetch_one(pool).await.expect("inspect real waiter");
            if waiting { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("request must reach real database delay");
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_logout_rechecks_token_and_family_expiry_after_audit_wait_before_commit() {
    for token_expires in [false, true] {
        let (store, pool, schema, database) = postgres_fixture().await;
        let (_, _, _, _, keyring, session, principal) = login!(store);
        sqlx::raw_sql("CREATE FUNCTION delay_logout_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF substring(NEW.event_bytes FROM 1 FOR 24) = convert_to('spl-operator-session-v1' || chr(7), 'UTF8') THEN PERFORM pg_sleep(4); END IF; RETURN NEW; END; $$; CREATE TRIGGER delay_logout_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION delay_logout_audit()")
            .execute(store.pool()).await.expect("delay only the revocation audit while production locks are held");
        let expires = millis() / 1000 + 3;
        let (raw, principal) = if token_expires {
            let mut claims = principal.claims().clone();
            claims.exp = u64::try_from(expires).expect("expiry");
            claims.iat = claims.exp - 600;
            signed(&claims, &keyring, u64::try_from(millis() / 1000).expect("clock"))
        } else {
            sqlx::query("UPDATE operator_refresh_families SET created_at_ms=$1,expires_at_ms=$2")
                .bind(expires * 1000 - 2_592_000_000_i64)
                .bind(expires * 1000)
                .execute(store.pool())
                .await
                .expect("near family expiry");
            (session.browser().access_token.clone(), principal)
        };
        let fresh = logout_proof(&raw);
        claim!(store, &fresh, &raw, principal).await.expect("proof before mutation");
        let (observed, application) = observed_store(&database).await;
        let waiting = {
            let observed = observed.clone();
            tokio::spawn(
                async move { observed.logout_operator(source(), &principal, ORIGIN).await },
            )
        };
        wait_for_delay(&pool, &application).await;
        assert!(!waiting.is_finished());
        assert!(matches!(waiting.await.expect("waiter"), Err(Error::Denied { changed: false })));
        let revoked: Option<i64> =
            sqlx::query_scalar("SELECT revoked_at_ms FROM operator_refresh_families")
                .fetch_one(store.pool())
                .await
                .expect("revocation rolled back before commit");
        assert!(revoked.is_none());
        let events: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT event_bytes FROM deployment_audit_events")
                .fetch_all(store.pool())
                .await
                .expect("rolled back revocation audit");
        let prefix = [b"spl-operator-session-v1".as_slice(), &[7]].concat();
        assert!(!events.iter().any(|event| event.starts_with(&prefix)));
        let charged: (i64, i64) = sqlx::query_as("SELECT attempts,failure_streak FROM operator_auth_admission WHERE endpoint=6 AND kind=4")
            .fetch_one(store.pool()).await.expect("admitted private attempt survives mutation rollback");
        assert_eq!(charged, (1, 1));
        store
            .verify_deployment_audit_chain()
            .await
            .expect("savepoint rollback preserves audit chain");
        observed.pool().close().await;
        cleanup(store, pool, schema).await;
    }
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_logout_serializes_both_orders_with_real_refresh() {
    for logout_first in [false, true] {
        let (store, pool, schema, database) = postgres_fixture().await;
        let (_, _, _, _, keyring, session, principal) = login!(store);
        let principal = std::sync::Arc::new(principal);
        let keyring = std::sync::Arc::new(keyring);
        let fresh = logout_proof(&session.browser().access_token);
        claim!(store, &fresh, &session.browser().access_token, principal)
            .await
            .expect("logout proof claimed once");
        sqlx::raw_sql("CREATE FUNCTION delay_logout_race_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.5); RETURN NEW; END; $$; CREATE TRIGGER delay_logout_race_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION delay_logout_race_audit()")
                .execute(store.pool()).await.expect("hold real mutation locks during its audit");
        let (first_store, application) = observed_store(&database).await;
        let first = {
            let replica = first_store.clone();
            let principal = principal.clone();
            let keyring = keyring.clone();
            let refresh = cookie(&session);
            tokio::spawn(async move {
                if logout_first {
                    replica
                        .logout_operator(source(), &principal, ORIGIN)
                        .await
                        .map(|_| ())
                        .map_err(|_| ())
                } else {
                    replica
                        .refresh_operator(
                            source(),
                            ORIGIN,
                            &refresh,
                            proof(&key(1)).as_str(),
                            &keyring,
                        )
                        .await
                        .map(|_| ())
                        .map_err(|_| ())
                }
            })
        };
        wait_for_delay(&pool, &application).await;
        assert!(!first.is_finished());
        let second = {
            let replica = store.clone();
            let principal = principal.clone();
            let keyring = keyring.clone();
            let refresh = cookie(&session);
            tokio::spawn(async move {
                if logout_first {
                    replica
                        .refresh_operator(
                            source(),
                            ORIGIN,
                            &refresh,
                            proof(&key(1)).as_str(),
                            &keyring,
                        )
                        .await
                        .map(|_| ())
                        .map_err(|_| ())
                } else {
                    replica
                        .logout_operator(source(), &principal, ORIGIN)
                        .await
                        .map(|_| ())
                        .map_err(|_| ())
                }
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(!second.is_finished(), "session lock remains held through audit");
        first.await.expect("first task").expect("first operation commits");
        let later = second.await.expect("second task");
        assert_eq!(
            later.is_err(),
            logout_first,
            "later protected action cannot authorize a revoked family"
        );
        assert!(
            store
                .current_operator_session(&principal)
                .await
                .expect("revoked after either order")
                .is_none()
        );
        first_store.pool().close().await;
        cleanup(store, pool, schema).await;
    }
}
