// SPDX-License-Identifier: AGPL-3.0-only

#[path = "support/legacy_identity.rs"]
mod legacy_identity;
#[cfg(feature = "postgres-integration")]
#[path = "support/lost_commit.rs"]
mod lost_commit;
#[path = "support/pool_close.rs"]
mod pool_close;
mod support;

use scoplen_api::{
    account_admission::{
        AccountCommittedConfirmation, AccountRegistrationPayload, AccountRegistrationRequest,
        AccountRequestChallengeRequest, AccountRequestChallengeResponse, AccountRequestIntent,
        AccountRequestKind,
    },
    sync::SyncAccountKeyBundleUpdate,
};
use scoplen_crypto::{
    AccountRequestProof, AccountRequestSignatureInput, DeviceArkWrap, DeviceCertificate,
    DeviceKemKeyPair, Ed25519SigningKey, P256SigningKey, PasswordArkWrap, PasswordBootstrapContext,
    PasswordSecrets, RevocationStatement, SecretBytes, SecretVec,
};
#[cfg(feature = "postgres-integration")]
use scoplen_store::PostgresStore;
use scoplen_store::{
    RelationalStore, SqliteStore,
    account_entry_admission::{AccountEntryAdmissionDecision, AccountEntryEndpoint},
    account_registration::{AccountRegistrationError, AccountRegistrationResult},
};
use uuid::Uuid;

const ORIGIN: &str = "https://registration.test";
const CEILING: u64 = 32;

struct Fixture {
    payload: AccountRegistrationPayload,
    root: Ed25519SigningKey,
    device: P256SigningKey,
    seed: u8,
}

fn scalar(seed: u8) -> [u8; 32] {
    let mut key = [0; 32];
    key[31] = seed;
    key
}

fn fixture(username: &str, seed: u8) -> Fixture {
    let root = Ed25519SigningKey::from_bytes(&[seed; 32]).expect("Account root");
    let device = P256SigningKey::from_bytes(&scalar(seed)).expect("Device signing key");
    let identity = legacy_identity::LegacyIdentity::new(&root, &device);
    let secrets = PasswordSecrets::create(
        ORIGIN,
        username,
        SecretVec::new(b"a real registration test password".to_vec()),
    )
    .expect("password secrets");
    let context = PasswordBootstrapContext::new(
        secrets.context().clone(),
        identity.account_id,
        identity.personal_vault_id,
        &identity.account_signing_public_key,
        &identity.account_kem_public_key,
        1,
    )
    .expect("bound bootstrap context");
    let payload = AccountRegistrationPayload {
        operation_id: Uuid::now_v7(),
        origin: ORIGIN.into(),
        username: username.into(),
        account_id: identity.account_id,
        personal_vault_id: identity.personal_vault_id,
        device_id: identity.device_certificate.device_id,
        account_signing_public_key: identity.account_signing_public_key,
        account_kem_public_key: identity.account_kem_public_key,
        password_salt: *secrets.context().salt(),
        verifier: *secrets.verifier().as_bytes(),
        password_ark: PasswordArkWrap::seal(&secrets, &context, &SecretBytes::new([11; 32]))
            .expect("password ARK")
            .encode(),
        device_certificate: identity.device_certificate.encode().expect("certificate"),
        key_bundle: identity.key_bundle_update.to_cbor().expect("accepted PUT"),
        personal_wrapped_key: identity
            .wrapped_personal_vault_key
            .try_into()
            .expect("Personal wrap"),
    };
    let mut fixture = Fixture { payload, root, device, seed };
    let kem =
        DeviceKemKeyPair::from_private_bytes(&scalar(seed + 100)).expect("independent Device KEM");
    let signing = fixture.device.public_key_sec1();
    set_device_keys(&mut fixture, signing, kem.public_key().to_vec());
    fixture
}

fn set_device_keys(fixture: &mut Fixture, signing: Vec<u8>, kem: Vec<u8>) {
    let p = &mut fixture.payload;
    let wrapped_ark =
        DeviceArkWrap::seal(p.account_id, p.device_id, &kem, &SecretBytes::new([11; 32]))
            .expect("bound Device wrap")
            .encode()
            .to_vec();
    p.device_certificate = DeviceCertificate::issue(
        &fixture.root,
        p.device_id,
        p.account_id,
        signing,
        kem,
        "Registration test Device".into(),
        "test".into(),
        1,
    )
    .expect("signed certificate")
    .encode()
    .expect("encoded certificate");
    let mut bundle = SyncAccountKeyBundleUpdate::from_cbor(&p.key_bundle).expect("bundle");
    bundle.device_wraps[0].device_id = p.device_id;
    bundle.device_wraps[0].wrapped_ark = wrapped_ark;
    bundle.signature =
        fixture.root.sign(&bundle.signature_input().expect("signature input")).to_vec();
    p.key_bundle = bundle.to_cbor().expect("signed bundle");
    p.validate().expect("complete real material");
}

fn request(
    fixture: &Fixture,
    intent: AccountRequestIntent,
    challenge: AccountRequestChallengeResponse,
) -> AccountRegistrationRequest {
    let payload = fixture.payload.to_cbor().expect("exact stable business bytes");
    let input = AccountRequestSignatureInput::new(AccountRequestKind::Register, &payload)
        .expect("Account signature input");
    let account_signature = input.sign(&fixture.root);
    let digest = input.request_digest(&account_signature);
    let proof = AccountRequestProof::new(
        AccountRequestKind::Register,
        intent,
        ORIGIN,
        challenge.attempt_id.as_bytes(),
        challenge.nonce.as_bytes(),
        fixture.payload.operation_id,
        fixture.payload.device_id,
        &digest,
    )
    .expect("fresh proof context");
    AccountRegistrationRequest {
        intent,
        payload: SecretVec::new(payload),
        account_signature,
        device_proof: proof.sign(&fixture.device).expect("Device possession proof"),
        attempt_id: challenge.attempt_id,
        nonce: challenge.nonce,
    }
}

fn peer(seed: u8) -> std::net::IpAddr {
    std::net::IpAddr::from([192, 0, 2, seed])
}
fn deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + std::time::Duration::from_secs(30)
}

fn assert_same_response(left: &[u8], right: &[u8]) {
    assert_eq!(SecretVec::new(left.to_vec()), SecretVec::new(right.to_vec()));
}

macro_rules! challenge {
    ($store:expr,$fixture:expr,$intent:expr) => {{
        let store = &$store;
        assert_eq!(
            store
                .admit_account_entry_source(AccountEntryEndpoint::RequestChallenge, peer(1))
                .await
                .expect("source admission"),
            AccountEntryAdmissionDecision::Admitted
        );
        let binding = AccountRequestChallengeRequest {
            kind: AccountRequestKind::Register,
            intent: $intent,
            operation_id: $fixture.payload.operation_id,
            device_id: $fixture.payload.device_id,
        };
        store
            .issue_account_request_challenge(peer(1), ORIGIN, &binding)
            .await
            .expect("fresh request challenge")
    }};
}

macro_rules! execute {
    ($store:expr,$request:expr,$enabled:expr) => {{
        let store = &$store;
        assert_eq!(
            store
                .admit_account_entry_source(AccountEntryEndpoint::Register, peer(2))
                .await
                .expect("source admission"),
            AccountEntryAdmissionDecision::Admitted
        );
        store
            .execute_account_registration(
                peer(2),
                ORIGIN,
                $enabled,
                CEILING,
                &$request.to_json().expect("structurally valid envelope"),
                deadline(),
            )
            .await
    }};
}

macro_rules! happy {
    ($store:expr) => {{
        let store = &$store;
        store.initialize_account_id_retention(CEILING).await.expect("D129 reservation");
        let fixture = fixture("registration-happy", 1);
        let submitted = request(
            &fixture,
            AccountRequestIntent::Submit,
            challenge!(store, fixture, AccountRequestIntent::Submit),
        );
        let AccountRegistrationResult::Created(bytes) =
            execute!(store, submitted, true).expect("confirmed new aggregate")
        else {
            panic!("submit creates");
        };
        let confirmation =
            AccountCommittedConfirmation::from_json(&bytes).expect("bounded public confirmation");
        confirmation
            .validate_for_request(
                AccountRequestKind::Register,
                submitted.payload.as_bytes(),
                &submitted.account_signature,
            )
            .expect("exact original operation");
        for table in [
            "identity_accounts",
            "identity_devices",
            "sync_personal_vaults",
            "account_password_bootstrap",
            "account_operation_receipts",
            "account_used_ids",
        ] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(store.pool())
                .await
                .expect("complete aggregate");
            assert_eq!(count, 1, "{table}");
        }
        for table in ["device_refresh_families", "device_refresh_tokens", "device_auth_challenges"]
        {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(store.pool())
                .await
                .expect("no authority issued");
            assert_eq!(count, 0, "{table}");
        }
        sqlx::query("UPDATE identity_devices SET active=FALSE")
            .execute(store.pool())
            .await
            .expect("later revocation");
        sqlx::query("UPDATE identity_accounts SET account_signing_public_key=$1")
            .bind([99_u8; 32].as_slice())
            .execute(store.pool())
            .await
            .expect("later root state");
        let head = store.deployment_audit_head().await.expect("audit head");
        let confirm = request(
            &fixture,
            AccountRequestIntent::Confirm,
            challenge!(store, fixture, AccountRequestIntent::Confirm),
        );
        let AccountRegistrationResult::Confirmed(repeated) = execute!(store, confirm, false)
            .expect("historical confirmation despite disabled registration and revocation")
        else {
            panic!("explicit historical confirm");
        };
        assert_same_response(&repeated, &bytes);
        assert_eq!(
            store.deployment_audit_head().await.expect("audit head"),
            head,
            "no duplicate business success audit"
        );
        (fixture, bytes)
    }};
}

macro_rules! proof_denials {
    ($store:expr)=>{{
        let store=&$store;
        store.initialize_account_id_retention(CEILING).await.expect("guard");
        let fixture=fixture("registration-denial",2);
        let mut proof=request(&fixture,AccountRequestIntent::Submit,challenge!(store,fixture,AccountRequestIntent::Submit));
        proof.device_proof[0]^=1;
        assert_eq!(execute!(store,proof,true).expect_err("invalid possession"),AccountRegistrationError::AuthenticationRequired);
        let pending:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_request_challenges").fetch_one(store.pool()).await.expect("challenge consumed");assert_eq!(pending,0);
        let established:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_entry_admission WHERE endpoint=2 AND kind=4").fetch_one(store.pool()).await.expect("no unverified Account debt");assert_eq!(established,0);
        let business:i64=sqlx::query_scalar("SELECT COUNT(*) FROM identity_accounts").fetch_one(store.pool()).await.expect("no business");assert_eq!(business,0);
        assert_eq!(store.account_id_retention_summary().await.expect("no lifetime slot").used,0);
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=time_high_water_ms+2000").execute(store.pool()).await.expect("elapsed cooldown");
        let live=challenge!(store,fixture,AccountRequestIntent::Submit);
        let mut invalid=request(&fixture,AccountRequestIntent::Submit,live);
        invalid.payload=SecretVec::new(vec![0]);
        let body=serde_json::to_vec(&serde_json::json!({"intent":"submit","payload":"AA","account_signature":base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD,invalid.account_signature),"attempt_id":base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD,invalid.attempt_id.as_bytes()),"nonce":base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD,invalid.nonce.as_bytes()),"device_proof":base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD,invalid.device_proof)})).expect("invalid protected body");
        assert_eq!(store.execute_account_registration(peer(2),ORIGIN,true,CEILING,&body,deadline()).await.expect_err("structural denial before claim"),AccountRegistrationError::InvalidRequest);
        let pending:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_request_challenges").fetch_one(store.pool()).await.expect("structural failure keeps challenge");assert_eq!(pending,1);
    }};
}

macro_rules! deletion {
    ($store:expr) => {{
        let store = &$store;
        store.initialize_account_id_retention(CEILING).await.expect("guard");
        let fixture = fixture("registration-delete", 3);
        let submitted = request(
            &fixture,
            AccountRequestIntent::Submit,
            challenge!(store, fixture, AccountRequestIntent::Submit),
        );
        execute!(store, submitted, true).expect("created");
        for query in [
            "UPDATE account_operation_receipts SET admitted_key_revision=2",
            "DELETE FROM account_operation_receipts",
        ] {
            let mut tx = store.pool().begin().await.expect("forbidden receipt change");
            assert!(sqlx::query(query).execute(&mut *tx).await.is_err());
            tx.rollback().await.expect("restore receipt");
        }
        let disabled = request(
            &fixture,
            AccountRequestIntent::Submit,
            challenge!(store, fixture, AccountRequestIntent::Submit),
        );
        assert_eq!(
            execute!(store, disabled, false).expect_err("submit never becomes historical confirm"),
            AccountRegistrationError::PolicyDenied
        );
        let duplicate = request(
            &fixture,
            AccountRequestIntent::Submit,
            challenge!(store, fixture, AccountRequestIntent::Submit),
        );
        assert_eq!(
            execute!(store, duplicate, true).expect_err("normal submit checks uniqueness"),
            AccountRegistrationError::RegistrationDenied
        );
        sqlx::query("DELETE FROM identity_devices")
            .execute(store.pool())
            .await
            .expect("independent Device FK");
        sqlx::query("DELETE FROM identity_accounts")
            .execute(store.pool())
            .await
            .expect("Account deletion");
        let receipts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_operation_receipts")
            .fetch_one(store.pool())
            .await
            .expect("ordinary receipt lifetime");
        assert_eq!(receipts, 0);
        assert_eq!(store.account_id_retention_summary().await.expect("permanent digest").used, 1);
        let confirm = request(
            &fixture,
            AccountRequestIntent::Confirm,
            challenge!(store, fixture, AccountRequestIntent::Confirm),
        );
        assert_eq!(
            execute!(store, confirm, false).expect_err("absence never recreates"),
            AccountRegistrationError::AuthenticationRequired
        );
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=time_high_water_ms+2000")
            .execute(store.pool())
            .await
            .expect("elapsed denial cooldown");
        let retry = request(
            &fixture,
            AccountRequestIntent::Submit,
            challenge!(store, fixture, AccountRequestIntent::Submit),
        );
        assert_eq!(
            execute!(store, retry, true).expect_err("D129 prevents deleted Account id reuse"),
            AccountRegistrationError::RegistrationDenied
        );
        let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_accounts")
            .fetch_one(store.pool())
            .await
            .expect("no recreated Account");
        assert_eq!(accounts, 0);
        let mut fresh = self::fixture("registration-after-deletion", 3);
        fresh.payload.device_id = fixture.payload.device_id;
        let signing = fresh.device.public_key_sec1();
        let kem = DeviceKemKeyPair::from_private_bytes(&scalar(fresh.seed + 100))
            .expect("original Device KEM");
        set_device_keys(&mut fresh, signing, kem.public_key().to_vec());
        let submitted = request(
            &fresh,
            AccountRequestIntent::Submit,
            challenge!(store, fresh, AccountRequestIntent::Submit),
        );
        assert!(matches!(
            execute!(store, submitted, true)
                .expect("deleted Account leaves no permanent Device/key cache"),
            AccountRegistrationResult::Created(_)
        ));
        assert_eq!(
            store.account_id_retention_summary().await.expect("only Account ids persist").used,
            2
        );
    }};
}

macro_rules! legacy_freshness {
    ($store:expr,$seed:path) => {{
        let store = &$store;
        let root = Ed25519SigningKey::from_bytes(&[70; 32]).expect("legacy root");
        let old_signer = P256SigningKey::from_bytes(&scalar(70)).expect("legacy signer");
        let legacy = legacy_identity::LegacyIdentity::new(&root, &old_signer);
        $seed(store.pool(), &legacy, true).await;
        store.initialize_account_id_retention(CEILING).await.expect("legacy upgrade retention");
        store
            .replace_account_key_statements(legacy.account_id.into_bytes(), &[], &[])
            .await
            .expect("legacy statements may change");
        sqlx::query("UPDATE identity_devices SET active=FALSE")
            .execute(store.pool())
            .await
            .expect("inactive still reserves keys");
        let mut candidate = fixture("registration-freshness", 4);
        let signing = candidate.device.public_key_sec1();
        set_device_keys(&mut candidate, signing, old_signer.public_key_sec1());
        let reused = request(
            &candidate,
            AccountRequestIntent::Submit,
            challenge!(store, candidate, AccountRequestIntent::Submit),
        );
        assert_eq!(
            execute!(store, reused, true)
                .expect_err("legacy admission row reserves both roles deployment-wide"),
            AccountRegistrationError::RegistrationDenied
        );
        sqlx::query("DELETE FROM identity_devices")
            .execute(store.pool())
            .await
            .expect("remove admission fixture");
        store
            .replace_account_key_statements(
                legacy.account_id.into_bytes(),
                &[legacy.device_certificate.encode().expect("original strict K2 certificate")],
                &[],
            )
            .await
            .expect("cert-only legacy fixture");
        let normal = candidate.device.public_key_sec1();
        let fresh_kem = DeviceKemKeyPair::from_private_bytes(&scalar(candidate.seed + 100))
            .expect("candidate KEM");
        set_device_keys(
            &mut candidate,
            old_signer.public_key_sec1(),
            fresh_kem.public_key().to_vec(),
        );
        candidate.device =
            P256SigningKey::from_bytes(&scalar(70)).expect("original signing possession");
        let reused = request(
            &candidate,
            AccountRequestIntent::Submit,
            challenge!(store, candidate, AccountRequestIntent::Submit),
        );
        assert_eq!(
            execute!(store, reused, true).expect_err("cert-only canonical point cannot be reused"),
            AccountRegistrationError::RegistrationDenied
        );
        let revocation = RevocationStatement::issue(
            &root,
            legacy.device_certificate.device_id,
            1,
            "fixture".into(),
        )
        .expect("revocation")
        .encode()
        .expect("revocation bytes");
        store
            .replace_account_key_statements(legacy.account_id.into_bytes(), &[], &[revocation])
            .await
            .expect("revocation-only fixture");
        candidate.payload.device_id = legacy.device_certificate.device_id;
        candidate.device =
            P256SigningKey::from_bytes(&scalar(candidate.seed)).expect("fresh signer");
        set_device_keys(&mut candidate, normal, fresh_kem.public_key().to_vec());
        let reused = request(
            &candidate,
            AccountRequestIntent::Submit,
            challenge!(store, candidate, AccountRequestIntent::Submit),
        );
        assert_eq!(
            execute!(store, reused, true).expect_err("retained revocation reserves Device id"),
            AccountRegistrationError::RegistrationDenied
        );
        assert_eq!(
            store.account_id_retention_summary().await.expect("only legacy lifetime slot").used,
            1
        );
    }};
}

macro_rules! retained_freshness {
    ($store:expr) => {{
        let store = &$store;
        store.initialize_account_id_retention(CEILING).await.expect("guard");
        let original = fixture("registration-original", 5);
        let submitted = request(
            &original,
            AccountRequestIntent::Submit,
            challenge!(store, original, AccountRequestIntent::Submit),
        );
        execute!(store, submitted, true).expect("original receipt");
        sqlx::query("DELETE FROM identity_devices")
            .execute(store.pool())
            .await
            .expect("later admission lifecycle");
        sqlx::query("DELETE FROM sync_account_key_certificates")
            .execute(store.pool())
            .await
            .expect("later statement lifecycle");
        let mut candidate = fixture("registration-reused", 6);
        let signing = candidate.device.public_key_sec1();
        set_device_keys(&mut candidate, signing, original.device.public_key_sec1());
        let reused = request(
            &candidate,
            AccountRequestIntent::Submit,
            challenge!(store, candidate, AccountRequestIntent::Submit),
        );
        assert_eq!(
            execute!(store, reused, true)
                .expect_err("historical receipt reserves cross-role key across Accounts"),
            AccountRegistrationError::RegistrationDenied
        );
        let kem =
            DeviceKemKeyPair::from_private_bytes(&scalar(candidate.seed + 100)).expect("new KEM");
        candidate.payload.device_id = original.payload.device_id;
        let signing = candidate.device.public_key_sec1();
        set_device_keys(&mut candidate, signing, kem.public_key().to_vec());
        let reused = request(
            &candidate,
            AccountRequestIntent::Submit,
            challenge!(store, candidate, AccountRequestIntent::Submit),
        );
        assert_eq!(
            execute!(store, reused, true).expect_err("historical receipt reserves Device id"),
            AccountRegistrationError::RegistrationDenied
        );
        assert_eq!(
            store.account_id_retention_summary().await.expect("no partial reservation").used,
            1
        );
    }};
}

macro_rules! receipt_capacity {
    ($store:expr,$pg:literal)=>{{
        let store=&$store;
        store.initialize_account_id_retention(CEILING).await.expect("guard");
        let fixture=fixture("registration-receipts",7);
        let submitted=request(&fixture,AccountRequestIntent::Submit,challenge!(store,fixture,AccountRequestIntent::Submit));
        execute!(store,submitted,true).expect("original receipt");
        if $pg {
            let mut tx=store.pool().begin().await.expect("shadow schema fixture");
            sqlx::query("CREATE TEMP TABLE identity_accounts (account_id BYTEA)").execute(&mut *tx).await.expect("empty shadow");
            assert!(sqlx::query("TRUNCATE account_operation_receipts").execute(&mut *tx).await.is_err());
            tx.rollback().await.expect("shadow removed");
        }else{
            let mut tx=store.pool().begin().await.expect("replacement attack");
            assert!(sqlx::query("INSERT OR REPLACE INTO account_operation_receipts SELECT * FROM account_operation_receipts").execute(&mut *tx).await.is_err());
            tx.rollback().await.expect("original retained");
        }
        let trigger_sql=if $pg {
            "CREATE TRIGGER account_operation_receipts_guard BEFORE INSERT OR UPDATE OR DELETE ON account_operation_receipts FOR EACH ROW EXECUTE FUNCTION guard_account_operation_receipt()".to_string()
        }else{
            sqlx::query_scalar::<_,String>("SELECT sql FROM sqlite_schema WHERE name='account_operation_receipts_insert'").fetch_one(store.pool()).await.expect("exact production guard")
        };
        let mut tx=store.pool().begin().await.expect("owned full-capacity fixture");
        sqlx::query(if $pg {"DROP TRIGGER account_operation_receipts_guard ON account_operation_receipts"}else{"DROP TRIGGER account_operation_receipts_insert"}).execute(&mut *tx).await.expect("bulk seed without quadratic counting");
        let query=if $pg {
            "INSERT INTO account_operation_receipts SELECT decode('00000000000070008000','hex')||convert_to(lpad(n::text,6,'0'),'UTF8'),account_id,personal_vault_id,decode('00000000000170008000','hex')||convert_to(lpad(n::text,6,'0'),'UTF8'),request_digest,2,device_signing_public_key,device_kem_public_key,account_signing_public_key,admitted_key_revision,committed_at_ms FROM account_operation_receipts CROSS JOIN generate_series(1,65535) n"
        }else{
            "WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM numbers WHERE n<65535) INSERT INTO account_operation_receipts SELECT CAST(x'00000000000070008000'||printf('%06d',n) AS BLOB),account_id,personal_vault_id,CAST(x'00000000000170008000'||printf('%06d',n) AS BLOB),request_digest,2,device_signing_public_key,device_kem_public_key,account_signing_public_key,admitted_key_revision,committed_at_ms FROM account_operation_receipts CROSS JOIN numbers"
        };
        assert_eq!(sqlx::query(query).execute(&mut *tx).await.expect("exact lifetime bound").rows_affected(),65535);
        sqlx::query(&trigger_sql).execute(&mut *tx).await.expect("production guard restored");
        tx.commit().await.expect("owned capacity fixture");
        let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_operation_receipts").fetch_one(store.pool()).await.expect("retained rows");assert_eq!(count,65536);
        let mut tx=store.pool().begin().await.expect("one row beyond bound");
        let inserted=sqlx::query("INSERT INTO account_operation_receipts SELECT $1,account_id,personal_vault_id,$2,request_digest,kind,device_signing_public_key,device_kem_public_key,account_signing_public_key,admitted_key_revision,committed_at_ms FROM account_operation_receipts LIMIT 1")
            .bind(Uuid::now_v7().as_bytes().as_slice()).bind(Uuid::now_v7().as_bytes().as_slice()).execute(&mut *tx).await;
        assert!(inserted.is_err());tx.rollback().await.expect("capacity denial rollback");
        let confirm=request(&fixture,AccountRequestIntent::Confirm,challenge!(store,fixture,AccountRequestIntent::Confirm));
        assert!(matches!(execute!(store,confirm,false).expect("confirmation remains available at receipt capacity"),AccountRegistrationResult::Confirmed(_)));
    }};
}

macro_rules! final_expiry {
    ($store:expr,$pg:literal)=>{{
        let store=&$store;
        store.initialize_account_id_retention(CEILING).await.expect("guard");
        let fixture=fixture("registration-expiry",8);
        let submitted=request(&fixture,AccountRequestIntent::Submit,challenge!(store,fixture,AccountRequestIntent::Submit));
        let trigger=if $pg {
            "CREATE FUNCTION advance_registration_clock() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN UPDATE account_entry_state SET time_high_water_ms=time_high_water_ms+120001; RETURN NEW; END'; CREATE TRIGGER advance_registration_clock BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION advance_registration_clock()"
        }else{
            "CREATE TRIGGER advance_registration_clock BEFORE INSERT ON deployment_audit_events BEGIN UPDATE account_entry_state SET time_high_water_ms=time_high_water_ms+120001; END"
        };
        sqlx::raw_sql(trigger).execute(store.pool()).await.expect("owned expiry-at-final-audit fault");
        assert_eq!(execute!(store,submitted,true).expect_err("final expiry must roll back business"),AccountRegistrationError::AuthenticationRequired);
        let accounts:i64=sqlx::query_scalar("SELECT COUNT(*) FROM identity_accounts").fetch_one(store.pool()).await.expect("no aggregate");assert_eq!(accounts,0);
        let receipts:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_operation_receipts").fetch_one(store.pool()).await.expect("no receipt");assert_eq!(receipts,0);
        assert_eq!(store.account_id_retention_summary().await.expect("no permanent slot").used,0);
    }};
}

macro_rules! audit_failure {
    ($store:expr,$pg:literal)=>{{
        let store=&$store;
        store.initialize_account_id_retention(CEILING).await.expect("guard");
        let fixture=fixture("registration-audit",9);
        let submitted=request(&fixture,AccountRequestIntent::Submit,challenge!(store,fixture,AccountRequestIntent::Submit));
        let mut fault=store.pool().acquire().await.expect("owned fault connection");
        sqlx::raw_sql(if $pg {"CREATE FUNCTION deny_registration_audit() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''audit unavailable''; END'; CREATE TRIGGER deny_registration_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION deny_registration_audit()"}else{"CREATE TRIGGER deny_registration_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END"}).execute(&mut *fault).await.expect("mandatory audit fault");
        assert_eq!(execute!(store,submitted,true).expect_err("no success without audit"),AccountRegistrationError::StorageUnavailable);
        let accounts:i64=sqlx::query_scalar("SELECT COUNT(*) FROM identity_accounts").fetch_one(store.pool()).await.expect("aggregate rollback");assert_eq!(accounts,0);
        let claims:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_request_challenges").fetch_one(store.pool()).await.expect("claim rollback");assert_eq!(claims,1);
        assert_eq!(store.account_id_retention_summary().await.expect("retention rollback").used,0);
        sqlx::raw_sql(if $pg {"DROP TRIGGER deny_registration_audit ON deployment_audit_events; DROP FUNCTION deny_registration_audit()"}else{"DROP TRIGGER deny_registration_audit"}).execute(&mut *fault).await.expect("remove own fault");drop(fault);
        let mut bad=request(&fixture,AccountRequestIntent::Submit,challenge!(store,fixture,AccountRequestIntent::Submit));bad.nonce=SecretBytes::new([0;32]);
        assert_eq!(execute!(store,bad,true).expect_err("wrong nonce denies"),AccountRegistrationError::AuthenticationRequired);
    }};
}

async fn sqlite_store() -> (SqliteStore, std::path::PathBuf) {
    let directory = std::env::temp_dir().join(format!("scoplen-registration-{}", Uuid::now_v7()));
    let store =
        SqliteStore::open(&directory.join("store.sqlite")).await.expect("owned SQLite store");
    (store, directory)
}

macro_rules! authentication_bindings {
    ($store:expr) => {{
        let store = &$store;
        store.initialize_account_id_retention(CEILING).await.expect("guard");
        let mut fixture = fixture("registration-bindings", 17);
        for case in 0..3 {
            let origin = fixture.payload.origin.clone();
            let operation = fixture.payload.operation_id;
            let challenge = challenge!(store, fixture, AccountRequestIntent::Submit);
            match case {
                1 => fixture.payload.origin = "https://different.test".into(),
                2 => fixture.payload.operation_id = Uuid::now_v7(),
                _ => (),
            }
            let mut submitted = request(&fixture, AccountRequestIntent::Submit, challenge);
            if case == 0 {
                submitted.account_signature[0] ^= 1;
            }
            assert_eq!(
                execute!(store, submitted, true)
                    .expect_err("all canonical binding/Account signature mismatches deny"),
                AccountRegistrationError::AuthenticationRequired
            );
            let remaining: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM account_request_challenges")
                    .fetch_one(store.pool())
                    .await
                    .expect("live attempt consumed even with mismatched canonical binding");
            assert_eq!(remaining, 0);
            fixture.payload.origin = origin;
            fixture.payload.operation_id = operation;
            sqlx::query(
                "UPDATE account_entry_state SET time_high_water_ms=time_high_water_ms+60000",
            )
            .execute(store.pool())
            .await
            .expect("advance owned quota clock");
        }
        assert_eq!(
            store.account_id_retention_summary().await.expect("no aggregate admission").used,
            0
        );
    }};
}

macro_rules! confirmation_rate {
    ($store:expr) => {{
        let store = &$store;
        store.initialize_account_id_retention(CEILING).await.expect("guard");
        let fixture = fixture("registration-private-rate", 18);
        let submitted = request(
            &fixture,
            AccountRequestIntent::Submit,
            challenge!(store, fixture, AccountRequestIntent::Submit),
        );
        execute!(store, submitted, true).expect("initial creation");
        let confirm = request(
            &fixture,
            AccountRequestIntent::Confirm,
            challenge!(store, fixture, AccountRequestIntent::Confirm),
        );
        execute!(store, confirm, false).expect("establish authenticated Account debt");
        sqlx::query("UPDATE account_entry_admission SET attempts=10 WHERE endpoint=2 AND kind=4")
            .execute(store.pool())
            .await
            .expect("owned established Account quota exhaustion");
        let confirm = request(
            &fixture,
            AccountRequestIntent::Confirm,
            challenge!(store, fixture, AccountRequestIntent::Confirm),
        );
        assert!(matches!(
            execute!(store, confirm, false),
            Err(AccountRegistrationError::RateLimited(_))
        ));
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_request_challenges")
            .fetch_one(store.pool())
            .await
            .expect("private rate denial rolls back provisional claim");
        assert_eq!(remaining, 1);
        let receipts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_operation_receipts")
            .fetch_one(store.pool())
            .await
            .expect("original receipt preserved");
        assert_eq!(receipts, 1);
    }};
}

macro_rules! sqlite_case {
    ($name:ident,$case:ident $($arguments:tt)*)=>{
        #[tokio::test]
        async fn $name() {let (store,directory)=sqlite_store().await;$case!(store $($arguments)*);pool_close::close(store.pool()).await;support::remove_test_directory(directory).await;}
    };
}

macro_rules! namespace_conflict {
    ($store:expr) => {{
        let store = &$store;
        store.initialize_account_id_retention(CEILING).await.expect("guard");
        let original = fixture("registration-unique-name", 19);
        let initial = request(
            &original,
            AccountRequestIntent::Submit,
            challenge!(store, original, AccountRequestIntent::Submit),
        );
        execute!(store, initial, true).expect("initial Account");
        let head = store.deployment_audit_head().await.expect("audit").expect("head").sequence;
        let collision = fixture("registration-unique-name", 20);
        let denied = request(
            &collision,
            AccountRequestIntent::Submit,
            challenge!(store, collision, AccountRequestIntent::Submit),
        );
        assert_eq!(
            execute!(store, denied, true).expect_err("database username uniqueness"),
            AccountRegistrationError::RegistrationDenied
        );
        assert_eq!(
            store.deployment_audit_head().await.expect("audit").expect("denial head").sequence,
            head + 1,
            "savepoint preserves claimed denial audit after PostgreSQL unique violation"
        );
        assert_eq!(
            store.account_id_retention_summary().await.expect("rolled-back D129 reservation").used,
            1
        );
        let claims: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_request_challenges")
            .fetch_one(store.pool())
            .await
            .expect("denied challenge consumed atomically");
        assert_eq!(claims, 0);
        let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_accounts")
            .fetch_one(store.pool())
            .await
            .expect("no second aggregate");
        assert_eq!(accounts, 1);
    }};
}

macro_rules! damaged_freshness {
    ($store:expr,$seed:path,$pg:literal) => {{
        let store = &$store;
        let root = Ed25519SigningKey::from_bytes(&[71; 32]).expect("legacy root");
        let signer = P256SigningKey::from_bytes(&scalar(71)).expect("legacy signer");
        let identity = legacy_identity::LegacyIdentity::new(&root, &signer);
        $seed(store.pool(), &identity, true).await;
        store.initialize_account_id_retention(CEILING).await.expect("upgrade guard");
        let candidate = fixture("registration-bounded-scan", 21);
        let damage = if $pg {
            "UPDATE identity_devices SET certificate=decode('00','hex')"
        } else {
            "UPDATE identity_devices SET certificate='invalid text type'"
        };
        sqlx::query(damage).execute(store.pool()).await.expect("owned invalid certificate fixture");
        let attempt = request(
            &candidate,
            AccountRequestIntent::Submit,
            challenge!(store, candidate, AccountRequestIntent::Submit),
        );
        assert_eq!(
            execute!(store, attempt, true)
                .expect_err("damaged unrelated retained state fails closed"),
            AccountRegistrationError::StorageUnavailable
        );
        if !$pg {
            let mut fault = store.pool().acquire().await.expect("owned size corruption connection");
            sqlx::query("PRAGMA ignore_check_constraints=ON")
                .execute(&mut *fault)
                .await
                .expect("allow owned corruption");
            sqlx::query("UPDATE identity_devices SET certificate=zeroblob(65537)")
                .execute(&mut *fault)
                .await
                .expect("oversized corruption");
            sqlx::query("PRAGMA ignore_check_constraints=OFF")
                .execute(&mut *fault)
                .await
                .expect("restore checks");
            drop(fault);
            let attempt = request(
                &candidate,
                AccountRequestIntent::Submit,
                challenge!(store, candidate, AccountRequestIntent::Submit),
            );
            assert_eq!(
                execute!(store, attempt, true)
                    .expect_err("oversized artifact rejected by SQL projection"),
                AccountRegistrationError::StorageUnavailable
            );
        }
        assert_eq!(
            store.account_id_retention_summary().await.expect("no partial new slot").used,
            1
        );
    }};
}
sqlite_case!(sqlite_registration_complete_public_submit_and_historical_confirmation, happy);
sqlite_case!(sqlite_registration_proof_denials_and_structural_consumption, proof_denials);
sqlite_case!(sqlite_registration_receipt_deletion_and_permanent_id_boundary, deletion);
sqlite_case!(
    sqlite_registration_legacy_global_canonical_key_freshness,
    legacy_freshness,
    legacy_identity::seed_sqlite
);
sqlite_case!(
    sqlite_registration_retained_receipts_prevent_cross_account_key_reuse,
    retained_freshness
);
sqlite_case!(sqlite_registration_receipt_guards_and_lifetime_capacity, receipt_capacity, false);
sqlite_case!(sqlite_registration_rechecks_expiry_after_mandatory_audit, final_expiry, false);
sqlite_case!(sqlite_registration_audit_failure_rolls_back_business_and_claim, audit_failure, false);
sqlite_case!(sqlite_registration_username_conflict_commits_only_denial, namespace_conflict);
sqlite_case!(
    sqlite_registration_global_scan_rejects_corrupt_and_oversized_state,
    damaged_freshness,
    legacy_identity::seed_sqlite,
    false
);
sqlite_case!(
    sqlite_registration_authentication_bindings_consume_live_attempts,
    authentication_bindings
);
sqlite_case!(sqlite_registration_private_confirmation_rate_rolls_back_claim, confirmation_rate);

#[cfg(feature = "postgres-integration")]
async fn postgres_store() -> (PostgresStore, sqlx::PgPool, String, String) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL fixture URL");
    let admin = sqlx::PgPool::connect(&database).await.expect("fixture pool");
    let schema = format!("account_registration_{}", Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("fixture URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let url = url.to_string();
    let store = PostgresStore::connect(&url).await.expect("PostgreSQL store");
    (store, admin, schema, url)
}

#[cfg(feature = "postgres-integration")]
async fn cleanup_postgres(store: PostgresStore, admin: sqlx::PgPool, schema: String) {
    store.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .expect("remove owned schema");
    admin.close().await;
}

#[cfg(feature = "postgres-integration")]
macro_rules! postgres_case {
    ($name:ident,$case:ident $($arguments:tt)*)=>{
        #[tokio::test]
        async fn $name() {let (store,admin,schema,_url)=postgres_store().await;$case!(store $($arguments)*);cleanup_postgres(store,admin,schema).await;}
    };
}
#[cfg(feature = "postgres-integration")]
postgres_case!(postgres_registration_complete_public_submit_and_historical_confirmation, happy);
#[cfg(feature = "postgres-integration")]
postgres_case!(postgres_registration_proof_denials_and_structural_consumption, proof_denials);
#[cfg(feature = "postgres-integration")]
postgres_case!(postgres_registration_receipt_deletion_and_permanent_id_boundary, deletion);
#[cfg(feature = "postgres-integration")]
postgres_case!(
    postgres_registration_legacy_global_canonical_key_freshness,
    legacy_freshness,
    legacy_identity::seed_postgres
);
#[cfg(feature = "postgres-integration")]
postgres_case!(
    postgres_registration_retained_receipts_prevent_cross_account_key_reuse,
    retained_freshness
);
#[cfg(feature = "postgres-integration")]
postgres_case!(postgres_registration_receipt_guards_and_lifetime_capacity, receipt_capacity, true);
#[cfg(feature = "postgres-integration")]
postgres_case!(postgres_registration_rechecks_expiry_after_mandatory_audit, final_expiry, true);
#[cfg(feature = "postgres-integration")]
postgres_case!(
    postgres_registration_audit_failure_rolls_back_business_and_claim,
    audit_failure,
    true
);
#[cfg(feature = "postgres-integration")]
postgres_case!(postgres_registration_username_conflict_commits_only_denial, namespace_conflict);
#[cfg(feature = "postgres-integration")]
postgres_case!(
    postgres_registration_global_scan_rejects_corrupt_state,
    damaged_freshness,
    legacy_identity::seed_postgres,
    true
);

#[cfg(feature = "postgres-integration")]
postgres_case!(
    postgres_registration_authentication_bindings_consume_live_attempts,
    authentication_bindings
);
#[cfg(feature = "postgres-integration")]
postgres_case!(postgres_registration_private_confirmation_rate_rolls_back_claim, confirmation_rate);

#[tokio::test]
async fn sqlite_registration_attempted_commit_failure_is_conservatively_unknown() {
    let (store, directory) = sqlite_store().await;
    store.initialize_account_id_retention(CEILING).await.expect("guard");
    let previous = store.deployment_audit_head().await.expect("D129 initialization audit");
    let fixture = fixture("registration-unknown", 10);
    let submitted = request(
        &fixture,
        AccountRequestIntent::Submit,
        challenge!(store, fixture, AccountRequestIntent::Submit),
    );
    sqlx::raw_sql("CREATE TABLE registration_commit_parent (id INTEGER PRIMARY KEY); CREATE TABLE registration_commit_child (id INTEGER REFERENCES registration_commit_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER registration_commit_failure AFTER INSERT ON account_operation_receipts BEGIN INSERT INTO registration_commit_child VALUES(1); END")
        .execute(store.pool()).await.expect("deferred COMMIT fault");
    assert_eq!(
        execute!(store, submitted, true).expect_err("no acknowledged business outcome"),
        AccountRegistrationError::CommitOutcomeUnknown
    );
    assert_eq!(
        store.deployment_audit_head().await.expect("no supplemental failure audit"),
        previous
    );
    // The implementation must not reinterpret this result from a later ordinary read.
    let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_accounts")
        .fetch_one(store.pool())
        .await
        .expect("test-only observation");
    assert_eq!(accounts, 0);
    pool_close::close(store.pool()).await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_registration_reopens_exact_receipt_and_rejects_inexact_confirmation() {
    let (store, directory) = sqlite_store().await;
    let (mut fixture, bytes) = happy!(store);
    pool_close::close(store.pool()).await;
    drop(store);
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("new instance");
    let confirm = request(
        &fixture,
        AccountRequestIntent::Confirm,
        challenge!(store, fixture, AccountRequestIntent::Confirm),
    );
    let AccountRegistrationResult::Confirmed(current) =
        execute!(store, confirm, false).expect("durable historical receipt")
    else {
        panic!("explicit confirmation");
    };
    assert_same_response(&current, &bytes);
    fixture.payload.operation_id = Uuid::now_v7();
    let borrowed = request(
        &fixture,
        AccountRequestIntent::Confirm,
        challenge!(store, fixture, AccountRequestIntent::Confirm),
    );
    assert_eq!(
        execute!(store, borrowed, false).expect_err("no negative receipt fallback"),
        AccountRegistrationError::AuthenticationRequired
    );
    pool_close::close(store.pool()).await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_registration_lost_business_and_confirmation_ack_return_no_result() {
    use std::sync::atomic::Ordering;
    let (store, admin, schema, url) = postgres_store().await;
    store.initialize_account_id_retention(CEILING).await.expect("guard");
    let fixture = fixture("registration-unknown", 11);
    let submitted = request(
        &fixture,
        AccountRequestIntent::Submit,
        challenge!(store, fixture, AccountRequestIntent::Submit),
    );
    assert_eq!(
        store
            .admit_account_entry_source(AccountEntryEndpoint::Register, peer(2))
            .await
            .expect("source"),
        AccountEntryAdmissionDecision::Admitted
    );
    let proxy = lost_commit::LostCommitProxy::start_skipping(&url, 1).await;
    let uncertain = PostgresStore::connect(&proxy.database_url).await.expect("proxied store");
    let previous = store.deployment_audit_head().await.expect("initial audit head");
    proxy.armed.store(true, Ordering::SeqCst);
    assert_eq!(
        uncertain
            .execute_account_registration(
                peer(2),
                ORIGIN,
                true,
                CEILING,
                &submitted.to_json().expect("body"),
                deadline()
            )
            .await
            .expect_err("business ACK lost"),
        AccountRegistrationError::CommitOutcomeUnknown
    );
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    let committed = store.deployment_audit_head().await.expect("committed business audit");
    assert_eq!(
        committed.as_ref().expect("one business event").sequence,
        previous.map_or(0, |head| head.sequence) + 1,
        "lost business acknowledgement adds no supplemental audit"
    );
    let receipts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_operation_receipts")
        .fetch_one(store.pool())
        .await
        .expect("test-only committed receipt observation");
    assert_eq!(receipts, 1);
    uncertain.pool().close().await;
    drop(proxy);
    let confirm = request(
        &fixture,
        AccountRequestIntent::Confirm,
        challenge!(store, fixture, AccountRequestIntent::Confirm),
    );
    let proxy = lost_commit::LostCommitProxy::start_skipping(&url, 1).await;
    let uncertain = PostgresStore::connect(&proxy.database_url).await.expect("confirmation proxy");
    proxy.armed.store(true, Ordering::SeqCst);
    assert_eq!(
        uncertain
            .execute_account_registration(
                peer(2),
                ORIGIN,
                false,
                CEILING,
                &confirm.to_json().expect("body"),
                deadline()
            )
            .await
            .expect_err("confirmation ACK lost"),
        AccountRegistrationError::StorageUnavailable
    );
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.deployment_audit_head().await.expect("unchanged historical audit"),
        committed,
        "confirmation uncertainty adds no duplicate or supplemental audit"
    );
    uncertain.pool().close().await;
    drop(proxy);
    let confirm = request(
        &fixture,
        AccountRequestIntent::Confirm,
        challenge!(store, fixture, AccountRequestIntent::Confirm),
    );
    assert!(matches!(
        execute!(store, confirm, false).expect("explicit fresh confirmation can recover"),
        AccountRegistrationResult::Confirmed(_)
    ));
    // Losing only the earlier private admission COMMIT cannot make a business outcome unknown.
    let fresh = self::fixture("registration-private-unknown", 12);
    let submitted = request(
        &fresh,
        AccountRequestIntent::Submit,
        challenge!(store, fresh, AccountRequestIntent::Submit),
    );
    let proxy = lost_commit::LostCommitProxy::start(&url).await;
    let uncertain = PostgresStore::connect(&proxy.database_url).await.expect("admission proxy");
    proxy.armed.store(true, Ordering::SeqCst);
    assert_eq!(
        uncertain
            .execute_account_registration(
                peer(2),
                ORIGIN,
                true,
                CEILING,
                &submitted.to_json().expect("body"),
                deadline()
            )
            .await
            .expect_err("private admission ACK lost"),
        AccountRegistrationError::StorageUnavailable
    );
    uncertain.pool().close().await;
    drop(proxy);
    cleanup_postgres(store, admin, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_registration_serializes_global_freshness_across_instances_and_statement_writers()
{
    let (store, admin, schema, url) = postgres_store().await;
    let second = PostgresStore::connect(&url).await.expect("independent instance");
    store.initialize_account_id_retention(CEILING).await.expect("guard");
    let first = fixture("registration-first-race", 13);
    let mut other = fixture("registration-other-race", 14);
    let signing = other.device.public_key_sec1();
    set_device_keys(&mut other, signing, first.device.public_key_sec1());
    let left = request(
        &first,
        AccountRequestIntent::Submit,
        challenge!(store, first, AccountRequestIntent::Submit),
    );
    let right = request(
        &other,
        AccountRequestIntent::Submit,
        challenge!(store, other, AccountRequestIntent::Submit),
    );
    assert_eq!(
        store
            .admit_account_entry_source(AccountEntryEndpoint::Register, peer(2))
            .await
            .expect("source"),
        AccountEntryAdmissionDecision::Admitted
    );
    assert_eq!(
        store
            .admit_account_entry_source(AccountEntryEndpoint::Register, peer(2))
            .await
            .expect("second source admission"),
        AccountEntryAdmissionDecision::Admitted
    );
    let left_body = left.to_json().expect("left body");
    let right_body = right.to_json().expect("right body");
    let (a, b) = tokio::join!(
        store.execute_account_registration(peer(2), ORIGIN, true, CEILING, &left_body, deadline()),
        second.execute_account_registration(
            peer(2),
            ORIGIN,
            true,
            CEILING,
            &right_body,
            deadline()
        )
    );
    assert_eq!(u8::from(a.is_ok()) + u8::from(b.is_ok()), 1);
    assert!(matches!(
        (&a, &b),
        (Ok(_), Err(AccountRegistrationError::RegistrationDenied))
            | (Err(AccountRegistrationError::RegistrationDenied), Ok(_))
    ));
    let mut guard = store.pool().begin().await.expect("global singleton guard");
    sqlx::query("SELECT singleton FROM account_entry_state WHERE singleton=1 FOR UPDATE")
        .execute(&mut *guard)
        .await
        .expect("held global guard");
    let mut writer =
        Box::pin(second.replace_account_key_statements(Uuid::now_v7().into_bytes(), &[], &[]));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut writer).await.is_err(),
        "public statement writer must wait before Account locks"
    );
    guard.rollback().await.expect("release guard");
    writer.await.expect("ordinary legacy empty statement replacement");
    second.pool().close().await;
    cleanup_postgres(store, admin, schema).await;
}

#[tokio::test]
async fn sqlite_registration_deadline_during_writer_wait_publishes_no_business() {
    let (store, directory) = sqlite_store().await;
    store.initialize_account_id_retention(CEILING).await.expect("guard");
    let fixture = fixture("registration-deadline", 15);
    let submitted = request(
        &fixture,
        AccountRequestIntent::Submit,
        challenge!(store, fixture, AccountRequestIntent::Submit),
    );
    store
        .admit_account_entry_source(AccountEntryEndpoint::Register, peer(2))
        .await
        .expect("source admitted before writer wait");
    let guard = store.pool().begin_with("BEGIN IMMEDIATE").await.expect("held writer");
    let body = submitted.to_json().expect("body");
    let limit = tokio::time::Instant::now() + std::time::Duration::from_millis(30);
    let (result, ()) = tokio::join!(
        store.execute_account_registration(peer(2), ORIGIN, true, CEILING, &body, limit),
        async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            guard.rollback().await.expect("release writer");
        }
    );
    assert_eq!(
        result.expect_err("precommit deadline"),
        AccountRegistrationError::StorageUnavailable
    );
    let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_accounts")
        .fetch_one(store.pool())
        .await
        .expect("no business");
    assert_eq!(accounts, 0);
    assert_eq!(store.account_id_retention_summary().await.expect("no digest").used, 0);
    pool_close::close(store.pool()).await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_registration_deadline_during_singleton_wait_and_final_audit_rolls_back() {
    let (store, admin, schema, _url) = postgres_store().await;
    store.initialize_account_id_retention(CEILING).await.expect("guard");
    let fixture = fixture("registration-deadline", 16);
    let submitted = request(
        &fixture,
        AccountRequestIntent::Submit,
        challenge!(store, fixture, AccountRequestIntent::Submit),
    );
    store
        .admit_account_entry_source(AccountEntryEndpoint::Register, peer(2))
        .await
        .expect("source");
    let mut guard = store.pool().begin().await.expect("singleton guard");
    sqlx::query("SELECT singleton FROM account_entry_state WHERE singleton=1 FOR UPDATE")
        .execute(&mut *guard)
        .await
        .expect("held singleton");
    let body = submitted.to_json().expect("body");
    let limit = tokio::time::Instant::now() + std::time::Duration::from_millis(30);
    let (result, ()) = tokio::join!(
        store.execute_account_registration(peer(2), ORIGIN, true, CEILING, &body, limit),
        async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            guard.rollback().await.expect("release singleton");
        }
    );
    assert_eq!(
        result.expect_err("lock wait deadline"),
        AccountRegistrationError::StorageUnavailable
    );
    sqlx::raw_sql("CREATE FUNCTION delay_registration_audit() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN PERFORM pg_sleep(0.1); RETURN NEW; END'; CREATE TRIGGER delay_registration_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION delay_registration_audit()")
        .execute(store.pool()).await.expect("owned slow final audit");
    let submitted = request(
        &fixture,
        AccountRequestIntent::Submit,
        challenge!(store, fixture, AccountRequestIntent::Submit),
    );
    let limit = tokio::time::Instant::now() + std::time::Duration::from_millis(80);
    assert_eq!(
        store
            .execute_account_registration(
                peer(2),
                ORIGIN,
                true,
                CEILING,
                &submitted.to_json().expect("body"),
                limit
            )
            .await
            .expect_err("final precommit deadline"),
        AccountRegistrationError::StorageUnavailable
    );
    let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_accounts")
        .fetch_one(store.pool())
        .await
        .expect("no business");
    assert_eq!(accounts, 0);
    assert_eq!(store.account_id_retention_summary().await.expect("no digest").used, 0);
    cleanup_postgres(store, admin, schema).await;
}
