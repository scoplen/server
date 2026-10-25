// SPDX-License-Identifier: AGPL-3.0-only

#[path = "support/legacy_identity.rs"]
mod legacy_identity;
#[cfg(feature = "postgres-integration")]
#[path = "support/lost_commit.rs"]
mod lost_commit;
#[path = "support/pool_close.rs"]
mod pool_close;
mod support;

use std::{net::IpAddr, time::Duration};

use scoplen_api::{
    account_admission::{
        AccountBootstrapSnapshot, AccountCommittedConfirmation, AccountDeviceAdmissionPayload,
        AccountDeviceAdmissionRequest, AccountPasswordLoginRequest, AccountPasswordLoginResponse,
        AccountPasswordOptionsRequest, AccountRegistrationPayload, AccountRequestChallengeRequest,
        AccountRequestChallengeResponse, AccountRequestIntent as Intent,
        AccountRequestKind as Kind,
    },
    sync::{SyncAccountDeviceWrap, SyncAccountKeyBundleUpdate},
};
use scoplen_crypto::{
    AccountRequestProof, AccountRequestSignatureInput, DeviceArkWrap, DeviceCertificate,
    DeviceKemKeyPair, Ed25519SigningKey, P256SigningKey, PasswordArkWrap, PasswordBootstrapContext,
    PasswordSecrets, RevocationStatement, SecretBytes, SecretVec, account_bootstrap_digest,
    account_capability_digest,
};
use scoplen_store::{
    RelationalStore, SqliteStore,
    account_device_admission::{
        AccountDeviceAdmissionError as Error, AccountDeviceAdmissionResult as Outcome,
    },
    account_entry_admission::{
        AccountEntryAdmissionDecision as Decision, AccountEntryEndpoint as Endpoint,
    },
    kms::KeyManagementService,
};
use uuid::Uuid;

const ORIGIN: &str = "https://admission.example.test";
const FUTURE: i64 = 4_000_000_020_000;
struct Kms;
impl KeyManagementService for Kms {
    fn key_encryption_key(&self) -> &[u8; 32] {
        &[7; 32]
    }
    fn backend_name(&self) -> &'static str {
        "test"
    }
}
fn source() -> IpAddr {
    IpAddr::from([192, 0, 2, 50])
}
fn deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(30)
}
fn scalar(seed: u8) -> [u8; 32] {
    let mut scalar = [0; 32];
    scalar[31] = seed;
    scalar
}

struct Account {
    payload: AccountRegistrationPayload,
    root: Ed25519SigningKey,
    secrets: PasswordSecrets,
}
fn account() -> Account {
    account_named("admission-user", 1)
}
fn account_named(username: &str, seed: u8) -> Account {
    let root = Ed25519SigningKey::from_bytes(&[seed; 32]).expect("Account root");
    let device = P256SigningKey::from_bytes(&scalar(seed)).expect("old Device signer");
    let identity = legacy_identity::LegacyIdentity::new(&root, &device);
    let secrets = PasswordSecrets::create(
        ORIGIN,
        username,
        SecretVec::new(b"real password bootstrap for Device admission".to_vec()),
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
    .expect("bootstrap context");
    Account {
        payload: AccountRegistrationPayload {
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
            key_bundle: identity.key_bundle_update.to_cbor().expect("accepted original PUT"),
            personal_wrapped_key: identity
                .wrapped_personal_vault_key
                .try_into()
                .expect("Personal wrap"),
        },
        root,
        secrets,
    }
}

struct Candidate {
    payload: AccountDeviceAdmissionPayload,
    signer: P256SigningKey,
    token: SecretBytes<32>,
}
fn candidate(account: &Account, login: &AccountPasswordLoginResponse, seed: u8) -> Candidate {
    let snapshot = AccountBootstrapSnapshot::from_cbor(login.snapshot.as_bytes())
        .expect("real verified login snapshot");
    let signer = P256SigningKey::from_bytes(&scalar(seed)).expect("fresh Device signer");
    let kem =
        DeviceKemKeyPair::from_private_bytes(&scalar(seed + 100)).expect("fresh distinct KEM");
    let device = Uuid::now_v7();
    let certificate = DeviceCertificate::issue(
        &account.root,
        device,
        snapshot.account_id,
        signer.public_key_sec1(),
        kem.public_key().to_vec(),
        "Independent Device".into(),
        "test".into(),
        1,
    )
    .expect("root-signed new certificate")
    .encode()
    .expect("strict K2");
    let mut bundle =
        SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle).expect("old complete PUT");
    bundle.revision += 1;
    bundle.device_wraps.push(SyncAccountDeviceWrap {
        device_id: device,
        wrapped_ark: DeviceArkWrap::seal(
            snapshot.account_id,
            device,
            kem.public_key(),
            &SecretBytes::new([11; 32]),
        )
        .expect("new Device wrap")
        .encode()
        .to_vec(),
    });
    bundle.device_wraps.sort_by_key(|wrap| wrap.device_id);
    bundle.signature =
        account.root.sign(&bundle.signature_input().expect("next PUT signature input")).to_vec();
    let payload = AccountDeviceAdmissionPayload {
        operation_id: Uuid::now_v7(),
        origin: ORIGIN.into(),
        username: snapshot.username,
        account_id: snapshot.account_id,
        personal_vault_id: snapshot.personal_vault_id,
        device_id: device,
        credential_generation: snapshot.credential_generation,
        snapshot_digest: account_bootstrap_digest(login.snapshot.as_bytes()),
        capability_digest: account_capability_digest(login.admission_token.as_bytes()),
        device_certificate: certificate,
        key_bundle: bundle.to_cbor().expect("canonical next PUT"),
    };
    Candidate { payload, signer, token: login.admission_token.clone() }
}
fn resign(
    candidate: &mut Candidate,
    account: &Account,
    change: impl FnOnce(&mut SyncAccountKeyBundleUpdate),
) {
    let mut update = SyncAccountKeyBundleUpdate::from_cbor(&candidate.payload.key_bundle)
        .expect("candidate PUT");
    change(&mut update);
    update.signature =
        account.root.sign(&update.signature_input().expect("modified PUT input")).to_vec();
    candidate.payload.key_bundle = update.to_cbor().expect("modified signed PUT");
}
fn request(
    candidate: &Candidate,
    account: &Account,
    intent: Intent,
    challenge: AccountRequestChallengeResponse,
) -> AccountDeviceAdmissionRequest {
    let payload = candidate.payload.to_cbor().expect("retained exact payload");
    let input = AccountRequestSignatureInput::new(Kind::Admit, &payload)
        .expect("additional Account signature context");
    let signature = input.sign(&account.root);
    let proof = AccountRequestProof::new(
        Kind::Admit,
        intent,
        ORIGIN,
        challenge.attempt_id.as_bytes(),
        challenge.nonce.as_bytes(),
        candidate.payload.operation_id,
        candidate.payload.device_id,
        &input.request_digest(&signature),
    )
    .expect("fresh Device proof context");
    AccountDeviceAdmissionRequest {
        intent,
        payload: SecretVec::new(payload),
        account_signature: signature,
        attempt_id: challenge.attempt_id,
        nonce: challenge.nonce,
        device_proof: proof.sign(&candidate.signer).expect("Device possession"),
        admission_token: if intent == Intent::Submit {
            Some(candidate.token.clone())
        } else {
            None
        },
    }
}

async fn sqlite_open() -> (SqliteStore, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("scoplen-device-admission-{}", Uuid::now_v7()));
    (SqliteStore::open(&path.join("store.sqlite")).await.expect("owned SQLite"), path)
}
async fn sqlite_cleanup(store: SqliteStore, path: std::path::PathBuf) {
    pool_close::close(store.pool()).await;
    drop(store);
    support::remove_test_directory(path).await;
}
async fn sqlite_reopen(path: &std::path::Path) -> SqliteStore {
    SqliteStore::open(&path.join("store.sqlite")).await.expect("independent SQLite instance")
}
#[cfg(feature = "postgres-integration")]
async fn postgres_open() -> (scoplen_store::PostgresStore, (sqlx::PgPool, String, String)) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL fixture URL");
    let admin = sqlx::PgPool::connect(&database).await.expect("admin fixture connection");
    let schema = format!("device_admission_{}", Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("fixture URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let url = url.to_string();
    (
        scoplen_store::PostgresStore::connect(&url).await.expect("owned PostgreSQL"),
        (admin, schema, url),
    )
}
#[cfg(feature = "postgres-integration")]
async fn postgres_cleanup(
    store: scoplen_store::PostgresStore,
    resources: (sqlx::PgPool, String, String),
) {
    let (admin, schema, _) = resources;
    store.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .expect("remove owned schema");
    admin.close().await;
}
#[cfg(feature = "postgres-integration")]
async fn postgres_reopen(
    resources: &(sqlx::PgPool, String, String),
) -> scoplen_store::PostgresStore {
    scoplen_store::PostgresStore::connect(&resources.2)
        .await
        .expect("independent PostgreSQL instance")
}

macro_rules! backend {
    ($module:ident,$store:ty,$db:ty,$open:ident,$cleanup:ident,$reopen:ident,$create:ident,$read:ident,$seed:path,$pg:literal)=>{
        mod $module {
            use super::*;
            use scoplen_store::account_bootstrap::{$create,$read};
            type Store=$store;
            async fn begin(store:&Store)->sqlx::Transaction<'_,$db> {
                if $pg {store.pool().begin().await.expect("transaction")}
                else {store.pool().begin_with("BEGIN IMMEDIATE").await.expect("writer transaction")}
            }
            pub(super) async fn establish(store:&Store)->Account {establish_at(store,FUTURE).await}
            pub(super) async fn establish_at(store:&Store,now:i64)->Account {
                store.initialize_account_id_retention(32).await.expect("D129 startup");
                store.ensure_account_probe_key(&Kms).await.expect("retained Kprobe");
                sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1").bind(now).execute(store.pool()).await.expect("controlled durable time");
                let account=account();let mut tx=begin(store).await;
                $create(&mut tx,ORIGIN,32,&account.payload,now).await.expect("complete signed initial Account");
                tx.commit().await.expect("fixture commit");account
            }
            pub(super) async fn source_admission(store:&Store,endpoint:Endpoint) {
                assert_eq!(store.admit_account_entry_source(endpoint,source()).await.expect("HTTP source debt"),Decision::Admitted);
            }
            pub(super) async fn login(store:&Store,account:&Account)->AccountPasswordLoginResponse {
                source_admission(store,Endpoint::PasswordOptions).await;
                let options=AccountPasswordOptionsRequest {username:account.payload.username.clone()}.to_json().expect("options");
                let issued=store.issue_account_password_options(source(),ORIGIN,&options,&Kms,deadline()).await.expect("real password options");
                source_admission(store,Endpoint::PasswordLogin).await;
                let body=AccountPasswordLoginRequest {attempt_id:issued.attempt_id,auth_secret:account.secrets.auth_secret().clone()}.to_json().expect("password proof");
                store.execute_account_password_login(source(),ORIGIN,body,&Kms,deadline()).await.expect("real issued admission capability")
            }
            pub(super) async fn challenge(store:&Store,candidate:&Candidate,intent:Intent)->AccountRequestChallengeResponse {
                source_admission(store,Endpoint::RequestChallenge).await;
                store.issue_account_request_challenge(source(),ORIGIN,&AccountRequestChallengeRequest {kind:Kind::Admit,intent,
                    operation_id:candidate.payload.operation_id,device_id:candidate.payload.device_id}).await.expect("fresh independent challenge")
            }
            pub(super) async fn execute(store:&Store,request:&AccountDeviceAdmissionRequest)->Result<Outcome,Error> {
                source_admission(store,Endpoint::DeviceAdmission).await;
                store.execute_account_device_admission(source(),ORIGIN,&request.to_json().expect("strict outer body"),deadline()).await
            }
            pub(super) async fn snapshot(store:&Store,account:&Account)->SecretVec {
                let mut tx=begin(store).await;
                let bytes=$read(&mut tx,ORIGIN,account.payload.account_id).await.expect("complete current bootstrap");
                tx.rollback().await.expect("snapshot read complete");bytes
            }
            pub(super) async fn count(store:&Store,table:&str)->i64 {
                sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}")).fetch_one(store.pool()).await.expect("fixture state count")
            }
            async fn quota(store:&Store)->i64 {
                sqlx::query_scalar("SELECT COUNT(*) FROM account_entry_admission WHERE endpoint=5 AND kind=4").fetch_one(store.pool()).await.expect("verified Account quota")
            }
            async fn advance(store:&Store,millis:i64) {
                sqlx::query("UPDATE account_entry_state SET time_high_water_ms=time_high_water_ms+$1").bind(millis).execute(store.pool()).await.expect("advance trusted time");
            }
            async fn audit_fault(store:&Store) {
                sqlx::raw_sql(if $pg {"CREATE FUNCTION deny_device_audit() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''audit unavailable''; END'; CREATE TRIGGER deny_device_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION deny_device_audit()"}
                    else {"CREATE TRIGGER deny_device_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END"})
                    .execute(store.pool()).await.expect("owned mandatory audit failure");
            }
            async fn remove_audit_fault(store:&Store) {
                sqlx::raw_sql(if $pg {"DROP TRIGGER deny_device_audit ON deployment_audit_events; DROP FUNCTION deny_device_audit()"}else{"DROP TRIGGER deny_device_audit"})
                    .execute(store.pool()).await.expect("remove owned audit fault");
            }
            async fn fill_receipts(store:&Store,account:&Account) {
                let certificate=DeviceCertificate::decode(&account.payload.device_certificate).expect("original certificate");
                sqlx::query("INSERT INTO account_operation_receipts (operation_id,account_id,personal_vault_id,device_id,request_digest,kind,device_signing_public_key,device_kem_public_key,account_signing_public_key,admitted_key_revision,committed_at_ms) VALUES ($1,$2,$3,$4,$5,1,$6,$7,$8,1,$9)")
                    .bind(account.payload.operation_id.as_bytes().as_slice()).bind(account.payload.account_id.as_bytes().as_slice())
                    .bind(account.payload.personal_vault_id.as_bytes().as_slice()).bind(account.payload.device_id.as_bytes().as_slice())
                    .bind([9_u8;32].as_slice()).bind(&certificate.signing_public_key).bind(&certificate.kem_public_key)
                    .bind(account.root.public_key().as_slice()).bind(FUTURE).execute(store.pool()).await.expect("owned receipt capacity seed");
                let trigger=if $pg {"CREATE TRIGGER account_operation_receipts_guard BEFORE INSERT OR UPDATE OR DELETE ON account_operation_receipts FOR EACH ROW EXECUTE FUNCTION guard_account_operation_receipt()".to_owned()}
                    else{sqlx::query_scalar::<_,String>("SELECT sql FROM sqlite_schema WHERE name='account_operation_receipts_insert'").fetch_one(store.pool()).await.expect("exact guard")};
                let mut tx=begin(store).await;
                sqlx::query(if $pg {"DROP TRIGGER account_operation_receipts_guard ON account_operation_receipts"}else{"DROP TRIGGER account_operation_receipts_insert"}).execute(&mut *tx).await.expect("owned bulk fixture without quadratic guard counts");
                let query=if $pg {"INSERT INTO account_operation_receipts SELECT decode('00000000000070008000','hex')||convert_to(lpad(n::text,6,'0'),'UTF8'),account_id,personal_vault_id,decode('00000000000170008000','hex')||convert_to(lpad(n::text,6,'0'),'UTF8'),request_digest,2,device_signing_public_key,device_kem_public_key,account_signing_public_key,admitted_key_revision,committed_at_ms FROM account_operation_receipts CROSS JOIN generate_series(1,65535) n"}
                    else{"WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM numbers WHERE n<65535) INSERT INTO account_operation_receipts SELECT CAST(x'00000000000070008000'||printf('%06d',n) AS BLOB),account_id,personal_vault_id,CAST(x'00000000000170008000'||printf('%06d',n) AS BLOB),request_digest,2,device_signing_public_key,device_kem_public_key,account_signing_public_key,admitted_key_revision,committed_at_ms FROM account_operation_receipts CROSS JOIN numbers"};
                assert_eq!(sqlx::query(query).execute(&mut *tx).await.expect("exact receipt capacity").rows_affected(),65_535);
                sqlx::query(&trigger).execute(&mut *tx).await.expect("production guard restored");tx.commit().await.expect("capacity fixture committed");
            }

            #[tokio::test]
            async fn receipt_capacity_preserves_capability_consumes_challenge_and_audit_failure_overrides_413() {
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await;
                let candidate=candidate(&account,&issued,2);let before=snapshot(&store,&account).await;fill_receipts(&store,&account).await;
                let submit=request(&candidate,&account,Intent::Submit,challenge(&store,&candidate,Intent::Submit).await);
                audit_fault(&store).await;
                assert_eq!(execute(&store,&submit).await.expect_err("audit failure overrides checked capacity denial"),Error::StorageUnavailable);
                assert_eq!(count(&store,"account_admission_capabilities").await,1);assert_eq!(count(&store,"account_request_challenges").await,1);assert_eq!(quota(&store).await,0);
                remove_audit_fault(&store).await;
                let head=store.deployment_audit_head().await.expect("before quota").expect("head").sequence;
                assert_eq!(execute(&store,&submit).await.expect_err("confirmed unchanged quota denial"),Error::QuotaExceeded);
                assert_eq!(snapshot(&store,&account).await,before);assert_eq!(count(&store,"identity_devices").await,1);assert_eq!(count(&store,"account_operation_receipts").await,65_536);
                assert_eq!(count(&store,"account_admission_capabilities").await,1);assert_eq!(count(&store,"account_request_challenges").await,0);assert_eq!(quota(&store).await,1);
                let attempts:i64=sqlx::query_scalar("SELECT attempts FROM account_entry_admission WHERE endpoint=5 AND kind=4").fetch_one(store.pool()).await.expect("authenticated debt kept");assert_eq!(attempts,1);
                assert_eq!(store.deployment_audit_head().await.expect("mandatory quota denial audit").expect("head").sequence,head+1);
                assert_eq!(execute(&store,&submit).await.expect_err("consumed challenge cannot be replayed"),Error::AuthenticationRequired);
                assert_eq!(count(&store,"account_admission_capabilities").await,1);
                $cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn competing_instances_admit_exactly_one_next_revision_and_spend_both_capabilities() {
                let (store,resources)=$open().await;let account=establish(&store).await;
                let left_login=login(&store,&account).await;let right_login=login(&store,&account).await;
                let left=candidate(&account,&left_login,2);let right=candidate(&account,&right_login,3);
                let a=request(&left,&account,Intent::Submit,challenge(&store,&left,Intent::Submit).await);
                let b=request(&right,&account,Intent::Submit,challenge(&store,&right,Intent::Submit).await);
                let second=$reopen(&resources).await;source_admission(&store,Endpoint::DeviceAdmission).await;source_admission(&store,Endpoint::DeviceAdmission).await;
                let a=a.to_json().expect("first body");let b=b.to_json().expect("competing body");
                let (a,b)=tokio::join!(store.execute_account_device_admission(source(),ORIGIN,&a,deadline()),second.execute_account_device_admission(source(),ORIGIN,&b,deadline()));
                assert!(matches!((&a,&b),(Ok(Outcome::Admitted(_)),Err(Error::AdmissionConflict))|(Err(Error::AdmissionConflict),Ok(Outcome::Admitted(_)))));
                assert_eq!(count(&store,"identity_devices").await,2);assert_eq!(count(&store,"account_operation_receipts").await,1);assert_eq!(count(&store,"account_admission_capabilities").await,0);
                pool_close::close(second.pool()).await;drop(second);$cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn independent_account_race_preserves_deployment_wide_cross_role_point_freshness() {
                let (store,resources)=$open().await;let first=establish(&store).await;let other=account_named("second-account",4);
                let mut tx=begin(&store).await;$create(&mut tx,ORIGIN,32,&other.payload,FUTURE).await.expect("independent Account");tx.commit().await.expect("fixture commit");
                let left_login=login(&store,&first).await;let right_login=login(&store,&other).await;
                let left=candidate(&first,&left_login,2);let mut right=candidate(&other,&right_login,3);
                let cross_role=left.signer.public_key_sec1();
                right.payload.device_certificate=DeviceCertificate::issue(&other.root,right.payload.device_id,other.payload.account_id,
                    right.signer.public_key_sec1(),cross_role.clone(),"Cross-role candidate".into(),"test".into(),1).expect("valid independently signed certificate").encode().expect("certificate");
                let wrap=DeviceArkWrap::seal(other.payload.account_id,right.payload.device_id,&cross_role,&SecretBytes::new([11;32])).expect("new bound wrap").encode().to_vec();
                let right_id=right.payload.device_id;
                resign(&mut right,&other,|update|update.device_wraps.iter_mut().find(|wrap|wrap.device_id==right_id).expect("new recipient").wrapped_ark=wrap);
                let a=request(&left,&first,Intent::Submit,challenge(&store,&left,Intent::Submit).await);
                let b=request(&right,&other,Intent::Submit,challenge(&store,&right,Intent::Submit).await);
                let second=$reopen(&resources).await;source_admission(&store,Endpoint::DeviceAdmission).await;source_admission(&store,Endpoint::DeviceAdmission).await;
                let a=a.to_json().expect("first body");let b=b.to_json().expect("second body");
                let (a,b)=tokio::join!(store.execute_account_device_admission(source(),ORIGIN,&a,deadline()),second.execute_account_device_admission(source(),ORIGIN,&b,deadline()));
                assert!(matches!((&a,&b),(Ok(Outcome::Admitted(_)),Err(Error::AdmissionConflict))|(Err(Error::AdmissionConflict),Ok(Outcome::Admitted(_)))));
                assert_eq!(count(&store,"identity_devices").await,3);assert_eq!(count(&store,"account_operation_receipts").await,1);assert_eq!(count(&store,"account_admission_capabilities").await,0);
                pool_close::close(second.pool()).await;drop(second);$cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn retained_legacy_device_material_blocks_independent_admission() {
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await;
                let candidate=candidate(&account,&issued,2);let before=snapshot(&store,&account).await;
                let root=Ed25519SigningKey::from_bytes(&[77;32]).expect("legacy Account root");
                let legacy=legacy_identity::LegacyIdentity::new(&root,&candidate.signer);
                $seed(store.pool(),&legacy,true).await;
                let submit=request(&candidate,&account,Intent::Submit,challenge(&store,&candidate,Intent::Submit).await);
                assert_eq!(execute(&store,&submit).await.expect_err("deployment-wide retained legacy signing point"),Error::AdmissionConflict);
                assert_eq!(snapshot(&store,&account).await,before);assert_eq!(count(&store,"identity_devices").await,2);assert_eq!(count(&store,"account_admission_capabilities").await,0);
                $cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn malformed_nested_body_and_wrong_intent_token_never_claim_challenge() {
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await;
                let candidate=candidate(&account,&issued,2);
                let submit=request(&candidate,&account,Intent::Submit,challenge(&store,&candidate,Intent::Submit).await);
                let original:serde_json::Value=serde_json::from_slice(&submit.to_json().expect("body")).expect("JSON");
                for case in 0..3 {
                    let mut body=original.clone();
                    match case {0=>body["payload"]=serde_json::Value::String("AA".into()),1=>body["intent"]=serde_json::Value::String("confirm".into()),_=>body["extra"]=serde_json::Value::Bool(true)}
                    source_admission(&store,Endpoint::DeviceAdmission).await;
                    assert_eq!(store.execute_account_device_admission(source(),ORIGIN,&serde_json::to_vec(&body).expect("invalid body"),deadline()).await.expect_err("structural rejection"),Error::InvalidRequest);
                    assert_eq!(count(&store,"account_request_challenges").await,1);assert_eq!(count(&store,"account_admission_capabilities").await,1);
                }
                source_admission(&store,Endpoint::DeviceAdmission).await;
                assert_eq!(store.execute_account_device_admission(source(),ORIGIN,&vec![b' ';6_291_457],deadline()).await.expect_err("raw body bound"),Error::RequestTooLarge);
                assert_eq!(quota(&store).await,0);
                let private:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_entry_admission WHERE endpoint=5 AND kind=3").fetch_one(store.pool()).await.expect("no decoded Device admission before full structural validation");assert_eq!(private,0);
                $cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn wrong_nonce_consumes_matching_challenge_without_claiming_capability() {
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await;
                let candidate=candidate(&account,&issued,2);
                let mut submit=request(&candidate,&account,Intent::Submit,challenge(&store,&candidate,Intent::Submit).await);submit.nonce=SecretBytes::new([0;32]);
                assert_eq!(execute(&store,&submit).await.expect_err("mismatched nonce"),Error::AuthenticationRequired);
                assert_eq!(count(&store,"account_request_challenges").await,0);assert_eq!(count(&store,"account_admission_capabilities").await,1);assert_eq!(quota(&store).await,0);
                $cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn reopened_exact_receipt_rejects_inexact_confirmation_and_submit_replay() {
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await;
                let mut candidate=candidate(&account,&issued,2);
                let submit=request(&candidate,&account,Intent::Submit,challenge(&store,&candidate,Intent::Submit).await);
                let Outcome::Admitted(original)=execute(&store,&submit).await.expect("admitted")else{panic!("new admission")};
                let second=$reopen(&resources).await;
                let confirm=request(&candidate,&account,Intent::Confirm,challenge(&second,&candidate,Intent::Confirm).await);
                let Outcome::Confirmed(reopened)=execute(&second,&confirm).await.expect("durable exact receipt")else{panic!("confirmation")};
                assert_eq!(SecretVec::new(original),SecretVec::new(reopened));
                let replay=request(&candidate,&account,Intent::Submit,challenge(&second,&candidate,Intent::Submit).await);
                assert_eq!(execute(&second,&replay).await.expect_err("submit never becomes receipt confirmation"),Error::AuthenticationRequired);
                advance(&second,2_000).await;
                candidate.payload.snapshot_digest[0]^=1;
                let substituted=request(&candidate,&account,Intent::Confirm,challenge(&second,&candidate,Intent::Confirm).await);
                assert_eq!(execute(&second,&substituted).await.expect_err("same ids and keys cannot substitute exact signed bytes"),Error::AuthenticationRequired);
                assert_eq!(count(&second,"identity_devices").await,2);assert_eq!(count(&second,"account_operation_receipts").await,1);
                pool_close::close(second.pool()).await;drop(second);$cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn expired_capability_preserves_business_and_denies_before_account_quota() {
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await;
                let candidate=candidate(&account,&issued,2);advance(&store,300_000).await;
                let submit=request(&candidate,&account,Intent::Submit,challenge(&store,&candidate,Intent::Submit).await);
                assert_eq!(execute(&store,&submit).await.expect_err("expired capability"),Error::AuthenticationRequired);
                assert_eq!(count(&store,"account_request_challenges").await,0);assert_eq!(count(&store,"identity_devices").await,1);assert_eq!(quota(&store).await,0);
                $cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn final_capability_expiry_after_audit_rolls_back_all_business() {
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await;
                let candidate=candidate(&account,&issued,2);advance(&store,240_000).await;
                let submit=request(&candidate,&account,Intent::Submit,challenge(&store,&candidate,Intent::Submit).await);
                sqlx::raw_sql(if $pg {"CREATE FUNCTION expire_device_capability() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN UPDATE account_entry_state SET time_high_water_ms=time_high_water_ms+60000; RETURN NEW; END'; CREATE TRIGGER expire_device_capability BEFORE INSERT ON deployment_audit_events FOR EACH ROW WHEN (substring(NEW.event_bytes FROM 1 FOR 30)=convert_to('spl-account-request-outcome-v1','UTF8') AND substring(NEW.event_bytes FROM 33 FOR 1)=decode('01','hex')) EXECUTE FUNCTION expire_device_capability()"}
                    else {"CREATE TRIGGER expire_device_capability BEFORE INSERT ON deployment_audit_events WHEN substr(NEW.event_bytes,1,30)=CAST('spl-account-request-outcome-v1' AS BLOB) AND substr(NEW.event_bytes,33,1)=x'01' BEGIN UPDATE account_entry_state SET time_high_water_ms=time_high_water_ms+60000; END"})
                    .execute(store.pool()).await.expect("capability expires while challenge remains live");
                assert_eq!(execute(&store,&submit).await.expect_err("capability final expiry"),Error::AuthenticationRequired);
                assert_eq!(count(&store,"identity_devices").await,1);assert_eq!(count(&store,"account_operation_receipts").await,0);assert_eq!(count(&store,"account_admission_capabilities").await,1);assert_eq!(count(&store,"account_request_challenges").await,0);
                let retained:i64=sqlx::query_scalar("SELECT time_high_water_ms FROM account_entry_state").fetch_one(store.pool()).await.expect("observed expiry survives business rollback");assert_eq!(retained,FUTURE+300_000);
                $cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn precommit_deadline_wait_rolls_back_before_bounded_failure_audit() {
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await;
                let candidate=candidate(&account,&issued,2);
                let submit=request(&candidate,&account,Intent::Submit,challenge(&store,&candidate,Intent::Submit).await);
                source_admission(&store,Endpoint::DeviceAdmission).await;
                let mut guard=begin(&store).await;
                if $pg {sqlx::query("SELECT singleton FROM account_entry_state WHERE singleton=1 FOR UPDATE").execute(&mut *guard).await.expect("held singleton");}
                let body=submit.to_json().expect("body");let limit=tokio::time::Instant::now()+Duration::from_millis(30);
                let (result,())=tokio::join!(store.execute_account_device_admission(source(),ORIGIN,&body,limit),async {
                    tokio::time::sleep(Duration::from_millis(100)).await;guard.rollback().await.expect("release owned lock");});
                assert_eq!(result.expect_err("deadline while acquiring admission writer"),Error::StorageUnavailable);
                assert_eq!(count(&store,"identity_devices").await,1);assert_eq!(count(&store,"account_admission_capabilities").await,1);assert_eq!(count(&store,"account_request_challenges").await,1);
                assert!(matches!(execute(&store,&submit).await.expect("pool remains usable and claim retained"),Outcome::Admitted(_)));
                $cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn complete_admission_preserves_every_old_artifact_and_historical_confirmation() {
                let (store,resources)=$open().await;let account=establish(&store).await;
                let issued=login(&store,&account).await;let candidate=candidate(&account,&issued,2);
                let credential:(Vec<u8>,Vec<u8>,i64,i64,Vec<u8>)=sqlx::query_as("SELECT verifier,password_ark,credential_generation,password_profile,password_salt FROM account_password_bootstrap").fetch_one(store.pool()).await.expect("credential before");
                let submitted=request(&candidate,&account,Intent::Submit,challenge(&store,&candidate,Intent::Submit).await);
                let Outcome::Admitted(bytes)=execute(&store,&submitted).await.expect("confirmed admission")else{panic!("submit admits")};
                AccountCommittedConfirmation::from_json(&bytes).expect("bounded response").validate_for_request(Kind::Admit,submitted.payload.as_bytes(),&submitted.account_signature).expect("exact business receipt");
                let current=AccountBootstrapSnapshot::from_cbor(snapshot(&store,&account).await.as_bytes()).expect("next complete snapshot");
                let mut expected=AccountBootstrapSnapshot::from_cbor(issued.snapshot.as_bytes()).expect("original snapshot");
                expected.key_bundle=candidate.payload.key_bundle.clone();expected.certificates.push(candidate.payload.device_certificate.clone());expected.certificates.sort();
                assert_eq!(current,expected,"only signed next PUT and one certificate change");
                let after:(Vec<u8>,Vec<u8>,i64,i64,Vec<u8>)=sqlx::query_as("SELECT verifier,password_ark,credential_generation,password_profile,password_salt FROM account_password_bootstrap").fetch_one(store.pool()).await.expect("credential after");assert_eq!(after,credential);
                for table in ["identity_devices","sync_account_key_certificates","sync_account_key_device_wraps"] {assert_eq!(count(&store,table).await,2,"{table}");}
                assert_eq!(count(&store,"account_operation_receipts").await,1);assert_eq!(count(&store,"account_admission_capabilities").await,0);
                for table in ["device_refresh_families","device_refresh_tokens","device_auth_challenges"] {assert_eq!(count(&store,table).await,0,"no session authority: {table}");}
                sqlx::query("UPDATE identity_devices SET active=FALSE").execute(store.pool()).await.expect("later Device revocation");
                let revocation=RevocationStatement::issue(&account.root,candidate.payload.device_id,2,"later revocation".into()).expect("root-signed revocation").encode().expect("revocation bytes");
                sqlx::query("INSERT INTO sync_account_key_revocations (account_id,revocation) VALUES ($1,$2)").bind(account.payload.account_id.as_bytes().as_slice()).bind(revocation).execute(store.pool()).await.expect("later retained revocation");
                sqlx::query("UPDATE identity_accounts SET account_signing_public_key=$1").bind([99_u8;32].as_slice()).execute(store.pool()).await.expect("later root lifecycle");
                advance(&store,300_001).await;
                let previous=store.deployment_audit_head().await.expect("success audit");
                let confirm=request(&candidate,&account,Intent::Confirm,challenge(&store,&candidate,Intent::Confirm).await);
                let Outcome::Confirmed(repeated)=execute(&store,&confirm).await.expect("historical root, expired capability, inactive Device")else{panic!("historical confirmation")};
                assert_eq!(SecretVec::new(bytes),SecretVec::new(repeated));assert_eq!(store.deployment_audit_head().await.expect("no duplicate success"),previous);
                let active:i64=sqlx::query_scalar("SELECT COUNT(*) FROM identity_devices WHERE active=TRUE").fetch_one(store.pool()).await.expect("no reactivation");assert_eq!(active,0);
                $cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn invalid_proof_preserves_capability_but_consumes_challenge_without_account_debt() {
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await;
                let candidate=candidate(&account,&issued,2);let before=snapshot(&store,&account).await;
                let mut bad=request(&candidate,&account,Intent::Submit,challenge(&store,&candidate,Intent::Submit).await);bad.device_proof[0]^=1;
                let head=store.deployment_audit_head().await.expect("before denial").expect("head").sequence;
                assert_eq!(execute(&store,&bad).await.expect_err("invalid possession"),Error::AuthenticationRequired);
                assert_eq!(snapshot(&store,&account).await,before);assert_eq!(count(&store,"account_admission_capabilities").await,1);
                assert_eq!(count(&store,"account_request_challenges").await,0);assert_eq!(quota(&store).await,0);
                assert_eq!(store.deployment_audit_head().await.expect("denial audit").expect("head").sequence,head+1);
                advance(&store,2_000).await;
                let good=request(&candidate,&account,Intent::Submit,challenge(&store,&candidate,Intent::Submit).await);
                assert!(matches!(execute(&store,&good).await.expect("fresh challenge retry uses preserved capability"),Outcome::Admitted(_)));
                $cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn canonical_binding_failures_preserve_capability_and_charge_no_account() {
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await;
                let mut candidate=candidate(&account,&issued,2);let original=candidate.payload.clone();
                for case in 0..7 {
                    let live=challenge(&store,&candidate,Intent::Submit).await;
                    match case {0=>candidate.payload.username="wrong-user".into(),1=>candidate.payload.personal_vault_id=Uuid::now_v7(),
                        2=>candidate.payload.snapshot_digest[0]^=1,3=>candidate.payload.capability_digest[0]^=1,
                        4=>candidate.payload.credential_generation+=1,5=>candidate.payload.origin="https://different.test".into(),_=>()}
                    let mut bad=request(&candidate,&account,Intent::Submit,live);
                    if case==6 {bad.account_signature[0]^=1;}
                    assert_eq!(execute(&store,&bad).await.expect_err("common canonical authentication denial"),Error::AuthenticationRequired);
                    assert_eq!(count(&store,"account_request_challenges").await,0);assert_eq!(count(&store,"account_admission_capabilities").await,1);assert_eq!(quota(&store).await,0);
                    candidate.payload=original.clone();advance(&store,2_000_i64 << case).await;
                }
                $cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn stale_complete_snapshot_spends_capability_before_old_root_proof_or_account_quota() {
                let (store,resources)=$open().await;let account=establish(&store).await;
                let first=login(&store,&account).await;let old=login(&store,&account).await;
                let current=candidate(&account,&first,2);let stale=candidate(&account,&old,3);
                let submit=request(&current,&account,Intent::Submit,challenge(&store,&current,Intent::Submit).await);
                execute(&store,&submit).await.expect("first admitted next revision");
                let attempts:i64=sqlx::query_scalar("SELECT attempts FROM account_entry_admission WHERE endpoint=5 AND kind=4").fetch_one(store.pool()).await.expect("verified previous debt");
                let mut request=request(&stale,&account,Intent::Submit,challenge(&store,&stale,Intent::Submit).await);request.account_signature[0]^=1;
                assert_eq!(execute(&store,&request).await.expect_err("stale CAS precedes unverifiable proof"),Error::AdmissionConflict);
                assert_eq!(count(&store,"account_admission_capabilities").await,0);assert_eq!(count(&store,"identity_devices").await,2);
                let after:i64=sqlx::query_scalar("SELECT attempts FROM account_entry_admission WHERE endpoint=5 AND kind=4").fetch_one(store.pool()).await.expect("stale branch adds no Account debt");assert_eq!(after,attempts);
                $cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn changed_root_or_personal_state_is_cas_conflict_without_account_quota() {
                for case in 0..2 {
                    let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await;
                    let candidate=candidate(&account,&issued,2);
                    if case==0 {sqlx::query("UPDATE identity_accounts SET account_signing_public_key=$1").bind([99_u8;32].as_slice()).execute(store.pool()).await.expect("later root");}
                    else{sqlx::query("UPDATE sync_vaults SET rotation_pending=TRUE").execute(store.pool()).await.expect("later pending Personal rotation");}
                    let mut submit=request(&candidate,&account,Intent::Submit,challenge(&store,&candidate,Intent::Submit).await);submit.account_signature[0]^=1;
                    assert_eq!(execute(&store,&submit).await.expect_err("current-state CAS wins without old-root proof"),Error::AdmissionConflict);
                    assert_eq!(count(&store,"account_admission_capabilities").await,0);assert_eq!(quota(&store).await,0);assert_eq!(count(&store,"identity_devices").await,1);
                    $cleanup(store,resources).await;
                }
            }

            #[tokio::test]
            async fn next_revision_and_existing_ciphertext_changes_spend_capability_as_conflict() {
                for case in 0..3 {
                    let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await;
                    let mut candidate=candidate(&account,&issued,2);let before=snapshot(&store,&account).await;
                    resign(&mut candidate,&account,|update|match case {0=>update.revision+=1,
                        1=>update.device_wraps.iter_mut().find(|wrap|wrap.device_id==account.payload.device_id).expect("original recipient").wrapped_ark[80]^=1,
                        _=>update.account_signing_key[40]^=1});
                    let submit=request(&candidate,&account,Intent::Submit,challenge(&store,&candidate,Intent::Submit).await);
                    AccountDeviceAdmissionRequest::decode_for_authentication(&submit.to_json().expect("signed conflict body")).expect("structurally valid semantic conflict");
                    assert_eq!(execute(&store,&submit).await.expect_err("signed semantic conflict"),Error::AdmissionConflict);
                    assert_eq!(snapshot(&store,&account).await,before);assert_eq!(count(&store,"account_admission_capabilities").await,0);assert_eq!(quota(&store).await,1);
                    $cleanup(store,resources).await;
                }
            }

            #[tokio::test]
            async fn invalid_bundle_signature_is_authentication_denial_with_capability_preserved() {
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await;
                let mut candidate=candidate(&account,&issued,2);
                let mut update=SyncAccountKeyBundleUpdate::from_cbor(&candidate.payload.key_bundle).expect("PUT");update.signature[0]^=1;
                candidate.payload.key_bundle=update.to_cbor().expect("structural PUT with invalid signature");
                let submit=request(&candidate,&account,Intent::Submit,challenge(&store,&candidate,Intent::Submit).await);
                assert_eq!(execute(&store,&submit).await.expect_err("signature denial before semantic CAS"),Error::AuthenticationRequired);
                assert_eq!(count(&store,"account_admission_capabilities").await,1);assert_eq!(quota(&store).await,0);
                $cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn account_rate_rejection_preserves_challenge_and_capability_and_prior_device_debt() {
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await;
                let candidate=candidate(&account,&issued,2);let live=challenge(&store,&candidate,Intent::Submit).await;
                // A real prior authenticated admission establishes this bucket first.
                let verified=scoplen_store::account_entry_admission::VerifiedAccountBucket::after_authentication(account.payload.account_id).expect("test trusted Account");
                for _ in 0..10 {assert_eq!(store.admit_account_entry_private(Endpoint::DeviceAdmission,source(),scoplen_store::account_entry_admission::AccountEntryPrivateBucket::EstablishedAccount(verified)).await.expect("prior authenticated debt"),Decision::Admitted);}
                let submit=request(&candidate,&account,Intent::Submit,live);
                assert!(matches!(execute(&store,&submit).await.expect_err("private Account rate limit"),Error::RateLimited(_)));
                assert_eq!(count(&store,"account_request_challenges").await,1);assert_eq!(count(&store,"account_admission_capabilities").await,1);assert_eq!(count(&store,"identity_devices").await,1);
                let charged:i64=sqlx::query_scalar("SELECT attempts FROM account_entry_admission WHERE endpoint=5 AND kind=3").fetch_one(store.pool()).await.expect("earlier committed Device debt");assert_eq!(charged,1);
                advance(&store,60_001).await;
                assert!(matches!(execute(&store,&submit).await.expect("same preserved challenge after rate window"),Outcome::Admitted(_)));
                $cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn missing_receipt_after_deletion_never_creates_or_confirms_negative_outcome() {
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await;
                let candidate=candidate(&account,&issued,2);
                let missing=request(&candidate,&account,Intent::Confirm,challenge(&store,&candidate,Intent::Confirm).await);
                assert_eq!(execute(&store,&missing).await.expect_err("missing receipt is unresolved"),Error::AuthenticationRequired);
                advance(&store,2_000).await;
                let submit=request(&candidate,&account,Intent::Submit,challenge(&store,&candidate,Intent::Submit).await);execute(&store,&submit).await.expect("new admission");
                let mut deletion=begin(&store).await;
                sqlx::query("DELETE FROM identity_devices WHERE account_id=$1").bind(account.payload.account_id.as_bytes().as_slice()).execute(&mut *deletion).await.expect("owned Device lifecycle deletion");
                sqlx::query("DELETE FROM identity_accounts WHERE account_id=$1").bind(account.payload.account_id.as_bytes().as_slice()).execute(&mut *deletion).await.expect("owned Account deletion fixture");
                deletion.commit().await.expect("atomic owned Account deletion fixture");
                let confirm=request(&candidate,&account,Intent::Confirm,challenge(&store,&candidate,Intent::Confirm).await);
                assert_eq!(execute(&store,&confirm).await.expect_err("deleted receipt never creates"),Error::AuthenticationRequired);
                assert_eq!(count(&store,"identity_accounts").await,0);assert_eq!(count(&store,"identity_devices").await,0);assert_eq!(count(&store,"account_operation_receipts").await,0);
                assert_eq!(store.account_id_retention_summary().await.expect("permanent id retention").used,1);
                $cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn mandatory_audit_failure_rolls_back_business_capability_and_challenge() {
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await;
                let candidate=candidate(&account,&issued,2);let before=snapshot(&store,&account).await;
                let submit=request(&candidate,&account,Intent::Submit,challenge(&store,&candidate,Intent::Submit).await);audit_fault(&store).await;
                assert_eq!(execute(&store,&submit).await.expect_err("mandatory audit overrides success"),Error::StorageUnavailable);
                assert_eq!(snapshot(&store,&account).await,before);assert_eq!(count(&store,"account_admission_capabilities").await,1);assert_eq!(count(&store,"account_request_challenges").await,1);assert_eq!(quota(&store).await,0);
                $cleanup(store,resources).await;
            }

            #[tokio::test]
            async fn final_audit_expiry_rolls_back_business_and_commits_only_separate_denial() {
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await;
                let candidate=candidate(&account,&issued,2);let before=snapshot(&store,&account).await;
                let submit=request(&candidate,&account,Intent::Submit,challenge(&store,&candidate,Intent::Submit).await);
                sqlx::raw_sql(if $pg {"CREATE FUNCTION expire_device_challenge() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN UPDATE account_entry_state SET time_high_water_ms=time_high_water_ms+120001; RETURN NEW; END'; CREATE TRIGGER expire_device_challenge BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION expire_device_challenge()"}
                    else {"CREATE TRIGGER expire_device_challenge BEFORE INSERT ON deployment_audit_events BEGIN UPDATE account_entry_state SET time_high_water_ms=time_high_water_ms+120001; END"})
                    .execute(store.pool()).await.expect("owned final-audit clock fault");
                assert_eq!(execute(&store,&submit).await.expect_err("fresh expiry after audit"),Error::AuthenticationRequired);
                assert_eq!(snapshot(&store,&account).await,before);assert_eq!(count(&store,"account_operation_receipts").await,0);assert_eq!(count(&store,"account_admission_capabilities").await,1);assert_eq!(count(&store,"account_request_challenges").await,1);
                $cleanup(store,resources).await;
            }
        }
    };
}

backend!(
    sqlite,
    SqliteStore,
    sqlx::Sqlite,
    sqlite_open,
    sqlite_cleanup,
    sqlite_reopen,
    create_sqlite_password_account_in_transaction,
    read_sqlite_password_bootstrap_in_transaction,
    legacy_identity::seed_sqlite,
    false
);
#[cfg(feature = "postgres-integration")]
backend!(
    postgres,
    scoplen_store::PostgresStore,
    sqlx::Postgres,
    postgres_open,
    postgres_cleanup,
    postgres_reopen,
    create_postgres_password_account_in_transaction,
    read_postgres_password_bootstrap_in_transaction,
    legacy_identity::seed_postgres,
    true
);

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_real_lost_acknowledgements_preserve_distinct_business_confirmation_private_and_denial_results()
 {
    use std::sync::atomic::Ordering;
    let (store, resources) = postgres_open().await;
    let account = postgres::establish(&store).await;
    let issued = postgres::login(&store, &account).await;
    let candidate = candidate(&account, &issued, 2);
    let submit = request(
        &candidate,
        &account,
        Intent::Submit,
        postgres::challenge(&store, &candidate, Intent::Submit).await,
    );
    postgres::source_admission(&store, Endpoint::DeviceAdmission).await;
    let before =
        store.deployment_audit_head().await.expect("before admission").expect("head").sequence;
    let proxy = lost_commit::LostCommitProxy::start_skipping(&resources.2, 1).await;
    let uncertain = scoplen_store::PostgresStore::connect(&proxy.database_url)
        .await
        .expect("business commit proxy");
    proxy.armed.store(true, Ordering::SeqCst);
    assert_eq!(
        uncertain
            .execute_account_device_admission(
                source(),
                ORIGIN,
                &submit.to_json().expect("body"),
                deadline()
            )
            .await
            .expect_err("real lost business commit ACK"),
        Error::CommitOutcomeUnknown
    );
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(postgres::count(&store, "identity_devices").await, 2);
    assert_eq!(postgres::count(&store, "account_operation_receipts").await, 1);
    let committed = store.deployment_audit_head().await.expect("committed success audit");
    assert_eq!(
        committed.as_ref().expect("head").sequence,
        before + 1,
        "no supplemental unknown-commit audit"
    );
    uncertain.pool().close().await;
    drop(proxy);
    let confirm = request(
        &candidate,
        &account,
        Intent::Confirm,
        postgres::challenge(&store, &candidate, Intent::Confirm).await,
    );
    postgres::source_admission(&store, Endpoint::DeviceAdmission).await;
    let proxy = lost_commit::LostCommitProxy::start_skipping(&resources.2, 1).await;
    let uncertain = scoplen_store::PostgresStore::connect(&proxy.database_url)
        .await
        .expect("confirmation proxy");
    proxy.armed.store(true, Ordering::SeqCst);
    assert_eq!(
        uncertain
            .execute_account_device_admission(
                source(),
                ORIGIN,
                &confirm.to_json().expect("body"),
                deadline()
            )
            .await
            .expect_err("real lost confirmation ACK"),
        Error::StorageUnavailable
    );
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.deployment_audit_head().await.expect("no duplicate or supplemental audit"),
        committed
    );
    uncertain.pool().close().await;
    drop(proxy);
    let confirm = request(
        &candidate,
        &account,
        Intent::Confirm,
        postgres::challenge(&store, &candidate, Intent::Confirm).await,
    );
    assert!(matches!(
        postgres::execute(&store, &confirm).await.expect("fresh explicit receipt-only recovery"),
        Outcome::Confirmed(_)
    ));
    let issued = postgres::login(&store, &account).await;
    let after_login = store.deployment_audit_head().await.expect("fresh login audit");
    let next = self::candidate(&account, &issued, 3);
    let mut submit = request(
        &next,
        &account,
        Intent::Submit,
        postgres::challenge(&store, &next, Intent::Submit).await,
    );
    postgres::source_admission(&store, Endpoint::DeviceAdmission).await;
    let proxy = lost_commit::LostCommitProxy::start(&resources.2).await;
    let uncertain = scoplen_store::PostgresStore::connect(&proxy.database_url)
        .await
        .expect("private debt proxy");
    proxy.armed.store(true, Ordering::SeqCst);
    assert_eq!(
        uncertain
            .execute_account_device_admission(
                source(),
                ORIGIN,
                &submit.to_json().expect("body"),
                deadline()
            )
            .await
            .expect_err("private admission lost ACK"),
        Error::StorageUnavailable
    );
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(postgres::count(&store, "identity_devices").await, 2);
    assert_eq!(postgres::count(&store, "account_request_challenges").await, 1);
    assert_eq!(postgres::count(&store, "account_admission_capabilities").await, 1);
    assert_eq!(
        store.deployment_audit_head().await.expect("no supplemental private-uncertainty audit"),
        after_login
    );
    uncertain.pool().close().await;
    drop(proxy);
    submit.device_proof[0] ^= 1;
    postgres::source_admission(&store, Endpoint::DeviceAdmission).await;
    let proxy = lost_commit::LostCommitProxy::start_skipping(&resources.2, 1).await;
    let uncertain = scoplen_store::PostgresStore::connect(&proxy.database_url)
        .await
        .expect("denial commit proxy");
    proxy.armed.store(true, Ordering::SeqCst);
    assert_eq!(
        uncertain
            .execute_account_device_admission(
                source(),
                ORIGIN,
                &submit.to_json().expect("body"),
                deadline()
            )
            .await
            .expect_err("lost denial ACK is storage failure"),
        Error::StorageUnavailable
    );
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(postgres::count(&store, "identity_devices").await, 2);
    assert_eq!(postgres::count(&store, "account_request_challenges").await, 0);
    assert_eq!(postgres::count(&store, "account_admission_capabilities").await, 1);
    assert_eq!(
        store
            .deployment_audit_head()
            .await
            .expect("one mandatory denial only")
            .expect("head")
            .sequence,
        after_login.expect("head after fresh login").sequence + 1
    );
    uncertain.pool().close().await;
    drop(proxy);
    postgres_cleanup(store, resources).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_missing_challenge_denial_lost_ack_never_appends_supplemental_audit() {
    postgres_separate_denial_lost_ack(false).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_expiry_recovery_denial_lost_ack_never_appends_supplemental_audit() {
    postgres_separate_denial_lost_ack(true).await;
}

#[cfg(feature = "postgres-integration")]
async fn postgres_separate_denial_lost_ack(expiry: bool) {
    use std::sync::atomic::Ordering;
    let (store, resources) = postgres_open().await;
    let account = postgres::establish(&store).await;
    let issued = postgres::login(&store, &account).await;
    let candidate = candidate(&account, &issued, 2);
    if expiry {
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=time_high_water_ms+240000")
            .execute(store.pool())
            .await
            .expect("near-expiry capability");
    }
    let mut submit = request(
        &candidate,
        &account,
        Intent::Submit,
        postgres::challenge(&store, &candidate, Intent::Submit).await,
    );
    if expiry {
        sqlx::raw_sql("CREATE FUNCTION expire_denial_capability() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN UPDATE account_entry_state SET time_high_water_ms=time_high_water_ms+60000; RETURN NEW; END'; CREATE TRIGGER expire_denial_capability BEFORE INSERT ON deployment_audit_events FOR EACH ROW WHEN (substring(NEW.event_bytes FROM 1 FOR 30)=convert_to('spl-account-request-outcome-v1','UTF8') AND substring(NEW.event_bytes FROM 33 FOR 1)=decode('01','hex')) EXECUTE FUNCTION expire_denial_capability()")
            .execute(store.pool()).await.expect("expire capability only in rolled-back success audit");
    } else {
        submit.attempt_id = SecretBytes::new([82; 32]);
    }
    postgres::source_admission(&store, Endpoint::DeviceAdmission).await;
    let before = store
        .deployment_audit_head()
        .await
        .expect("before separate denial")
        .expect("head")
        .sequence;
    let proxy = lost_commit::LostCommitProxy::start_skipping(&resources.2, 1).await;
    let uncertain = scoplen_store::PostgresStore::connect(&proxy.database_url)
        .await
        .expect("separate denial proxy");
    proxy.armed.store(true, Ordering::SeqCst);
    assert_eq!(
        uncertain
            .execute_account_device_admission(
                source(),
                ORIGIN,
                &submit.to_json().expect("body"),
                deadline()
            )
            .await
            .expect_err("separate denial commit lost ACK"),
        Error::StorageUnavailable
    );
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .deployment_audit_head()
            .await
            .expect("no supplemental denial audit")
            .expect("head")
            .sequence,
        before + 1
    );
    assert_eq!(postgres::count(&store, "identity_devices").await, 1);
    assert_eq!(postgres::count(&store, "account_operation_receipts").await, 0);
    assert_eq!(postgres::count(&store, "account_admission_capabilities").await, 1);
    assert_eq!(postgres::count(&store, "account_request_challenges").await, i64::from(!expiry));
    if expiry {
        let retained: i64 =
            sqlx::query_scalar("SELECT time_high_water_ms FROM account_entry_state")
                .fetch_one(store.pool())
                .await
                .expect("durable observed expiry");
        assert_eq!(retained, FUTURE + 300_000);
    }
    uncertain.pool().close().await;
    drop(proxy);
    postgres_cleanup(store, resources).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_rechecks_both_expiries_after_waiting_for_account_serialization() {
    for capability in [false, true] {
        let (store, resources) = postgres_open().await;
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_millis(),
        )
        .expect("millis");
        let account = postgres::establish_at(&store, now).await;
        let issued = postgres::login(&store, &account).await;
        let candidate = candidate(&account, &issued, 2);
        let live = postgres::challenge(&store, &candidate, Intent::Submit).await;
        let submit = request(&candidate, &account, Intent::Submit, live);
        let verified =
            scoplen_store::account_entry_admission::VerifiedAccountBucket::after_authentication(
                account.payload.account_id,
            )
            .expect("test authenticated Account");
        for _ in 0..10 {
            assert_eq!(store.admit_account_entry_private(Endpoint::DeviceAdmission,source(),scoplen_store::account_entry_admission::AccountEntryPrivateBucket::EstablishedAccount(verified)).await.expect("prior exhausted Account quota"),Decision::Admitted);
        }
        let query = if capability {
            "WITH time AS MATERIALIZED (SELECT (EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT AS value) UPDATE account_admission_capabilities SET issued_at_ms=time.value-299750,expires_at_ms=time.value+250 FROM time"
        } else {
            "WITH time AS MATERIALIZED (SELECT (EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT AS value) UPDATE account_request_challenges SET issued_at_ms=time.value-119750,expires_at_ms=time.value+250 FROM time"
        };
        sqlx::query(query).execute(store.pool()).await.expect("owned short remaining lifetime");
        postgres::source_admission(&store, Endpoint::DeviceAdmission).await;
        let mut guard = store.pool().begin().await.expect("held Account writer");
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1,'hex'),0))")
            .bind(account.payload.account_id.as_bytes().as_slice())
            .execute(&mut *guard)
            .await
            .expect("exclusive Account serialization");
        let body = submit.to_json().expect("body");
        let mut operation =
            Box::pin(store.execute_account_device_admission(source(), ORIGIN, &body, deadline()));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut operation).await.is_err(),
            "transaction actually waits for the held Account lock"
        );
        let (result, ()) = tokio::join!(operation, async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            guard.rollback().await.expect("release Account writer");
        });
        assert_eq!(
            result.expect_err("expiry after Account lock wait"),
            Error::AuthenticationRequired
        );
        assert_eq!(postgres::count(&store, "identity_devices").await, 1);
        assert_eq!(postgres::count(&store, "account_operation_receipts").await, 0);
        assert_eq!(postgres::count(&store, "account_admission_capabilities").await, 1);
        assert_eq!(
            postgres::count(&store, "account_request_challenges").await,
            i64::from(!capability)
        );
        let attempts: i64 = sqlx::query_scalar(
            "SELECT attempts FROM account_entry_admission WHERE endpoint=5 AND kind=4",
        )
        .fetch_one(store.pool())
        .await
        .expect("expiry wins before Account quota admission");
        assert_eq!(attempts, 10);
        postgres_cleanup(store, resources).await;
    }
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_business_deadline_cancels_account_wait_and_explicitly_restores_both_claims() {
    let (store, resources) = postgres_open().await;
    let account = postgres::establish(&store).await;
    let issued = postgres::login(&store, &account).await;
    let candidate = candidate(&account, &issued, 2);
    let submit = request(
        &candidate,
        &account,
        Intent::Submit,
        postgres::challenge(&store, &candidate, Intent::Submit).await,
    );
    postgres::source_admission(&store, Endpoint::DeviceAdmission).await;
    let mut guard = store.pool().begin().await.expect("held Account writer");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1,'hex'),0))")
        .bind(account.payload.account_id.as_bytes().as_slice())
        .execute(&mut *guard)
        .await
        .expect("exclusive Account lock");
    let body = submit.to_json().expect("body");
    let limit = tokio::time::Instant::now() + Duration::from_millis(100);
    let mut operation =
        Box::pin(store.execute_account_device_admission(source(), ORIGIN, &body, limit));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut operation).await.is_err(),
        "business preparation reaches the held Account lock"
    );
    let (result, ()) = tokio::join!(operation, async {
        tokio::time::sleep(Duration::from_millis(150)).await;
        guard.rollback().await.expect("release fixture writer");
    });
    assert_eq!(
        result.expect_err("precommit deadline after claiming both secrets"),
        Error::StorageUnavailable
    );
    assert_eq!(postgres::count(&store, "identity_devices").await, 1);
    assert_eq!(postgres::count(&store, "account_operation_receipts").await, 0);
    assert_eq!(postgres::count(&store, "account_admission_capabilities").await, 1);
    assert_eq!(postgres::count(&store, "account_request_challenges").await, 1);
    let debt: i64 = sqlx::query_scalar(
        "SELECT attempts FROM account_entry_admission WHERE endpoint=5 AND kind=3",
    )
    .fetch_one(store.pool())
    .await
    .expect("earlier private debt retained");
    assert_eq!(debt, 1);
    assert!(matches!(
        postgres::execute(&store, &submit).await.expect("explicit later retry on usable pool"),
        Outcome::Admitted(_)
    ));
    postgres_cleanup(store, resources).await;
}

#[tokio::test]
async fn sqlite_attempted_business_commit_failure_remains_unknown_without_supplemental_audit() {
    let (store, path) = sqlite_open().await;
    let account = sqlite::establish(&store).await;
    let issued = sqlite::login(&store, &account).await;
    let candidate = candidate(&account, &issued, 2);
    let submit = request(
        &candidate,
        &account,
        Intent::Submit,
        sqlite::challenge(&store, &candidate, Intent::Submit).await,
    );
    let previous = store.deployment_audit_head().await.expect("before commit fault");
    sqlx::raw_sql("CREATE TABLE device_commit_parent (id INTEGER PRIMARY KEY); CREATE TABLE device_commit_child (id INTEGER REFERENCES device_commit_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER device_commit_failure AFTER INSERT ON account_operation_receipts BEGIN INSERT INTO device_commit_child VALUES(1); END")
        .execute(store.pool()).await.expect("deferred business COMMIT fault");
    assert_eq!(
        sqlite::execute(&store, &submit)
            .await
            .expect_err("attempted business COMMIT is always conservatively unknown"),
        Error::CommitOutcomeUnknown
    );
    assert_eq!(store.deployment_audit_head().await.expect("no supplemental audit"), previous);
    assert_eq!(sqlite::count(&store, "identity_devices").await, 1);
    assert_eq!(sqlite::count(&store, "account_operation_receipts").await, 0);
    assert_eq!(sqlite::count(&store, "account_admission_capabilities").await, 1);
    assert_eq!(sqlite::count(&store, "account_request_challenges").await, 1);
    sqlite_cleanup(store, path).await;
}
