// SPDX-License-Identifier: AGPL-3.0-only

#[allow(dead_code)]
#[path = "support/legacy_identity.rs"]
mod legacy_identity;
#[path = "support/pool_close.rs"]
mod pool_close;
mod support;

use scoplen_api::account_admission::{
    AccountBootstrapSnapshot, AccountPasswordChangeConfirmation, AccountPasswordChangePayload,
    AccountPasswordChangeRequest, AccountPasswordLoginRequest, AccountPasswordLoginResponse,
    AccountPasswordOptionsRequest, AccountRegistrationPayload, AccountRequestChallengeRequest,
    AccountRequestChallengeResponse, AccountRequestIntent as Intent, AccountRequestKind as Kind,
};
use scoplen_crypto::{
    AccountRequestProof, AccountRequestSignatureInput, DeviceCertificate, Ed25519SigningKey,
    P256SigningKey, PasswordArkWrap, PasswordBootstrapContext, PasswordSecrets, SecretBytes,
    SecretVec, account_bootstrap_digest, account_capability_digest,
};
use scoplen_store::{
    RelationalStore, SqliteStore,
    account_entry_admission::{
        AccountEntryAdmissionDecision as Decision, AccountEntryEndpoint as Endpoint,
    },
    account_password_change::{
        AccountPasswordChangeError as Error, AccountPasswordChangeResult as Outcome,
    },
    kms::KeyManagementService,
};
use std::{net::IpAddr, time::Duration};
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
    let mut bytes = [0; 32];
    bytes[31] = seed;
    bytes
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

struct Change {
    payload: AccountPasswordChangePayload,
    token: SecretBytes<32>,
}
fn proposal(account: &Account, login: &AccountPasswordLoginResponse) -> (Change, PasswordSecrets) {
    let snapshot =
        AccountBootstrapSnapshot::from_cbor(login.snapshot.as_bytes()).expect("verified bootstrap");
    let secrets = PasswordSecrets::create(
        ORIGIN,
        &snapshot.username,
        SecretVec::new(b"another different current Account password".to_vec()),
    )
    .expect("new password");
    let generation = snapshot.credential_generation.checked_add(1).expect("successor generation");
    let context = PasswordBootstrapContext::new(
        secrets.context().clone(),
        snapshot.account_id,
        snapshot.personal_vault_id,
        &snapshot.account_signing_public_key,
        &snapshot.account_kem_public_key,
        generation,
    )
    .expect("new AAD");
    let payload = AccountPasswordChangePayload {
        operation_id: Uuid::now_v7(),
        origin: ORIGIN.into(),
        username: snapshot.username,
        account_id: snapshot.account_id,
        personal_vault_id: snapshot.personal_vault_id,
        device_id: account.payload.device_id,
        credential_generation: snapshot.credential_generation,
        new_credential_generation: generation,
        snapshot_digest: account_bootstrap_digest(login.snapshot.as_bytes()),
        capability_digest: account_capability_digest(login.admission_token.as_bytes()),
        password_salt: *secrets.context().salt(),
        verifier: *secrets.verifier().as_bytes(),
        password_ark: PasswordArkWrap::seal(&secrets, &context, &SecretBytes::new([11; 32]))
            .expect("same ARK")
            .encode(),
    };
    (Change { payload, token: login.admission_token.clone() }, secrets)
}
fn request(
    change: &Change,
    account: &Account,
    intent: Intent,
    challenge: AccountRequestChallengeResponse,
) -> AccountPasswordChangeRequest {
    let payload = change.payload.to_cbor().expect("retained protected payload");
    let input = AccountRequestSignatureInput::new(Kind::PasswordChange, &payload)
        .expect("Account proof domain");
    let signature = input.sign(&account.root);
    let proof = AccountRequestProof::new(
        Kind::PasswordChange,
        intent,
        ORIGIN,
        challenge.attempt_id.as_bytes(),
        challenge.nonce.as_bytes(),
        change.payload.operation_id,
        change.payload.device_id,
        &input.request_digest(&signature),
    )
    .expect("Device proof domain");
    AccountPasswordChangeRequest {
        intent,
        payload: SecretVec::new(payload),
        account_signature: signature,
        attempt_id: challenge.attempt_id,
        nonce: challenge.nonce,
        device_proof: proof
            .sign(&P256SigningKey::from_bytes(&scalar(1)).expect("original Device"))
            .expect("existing Device proof"),
        admission_token: if intent == Intent::Submit { Some(change.token.clone()) } else { None },
    }
}
async fn sqlite_open() -> (SqliteStore, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("scoplen-password-change-{}", Uuid::now_v7()));
    (SqliteStore::open(&path.join("store.sqlite")).await.expect("owned SQLite"), path)
}
async fn sqlite_cleanup(store: SqliteStore, path: std::path::PathBuf) {
    pool_close::close(store.pool()).await;
    drop(store);
    support::remove_test_directory(path).await;
}
#[cfg(feature = "postgres-integration")]
async fn postgres_open() -> (scoplen_store::PostgresStore, (sqlx::PgPool, String, String)) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL fixture URL");
    let admin = sqlx::PgPool::connect(&database).await.expect("admin fixture connection");
    let schema = format!("password_change_{}", Uuid::now_v7().simple());
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
macro_rules! backend {
    ($module:ident,$store:ty,$db:ty,$open:ident,$cleanup:ident,$create:ident,$read:ident,$claim:ident,$pg:literal)=>{
        mod $module {
            use super::*;
            use scoplen_store::account_bootstrap::{$create,$read};
            use scoplen_store::account_admission_capabilities::$claim;
            type Store=$store;
            async fn begin(store:&Store)->sqlx::Transaction<'_,$db>{
                if $pg {store.pool().begin().await.expect("transaction")}else{store.pool().begin_with("BEGIN IMMEDIATE").await.expect("writer")}
            }
            async fn establish(store:&Store)->Account {
                store.initialize_account_id_retention(32).await.expect("startup retention");
                store.ensure_account_probe_key(&Kms).await.expect("retained probe key");
                sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1").bind(FUTURE).execute(store.pool()).await.expect("controlled durable clock");
                let account=account();let mut tx=begin(store).await;
                $create(&mut tx,ORIGIN,32,&account.payload,FUTURE).await.expect("complete original Account");tx.commit().await.expect("fixture commit");account
            }
            async fn source_admission(store:&Store,endpoint:Endpoint){
                assert_eq!(store.admit_account_entry_source(endpoint,source()).await.expect("source admission"),Decision::Admitted);
            }
            async fn login(store:&Store,account:&Account)->Result<AccountPasswordLoginResponse,scoplen_store::account_password_login::AccountPasswordLoginError>{
                source_admission(store,Endpoint::PasswordOptions).await;
                let issued=store.issue_account_password_options(source(),ORIGIN,&AccountPasswordOptionsRequest{username:account.payload.username.clone()}.to_json().expect("options"),&Kms,deadline()).await.expect("options issued");
                source_admission(store,Endpoint::PasswordLogin).await;
                store.execute_account_password_login(source(),ORIGIN,AccountPasswordLoginRequest{attempt_id:issued.attempt_id,auth_secret:account.secrets.auth_secret().clone()}.to_json().expect("password proof"),&Kms,deadline()).await
            }
            async fn challenge(store:&Store,change:&Change,intent:Intent)->AccountRequestChallengeResponse {
                source_admission(store,Endpoint::RequestChallenge).await;
                store.issue_account_request_challenge(source(),ORIGIN,&AccountRequestChallengeRequest{kind:Kind::PasswordChange,intent,
                    operation_id:change.payload.operation_id,device_id:change.payload.device_id}).await.expect("fresh challenge")
            }
            async fn execute(store:&Store,request:&AccountPasswordChangeRequest)->Result<Outcome,Error>{
                source_admission(store,Endpoint::PasswordChange).await;
                store.execute_account_password_change(source(),ORIGIN,&request.to_json().expect("strict request"),deadline()).await
            }
            async fn snapshot(store:&Store,account:&Account)->SecretVec {
                let mut tx=begin(store).await;let bytes=$read(&mut tx,ORIGIN,account.payload.account_id).await.expect("complete current bootstrap");tx.rollback().await.expect("read complete");bytes
            }
            async fn count(store:&Store,table:&str)->i64{sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}")).fetch_one(store.pool()).await.expect("state count")}
            async fn advance(store:&Store){sqlx::query("UPDATE account_entry_state SET time_high_water_ms=time_high_water_ms+60000").execute(store.pool()).await.expect("advance durable window");}
            async fn audit_fault(store:&Store,remove:bool){
                let sql=match ($pg,remove){
                    (true,false)=>"CREATE FUNCTION deny_password_audit() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''audit unavailable''; END'; CREATE TRIGGER deny_password_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION deny_password_audit()",
                    (true,true)=>"DROP TRIGGER deny_password_audit ON deployment_audit_events; DROP FUNCTION deny_password_audit()",
                    (false,false)=>"CREATE TRIGGER deny_password_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END",
                    (false,true)=>"DROP TRIGGER deny_password_audit"};
                sqlx::raw_sql(sql).execute(store.pool()).await.expect("owned audit fault change");
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
                let query=if $pg {"INSERT INTO account_operation_receipts (operation_id,account_id,personal_vault_id,device_id,request_digest,kind,device_signing_public_key,device_kem_public_key,account_signing_public_key,admitted_key_revision,committed_at_ms) SELECT decode('00000000000070008000','hex')||convert_to(lpad(n::text,6,'0'),'UTF8'),account_id,personal_vault_id,decode('00000000000170008000','hex')||convert_to(lpad(n::text,6,'0'),'UTF8'),request_digest,2,device_signing_public_key,device_kem_public_key,account_signing_public_key,admitted_key_revision,committed_at_ms FROM account_operation_receipts CROSS JOIN generate_series(1,65535) n"}
                    else{"WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM numbers WHERE n<65535) INSERT INTO account_operation_receipts (operation_id,account_id,personal_vault_id,device_id,request_digest,kind,device_signing_public_key,device_kem_public_key,account_signing_public_key,admitted_key_revision,committed_at_ms) SELECT CAST(x'00000000000070008000'||printf('%06d',n) AS BLOB),account_id,personal_vault_id,CAST(x'00000000000170008000'||printf('%06d',n) AS BLOB),request_digest,2,device_signing_public_key,device_kem_public_key,account_signing_public_key,admitted_key_revision,committed_at_ms FROM account_operation_receipts CROSS JOIN numbers"};
                assert_eq!(sqlx::query(query).execute(&mut *tx).await.expect("exact receipt capacity").rows_affected(),65_535);
                sqlx::query(&trigger).execute(&mut *tx).await.expect("production guard restored");tx.commit().await.expect("capacity fixture committed");
            }

            #[tokio::test]
            async fn credential_only_change_preserves_artifacts_and_historical_confirmation(){
                let (store,resources)=$open().await;let mut account=establish(&store).await;
                let issued=login(&store,&account).await.expect("old-password login");let before=AccountBootstrapSnapshot::from_cbor(issued.snapshot.as_bytes()).unwrap();
                let (change,new_secrets)=proposal(&account,&issued);let submit=request(&change,&account,Intent::Submit,challenge(&store,&change,Intent::Submit).await);
                let Outcome::Changed(body)=execute(&store,&submit).await.expect("confirmed credential change")else{panic!("new change")};
                let result=AccountPasswordChangeConfirmation::from_json(&body).expect("exact confirmation");result.validate_for_request(submit.payload.as_bytes(),&submit.account_signature).unwrap();
                let actual=AccountBootstrapSnapshot::from_cbor(snapshot(&store,&account).await.as_bytes()).unwrap();
                let mut expected=before;expected.credential_generation=2;expected.password_salt=change.payload.password_salt;expected.password_ark=change.payload.password_ark;assert_eq!(actual,expected);
                let mut next_put=scoplen_api::sync::SyncAccountKeyBundleUpdate::from_cbor(&actual.key_bundle).unwrap();
                next_put.revision+=1;next_put.signature=account.root.sign(&next_put.signature_input().unwrap()).to_vec();
                let update=scoplen_store::account_keys::AccountKeyBundleUpdate::try_from(&next_put).unwrap();
                assert!(store.put_account_key_bundle(account.payload.account_id.into_bytes(),&update).await.is_err(),"standalone K-4 writer retains password protection after change");
                assert_eq!(count(&store,"identity_devices").await,1);assert_eq!(count(&store,"account_operation_receipts").await,1);
                assert!(matches!(login(&store,&account).await.expect_err("old credential denied"),scoplen_store::account_password_login::AccountPasswordLoginError::AuthenticationRequired));
                account.secrets=new_secrets;advance(&store).await;
                let next_login=login(&store,&account).await.expect("new password login");
                let (next,_)=proposal(&account,&next_login);let next_submit=request(&next,&account,Intent::Submit,challenge(&store,&next,Intent::Submit).await);
                assert!(matches!(execute(&store,&next_submit).await.expect("same Device second change"),Outcome::Changed(_)));
                sqlx::query("UPDATE identity_devices SET active=FALSE").execute(store.pool()).await.expect("later Device deactivation");
                let confirm=request(&change,&account,Intent::Confirm,challenge(&store,&change,Intent::Confirm).await);
                let audit=store.deployment_audit_head().await.expect("audit before confirmation");
                let Outcome::Confirmed(confirmed)=execute(&store,&confirm).await.expect("historical receipt despite later changes")else{panic!("receipt only")};
                assert_eq!(confirmed,body);assert_eq!(store.deployment_audit_head().await.unwrap(),audit);
                assert_eq!(count(&store,"account_operation_receipts").await,2);
                sqlx::query("DELETE FROM identity_devices").execute(store.pool()).await.unwrap();
                sqlx::query("DELETE FROM identity_accounts").execute(store.pool()).await.expect("Account deletion cascades receipt");
                let missing=request(&change,&account,Intent::Confirm,challenge(&store,&change,Intent::Confirm).await);
                assert_eq!(execute(&store,&missing).await.unwrap_err(),Error::AuthenticationRequired);
                assert_eq!(count(&store,"account_operation_receipts").await,0);
                $cleanup(store,resources).await;
            }
            #[tokio::test]
            async fn invalid_proof_and_audit_rollback_preserve_credential_and_shared_capability(){
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await.unwrap();
                let (change,_)=proposal(&account,&issued);let before=snapshot(&store,&account).await;
                let mut invalid=request(&change,&account,Intent::Submit,challenge(&store,&change,Intent::Submit).await);invalid.device_proof[0]^=1;
                assert_eq!(execute(&store,&invalid).await.unwrap_err(),Error::AuthenticationRequired);
                assert_eq!(count(&store,"account_request_challenges").await,0);assert_eq!(count(&store,"account_admission_capabilities").await,1);
                advance(&store).await;
                let submit=request(&change,&account,Intent::Submit,challenge(&store,&change,Intent::Submit).await);
                audit_fault(&store,false).await;assert_eq!(execute(&store,&submit).await.unwrap_err(),Error::StorageUnavailable);audit_fault(&store,true).await;
                assert_eq!(snapshot(&store,&account).await,before);assert_eq!(count(&store,"account_operation_receipts").await,0);
                assert_eq!(count(&store,"account_request_challenges").await,1);assert_eq!(count(&store,"account_admission_capabilities").await,1);
                assert!(matches!(execute(&store,&submit).await.expect("explicit retry after confirmed rollback"),Outcome::Changed(_)));
                let mut tx=begin(&store).await;assert!($claim(&mut tx,issued.admission_token.as_bytes()).await.expect("same consumer boundary").is_none());tx.rollback().await.unwrap();
                $cleanup(store,resources).await;
            }
            #[tokio::test]
            async fn stale_snapshot_consumes_matching_challenge_and_capability_without_mutation(){
                let (store,resources)=$open().await;let account=establish(&store).await;
                let first=login(&store,&account).await.unwrap();let second=login(&store,&account).await.unwrap();
                let (change,_)=proposal(&account,&first);let (stale,_)=proposal(&account,&second);
                let submit=request(&change,&account,Intent::Submit,challenge(&store,&change,Intent::Submit).await);execute(&store,&submit).await.unwrap();
                let before=snapshot(&store,&account).await;
                let stale_request=request(&stale,&account,Intent::Submit,challenge(&store,&stale,Intent::Submit).await);
                assert_eq!(execute(&store,&stale_request).await.unwrap_err(),Error::AdmissionConflict);
                assert_eq!(snapshot(&store,&account).await,before);assert_eq!(count(&store,"account_operation_receipts").await,1);
                assert_eq!(count(&store,"account_admission_capabilities").await,0);assert_eq!(count(&store,"account_request_challenges").await,0);
                $cleanup(store,resources).await;
            }
            #[tokio::test]
            async fn inactive_device_and_other_consumer_cannot_change_credential(){
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await.unwrap();
                let (change,_)=proposal(&account,&issued);let before=snapshot(&store,&account).await;
                sqlx::query("UPDATE identity_devices SET active=FALSE").execute(store.pool()).await.unwrap();
                let submit=request(&change,&account,Intent::Submit,challenge(&store,&change,Intent::Submit).await);
                assert_eq!(execute(&store,&submit).await.unwrap_err(),Error::AuthenticationRequired);
                assert_eq!(snapshot(&store,&account).await,before);assert_eq!(count(&store,"account_admission_capabilities").await,1);
                sqlx::query("UPDATE identity_devices SET active=TRUE").execute(store.pool()).await.unwrap();advance(&store).await;
                let mut tx=begin(&store).await;assert!($claim(&mut tx,issued.admission_token.as_bytes()).await.unwrap().is_some());tx.commit().await.unwrap();
                let submit=request(&change,&account,Intent::Submit,challenge(&store,&change,Intent::Submit).await);
                assert_eq!(execute(&store,&submit).await.unwrap_err(),Error::AuthenticationRequired);assert_eq!(snapshot(&store,&account).await,before);
                assert_eq!(count(&store,"account_admission_capabilities").await,0);assert_eq!(count(&store,"account_request_challenges").await,0);
                $cleanup(store,resources).await;
            }
            #[tokio::test]
            async fn expired_capability_denies_without_password_mutation(){
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await.unwrap();
                let (change,_)=proposal(&account,&issued);let before=snapshot(&store,&account).await;
                sqlx::query("UPDATE account_admission_capabilities SET issued_at_ms=$1,expires_at_ms=$2").bind(FUTURE-300000).bind(FUTURE).execute(store.pool()).await.unwrap();
                let submit=request(&change,&account,Intent::Submit,challenge(&store,&change,Intent::Submit).await);
                assert_eq!(execute(&store,&submit).await.unwrap_err(),Error::AuthenticationRequired);assert_eq!(snapshot(&store,&account).await,before);
                assert_eq!(count(&store,"account_operation_receipts").await,0);assert_eq!(count(&store,"account_request_challenges").await,0);
                $cleanup(store,resources).await;
            }
            #[tokio::test]
            async fn established_account_rate_denial_preserves_challenge_and_capability(){
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await.unwrap();
                let (change,_)=proposal(&account,&issued);let before=snapshot(&store,&account).await;
                let submit=request(&change,&account,Intent::Submit,challenge(&store,&change,Intent::Submit).await);
                sqlx::query("INSERT INTO account_entry_admission (endpoint,kind,bucket_key,window_start_ms,attempts,failure_streak,last_admitted_ms,retire_at_ms) VALUES (50,4,$1,$2,10,0,$3,$4)")
                    .bind(account.payload.account_id.as_bytes().as_slice()).bind(FUTURE/60000*60000).bind(FUTURE).bind(FUTURE+600000).execute(store.pool()).await.unwrap();
                assert!(matches!(execute(&store,&submit).await.unwrap_err(),Error::RateLimited(_)));
                assert_eq!(snapshot(&store,&account).await,before);assert_eq!(count(&store,"account_admission_capabilities").await,1);assert_eq!(count(&store,"account_request_challenges").await,1);
                assert_eq!(count(&store,"account_operation_receipts").await,0);$cleanup(store,resources).await;
            }
            #[tokio::test]
            async fn shared_receipt_quota_preserves_capability_and_credential(){
                let (store,resources)=$open().await;let account=establish(&store).await;let issued=login(&store,&account).await.unwrap();
                let (change,_)=proposal(&account,&issued);let before=snapshot(&store,&account).await;fill_receipts(&store,&account).await;
                let submit=request(&change,&account,Intent::Submit,challenge(&store,&change,Intent::Submit).await);
                assert_eq!(execute(&store,&submit).await.unwrap_err(),Error::QuotaExceeded);assert_eq!(snapshot(&store,&account).await,before);
                assert_eq!(count(&store,"account_admission_capabilities").await,1);assert_eq!(count(&store,"account_request_challenges").await,0);assert_eq!(count(&store,"account_operation_receipts").await,65536);
                $cleanup(store,resources).await;
            }
            #[tokio::test]
            async fn full_unsigned_generation_remains_readable_through_login_and_change(){
                let (store,resources)=$open().await;let account=establish(&store).await;
                let generation=u64::MAX-1;
                let context=PasswordBootstrapContext::new(account.secrets.context().clone(),account.payload.account_id,account.payload.personal_vault_id,
                    &account.payload.account_signing_public_key,&account.payload.account_kem_public_key,generation).unwrap();
                let wrapper=PasswordArkWrap::seal(&account.secrets,&context,&SecretBytes::new([11;32])).unwrap().encode();
                sqlx::query("UPDATE account_password_bootstrap SET credential_generation=$1,password_ark=$2").bind(generation.to_be_bytes().as_slice()).bind(wrapper.as_slice()).execute(store.pool()).await.expect("owned high-generation fixture");
                let issued=login(&store,&account).await.expect("full unsigned capability");let (change,new_secrets)=proposal(&account,&issued);
                let submit=request(&change,&account,Intent::Submit,challenge(&store,&change,Intent::Submit).await);
                assert!(matches!(execute(&store,&submit).await.unwrap(),Outcome::Changed(_)));
                let mut account=account;account.secrets=new_secrets;advance(&store).await;
                let next=login(&store,&account).await.expect("maximum generation is readable");
                assert_eq!(AccountBootstrapSnapshot::from_cbor(next.snapshot.as_bytes()).unwrap().credential_generation,u64::MAX);
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
    create_sqlite_password_account_in_transaction,
    read_sqlite_password_bootstrap_in_transaction,
    claim_sqlite_account_admission_capability_in_transaction,
    false
);
#[cfg(feature = "postgres-integration")]
backend!(
    postgres,
    scoplen_store::PostgresStore,
    sqlx::Postgres,
    postgres_open,
    postgres_cleanup,
    create_postgres_password_account_in_transaction,
    read_postgres_password_bootstrap_in_transaction,
    claim_postgres_account_admission_capability_in_transaction,
    true
);
