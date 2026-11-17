// SPDX-License-Identifier: AGPL-3.0-only

#[path = "support/legacy_identity.rs"]
#[expect(dead_code, reason = "only signed identity material is used from the shared fixture")]
mod legacy_identity;
#[cfg(feature = "postgres-integration")]
#[path = "support/lost_commit.rs"]
mod lost_commit;
mod support;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scoplen_api::{
    account_admission::{
        AccountPasswordLoginRequest, AccountPasswordOptionsRequest, AccountRegistrationPayload,
    },
    account_browser::{
        AccountBrowserAccessToken, AccountBrowserPasswordLoginRequest,
        AccountBrowserPasswordOptionsRequest,
    },
    group_policy::PolicyFields,
    inventory::{InventoryCreateRequest, InventoryFields, InventoryReplaceRequest, InventoryType},
    inventory_import::{
        InventoryImportFields, InventoryImportRequest, InventoryImportResult, InventoryImportRow,
    },
    organization::OrganizationCreateRequest,
    sync::SyncWriteLimits,
};
use scoplen_crypto::{
    Ed25519SigningKey, P256SigningKey, PasswordArkWrap, PasswordBootstrapContext, PasswordSecrets,
    SecretBytes, SecretVec, dpop_jwk_thumbprint,
};
use scoplen_model::Object;
#[cfg(feature = "postgres-integration")]
use scoplen_store::{
    PostgresStore, account_bootstrap::create_postgres_password_account_in_transaction,
};
use scoplen_store::{
    RelationalStore as _, SqliteStore,
    account_bootstrap::create_sqlite_password_account_in_transaction,
    account_entry_admission::{AccountEntryAdmissionDecision, AccountEntryEndpoint},
    device_authentication::CurrentPrincipal,
    kms::KeyManagementService,
    organizations::{
        OrganizationStoreError as Error,
        group_policy::{ControlFields, ControlKind, ControlTarget, ControlWrite},
        inventory::{InventoryTarget, InventoryWrite},
    },
    sync::SyncCardinalityLimits,
};
use sqlx::Row;
use tokio::time::Instant;
use uuid::Uuid;

const ORIGIN: &str = "https://imports.example.test";

struct Kms;
impl KeyManagementService for Kms {
    fn key_encryption_key(&self) -> &[u8; 32] {
        &[7; 32]
    }
    fn backend_name(&self) -> &'static str {
        "test"
    }
}

fn now_ms() -> i64 {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_millis())
        .expect("timestamp")
}

fn expires() -> u64 {
    u64::try_from(now_ms() / 1000 + 600).expect("expiry")
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

fn limits() -> SyncCardinalityLimits {
    SyncCardinalityLimits { max_objects_per_vault: 256, ..SyncCardinalityLimits::default() }
}

fn password_fixture() -> (AccountRegistrationPayload, PasswordSecrets, CurrentPrincipal) {
    let signing = Ed25519SigningKey::from_bytes(&[1; 32]).expect("Account signing key");
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let device = P256SigningKey::from_bytes(&scalar).expect("Device key");
    let identity = legacy_identity::LegacyIdentity::new(&signing, &device);
    let secrets = PasswordSecrets::create(
        ORIGIN,
        "import-owner",
        SecretVec::new(b"synthetic import fixture password".to_vec()),
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
    let certificate = identity.device_certificate.encode().expect("signed Device certificate");
    let principal = CurrentPrincipal {
        account_id: identity.account_id.into_bytes(),
        device_id: identity.device_certificate.device_id.into_bytes(),
        signing_public_key: device.public_key_sec1(),
        jkt: dpop_jwk_thumbprint(&device.public_key_sec1()).expect("thumbprint"),
        certificate: certificate.clone(),
    };
    let payload = AccountRegistrationPayload {
        operation_id: Uuid::now_v7(),
        origin: ORIGIN.into(),
        username: "import-owner".into(),
        account_id: identity.account_id,
        personal_vault_id: identity.personal_vault_id,
        device_id: identity.device_certificate.device_id,
        account_signing_public_key: identity.account_signing_public_key,
        account_kem_public_key: identity.account_kem_public_key,
        password_salt: *secrets.context().salt(),
        verifier: *secrets.verifier().as_bytes(),
        password_ark: PasswordArkWrap::seal(&secrets, &context, &SecretBytes::new([11; 32]))
            .expect("password envelope")
            .encode(),
        device_certificate: certificate,
        key_bundle: identity.key_bundle_update.to_cbor().expect("signed key bundle"),
        personal_wrapped_key: identity.wrapped_personal_vault_key.try_into().expect("Personal key"),
    };
    (payload, secrets, principal)
}

fn batch(count: usize) -> InventoryImportRequest {
    InventoryImportRequest {
        rows: (0..count)
            .map(|_| InventoryImportRow {
                host_id: Uuid::now_v7(),
                access_profile_id: Uuid::now_v7(),
                fields: InventoryImportFields {
                    name: "Duplicate display name".into(),
                    address: "host.example.test".into(),
                    port: 22,
                    username: "operator".into(),
                    login_name: Some("Operations".into()),
                },
            })
            .collect(),
    }
}

macro_rules! setup {
    ($store:expr,$create:ident) => {{
        $store.initialize_account_id_retention(16).await.expect("retention ceiling");
        let (payload, secrets, native) = password_fixture();
        let mut tx = $store.pool().begin().await.expect("owned Account transaction");
        $create(&mut tx, ORIGIN, 16, &payload, now_ms()).await.expect("signed bootstrap");
        tx.commit().await.expect("Account committed");
        let organization = $store
            .create_organization(
                &native,
                expires(),
                true,
                Uuid::now_v7(),
                &OrganizationCreateRequest::new("Import team").expect("team name"),
            )
            .await
            .expect("team creation");
        (payload, secrets, native, organization)
    }};
}

macro_rules! browser {
    ($store:expr,$payload:expr,$secrets:expr,$jkt:expr) => {{
        let source = "192.0.2.51".parse().expect("source");
        $store.ensure_account_probe_key(&Kms).await.expect("probe key");
        assert_eq!(
            $store
                .admit_account_entry_source(AccountEntryEndpoint::PasswordOptions, source)
                .await
                .unwrap(),
            AccountEntryAdmissionDecision::Admitted
        );
        let options = AccountBrowserPasswordOptionsRequest(AccountPasswordOptionsRequest {
            username: $payload.username.clone(),
        })
        .to_json()
        .unwrap();
        let options = $store
            .issue_account_browser_password_options(
                source,
                ORIGIN,
                &options,
                $jkt,
                &Kms,
                deadline(),
            )
            .await
            .unwrap()
            .0;
        let request = AccountBrowserPasswordLoginRequest(AccountPasswordLoginRequest {
            attempt_id: options.attempt_id,
            auth_secret: $secrets.auth_secret().clone(),
        })
        .to_json()
        .unwrap();
        assert_eq!(
            $store
                .admit_account_entry_source(AccountEntryEndpoint::PasswordLogin, source)
                .await
                .unwrap(),
            AccountEntryAdmissionDecision::Admitted
        );
        let response = $store
            .execute_account_browser_password_login(source, ORIGIN, request, $jkt, &Kms, deadline())
            .await
            .unwrap();
        let token = AccountBrowserAccessToken::parse(&response.browser.access_token).unwrap();
        $store
            .current_account_browser_session(&token, ORIGIN)
            .await
            .unwrap()
            .expect("current browser family")
    }};
}

#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    revision: u64,
    sequence: i64,
    objects: i64,
    references: i64,
    versions: i64,
    receipts: i64,
    audit: i64,
}

macro_rules! snapshot {
    ($store:expr,$org:expr) => {{
        let org=$org;
        let row=sqlx::query("SELECT o.view_revision,s.current_seq,(SELECT COUNT(*) FROM organization_inventory_objects WHERE organization_id=$1) AS objects,(SELECT COUNT(*) FROM organization_inventory_references WHERE organization_id=$1) AS refs,(SELECT COUNT(*) FROM sync_object_versions WHERE vault_id=v.vault_id) AS versions,(SELECT COUNT(*) FROM organization_inventory_receipts WHERE organization_id=$1) AS receipts,(SELECT COUNT(*) FROM audit_events WHERE organization_id=$1) AS audit FROM organizations o JOIN organization_inventory_vaults v ON v.organization_id=o.id JOIN sync_vaults s ON s.vault_id=v.vault_id WHERE o.id=$1")
            .bind(org.as_bytes().as_slice()).fetch_one($store.pool()).await.unwrap();
        Snapshot{revision:u64::from_be_bytes(row.try_get::<Vec<u8>,_>("view_revision").unwrap().try_into().unwrap()),sequence:row.try_get("current_seq").unwrap(),objects:row.try_get("objects").unwrap(),references:row.try_get("refs").unwrap(),versions:row.try_get("versions").unwrap(),receipts:row.try_get("receipts").unwrap(),audit:row.try_get("audit").unwrap()}
    }};
}

macro_rules! policy {
    ($store:expr,$native:expr,$org:expr,$source:expr) => {{
        let fields = ControlFields::Policy(PolicyFields {
            name: "Import authorization".into(),
            source: $source.into(),
            enabled: true,
        });
        $store
            .write_organization_control(
                $native,
                expires(),
                ORIGIN,
                ControlTarget { organization: $org, kind: ControlKind::Policy, id: Uuid::now_v7() },
                ControlWrite::Create { key: Uuid::now_v7(), fields: &fields },
            )
            .await
            .expect("current policy authoring");
    }};
}

macro_rules! store_checks {
    ($name:ident,$store:ty,$create:ident,$postgres:literal) => {
        #[allow(clippy::too_many_lines)]
        async fn $name(store:&$store) {
            let (payload,secrets,native,organization)=setup!(store,$create);
            let org=organization.id;
            let request=batch(100);
            let key=Uuid::now_v7();
            let before=snapshot!(store,org);
            let imported=store.import_organization_inventory(&native,expires(),ORIGIN,org,key,&request).await.expect("complete hundred-pair import");
            assert!(imported.changed);
            imported.result.validate_for_request(&request).unwrap();
            InventoryImportResult::from_json(&imported.result.to_json().unwrap()).unwrap().validate_for_request(&request).unwrap();
            assert_eq!(imported.sequence,200);
            assert_eq!(imported.view_revision,before.revision+1);
            let after=snapshot!(store,org);
            assert_eq!(after,Snapshot{revision:before.revision+1,sequence:200,objects:200,references:200,versions:200,receipts:1,audit:before.audit+200});
            let rows=sqlx::query("SELECT object_id,sequence,envelope FROM sync_objects WHERE vault_id=$1 ORDER BY sequence")
                .bind(imported.vault.as_bytes().as_slice()).fetch_all(store.pool()).await.unwrap();
            for (index,row) in rows.iter().enumerate() {
                let desired=&request.rows[index/2];
                let id=if index%2==0 {desired.host_id} else {desired.access_profile_id};
                assert_eq!(row.try_get::<Vec<u8>,_>("object_id").unwrap(),id.as_bytes());
                assert_eq!(row.try_get::<i64,_>("sequence").unwrap(),i64::try_from(index).unwrap()+1);
                let object=Object::decode(&row.try_get::<Vec<u8>,_>("envelope").unwrap()).unwrap();
                assert!(object.fields.values().all(|field|field.origin.into_bytes()==native.device_id));
                let (host,login)=desired.inventory_creates().unwrap();
                let fields=if index%2==0 {host.fields} else {login.fields};
                assert_eq!(InventoryFields::from_object(&object).unwrap(),fields);
            }
            let confirmed=store.import_organization_inventory(&native,expires(),ORIGIN,org,key,&request).await.expect("exact original confirmation");
            assert!(!confirmed.changed);
            assert_eq!(snapshot!(store,org),after);
            assert!(matches!(store.import_organization_inventory(&native,expires(),ORIGIN,org,Uuid::now_v7(),&request).await,Err(Error::Conflict)));
            let mut altered=request.clone();
            altered.rows[0].fields.name="Changed name".into();
            assert!(matches!(store.import_organization_inventory(&native,expires(),ORIGIN,org,key,&altered).await,Err(Error::Conflict)));
            assert!(matches!(store.import_organization_inventory(&native,expires(),"https://other.example.test",org,key,&request).await,Err(Error::Conflict)));
            assert!(matches!(store.import_organization_inventory(&native,expires(),ORIGIN,Uuid::now_v7(),key,&request).await,Err(Error::NotFound)));
            assert!(matches!(store.import_organization_inventory(&native,0,ORIGIN,org,key,&request).await,Err(Error::AuthenticationRequired)));
            assert!(matches!(store.import_organization_inventory(&native,expires(),ORIGIN,org,Uuid::now_v7(),&batch(100)).await,Err(Error::Conflict)));
            let mut invalid=batch(2);
            invalid.rows[1].host_id=invalid.rows[0].access_profile_id;
            assert!(matches!(store.import_organization_inventory(&native,expires(),ORIGIN,org,Uuid::now_v7(),&invalid).await,Err(Error::InvalidRequest)));
            let single=InventoryCreateRequest{id:Uuid::now_v7(),fields:InventoryFields::from_json(InventoryType::Host,br#"{"name":"Separate","address":"host.example.test"}"#).unwrap()};
            assert!(matches!(store.write_organization_inventory(&native,expires(),ORIGIN,InventoryTarget{org,kind:InventoryType::Host,id:single.id},InventoryWrite::Create{key,request:&single}).await,Err(Error::Conflict)));
            assert_eq!(snapshot!(store,org),after);

            let browser=browser!(store,payload,secrets,&native.jkt);
            assert!(matches!(store.import_organization_inventory(&browser,expires(),ORIGIN,org,key,&request).await,Err(Error::Conflict)));
            let browser_request=batch(1);
            let browser_key=Uuid::now_v7();
            let browser_result=store.import_organization_inventory(&browser,expires(),ORIGIN,org,browser_key,&browser_request).await.expect("browser import");
            let bytes:Vec<u8>=sqlx::query_scalar("SELECT envelope FROM sync_objects WHERE vault_id=$1 AND object_id=$2")
                .bind(browser_result.vault.as_bytes().as_slice()).bind(browser_request.rows[0].host_id.as_bytes().as_slice()).fetch_one(store.pool()).await.unwrap();
            assert!(Object::decode(&bytes).unwrap().fields.values().all(|field|field.origin.into_bytes()==browser.family_id));
            assert!(!store.import_organization_inventory(&browser,expires(),ORIGIN,org,browser_key,&browser_request).await.unwrap().changed);
            let other=browser!(store,payload,secrets,&native.jkt);
            assert_ne!(browser.family_id,other.family_id);
            assert!(matches!(store.import_organization_inventory(&other,expires(),ORIGIN,org,browser_key,&browser_request).await,Err(Error::Conflict)));
            let browser_state=snapshot!(store,org);
            sqlx::query("UPDATE account_browser_families SET revoked_at_ms=$1 WHERE family_id=$2")
                .bind(now_ms()).bind(browser.family_id.as_slice()).execute(store.pool()).await.unwrap();
            assert!(matches!(store.import_organization_inventory(&browser,expires(),ORIGIN,org,browser_key,&browser_request).await,Err(Error::AuthenticationRequired)));
            assert_eq!(snapshot!(store,org),browser_state);

            for (table,existing) in [("organization_inventory_objects",browser_state.objects),("audit_events",browser_state.audit),("organization_inventory_receipts",0)] {
                let condition=if table=="organization_inventory_receipts" {"TRUE".into()} else {format!("(SELECT COUNT(*) FROM {table} WHERE organization_id=NEW.organization_id)>{existing}")};
                if $postgres {
                    sqlx::query(&format!("CREATE FUNCTION reject_import_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF {condition} THEN RAISE EXCEPTION 'owned import failure'; END IF; RETURN NEW; END; $$"))
                        .execute(store.pool()).await.unwrap();
                    sqlx::query(&format!("CREATE TRIGGER reject_import_write BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION reject_import_write()"))
                        .execute(store.pool()).await.unwrap();
                } else {
                    sqlx::query(&format!("CREATE TRIGGER reject_import_write BEFORE INSERT ON {table} WHEN {condition} BEGIN SELECT RAISE(ABORT,'owned import failure'); END"))
                        .persistent(false).execute(store.pool()).await.unwrap_or_else(|error|panic!("install {table} rollback trigger: {error}"));
                }
                assert!(matches!(store.import_organization_inventory(&native,expires(),ORIGIN,org,Uuid::now_v7(),&batch(2)).await,Err(Error::StorageUnavailable)));
                assert_eq!(snapshot!(store,org),browser_state,"whole batch rollback at {table}");
                sqlx::query(&if $postgres {format!("DROP TRIGGER reject_import_write ON {table}")} else {"DROP TRIGGER reject_import_write".into()})
                    .persistent(false).execute(store.pool()).await.unwrap_or_else(|error|panic!("remove {table} rollback trigger: {error}"));
                if !$postgres {
                    let remaining:i64=sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_schema WHERE type='trigger' AND name='reject_import_write'")
                        .fetch_one(store.pool()).await.unwrap();
                    assert_eq!(remaining,0,"removed {table} rollback trigger");
                }
                if $postgres {sqlx::query("DROP FUNCTION reject_import_write()").execute(store.pool()).await.unwrap();}
            }

            let first=&request.rows[0];
            let host=store.read_organization_inventory(&native,expires(),org,InventoryType::Host,first.host_id).await.unwrap();
            let clear=InventoryReplaceRequest{fields:InventoryFields::from_json(InventoryType::Host,br#"{"name":"Detached Host","address":"host.example.test"}"#).unwrap()};
            store.write_organization_inventory(&native,expires(),ORIGIN,InventoryTarget{org,kind:InventoryType::Host,id:first.host_id},InventoryWrite::Replace{if_match:&host.etag,request:&clear}).await.unwrap();
            let login=store.read_organization_inventory(&native,expires(),org,InventoryType::AccessProfile,first.access_profile_id).await.unwrap();
            store.write_organization_inventory(&native,expires(),ORIGIN,InventoryTarget{org,kind:InventoryType::AccessProfile,id:first.access_profile_id},InventoryWrite::Delete{if_match:&login.etag}).await.unwrap();
            let detached=store.read_organization_inventory(&native,expires(),org,InventoryType::Host,first.host_id).await.unwrap();
            store.write_organization_inventory(&native,expires(),ORIGIN,InventoryTarget{org,kind:InventoryType::Host,id:first.host_id},InventoryWrite::Delete{if_match:&detached.etag}).await.unwrap();
            let after_delete=snapshot!(store,org);
            assert!(!store.import_organization_inventory(&native,expires(),ORIGIN,org,key,&request).await.unwrap().changed);
            assert!(matches!(store.import_organization_inventory(&native,expires(),ORIGIN,org,Uuid::now_v7(),&InventoryImportRequest{rows:vec![first.clone()]}).await,Err(Error::Conflict)));
            assert_eq!(snapshot!(store,org),after_delete);

            policy!(store,&native,org,"forbid(principal, action == Action::\"view_inventory\", resource is Host);");
            let denied=snapshot!(store,org);
            assert!(matches!(store.import_organization_inventory(&native,expires(),ORIGIN,org,Uuid::now_v7(),&batch(1)).await,Err(Error::NotFound)));
            assert!(!store.import_organization_inventory(&native,expires(),ORIGIN,org,key,&request).await.unwrap().changed);
            assert_eq!(snapshot!(store,org),denied,"confirmation does not rebuild historical graph");
            policy!(store,&native,org,"forbid(principal, action == Action::\"manage_inventory\", resource);");
            let denied=snapshot!(store,org);
            assert!(matches!(store.import_organization_inventory(&native,expires(),ORIGIN,org,key,&request).await,Err(Error::PermissionDenied)));
            assert_eq!(snapshot!(store,org),denied);
        }
    };
}

store_checks!(sqlite_checks, SqliteStore, create_sqlite_password_account_in_transaction, false);
#[cfg(feature = "postgres-integration")]
store_checks!(
    postgres_checks,
    PostgresStore,
    create_postgres_password_account_in_transaction,
    true
);

#[tokio::test]
async fn sqlite_import_is_atomic_current_and_original_writer_bound() {
    let directory = std::env::temp_dir().join(format!("scoplen-import-{}", Uuid::new_v4()));
    let store = SqliteStore::open_with_sync_limits(
        &directory.join("store.sqlite"),
        limits(),
        SyncWriteLimits::default(),
    )
    .await
    .unwrap();
    sqlite_checks(&store).await;
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_import_is_atomic_current_and_original_writer_bound() {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned database");
    let admin = sqlx::PgPool::connect(&database).await.unwrap();
    let schema = format!("organization_import_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.unwrap();
    let mut url = url::Url::parse(&database).unwrap();
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let store =
        PostgresStore::connect_with_sync_limits(url.as_str(), limits(), SyncWriteLimits::default())
            .await
            .unwrap();
    postgres_checks(&store).await;
    store.pool().close().await;
    assert!(
        schema.starts_with("organization_import_")
            && schema.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE")).execute(&admin).await.unwrap();
    admin.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_import_lost_commit_ack_confirms_one_complete_original_batch() {
    use std::sync::atomic::Ordering;

    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned database");
    let admin = sqlx::PgPool::connect(&database).await.unwrap();
    let schema = format!("organization_import_commit_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.unwrap();
    let mut url = url::Url::parse(&database).unwrap();
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let store = PostgresStore::connect(url.as_str()).await.unwrap();
    let (_, _, native, organization) =
        setup!(&store, create_postgres_password_account_in_transaction);
    let proxy = lost_commit::LostCommitProxy::start(url.as_str()).await;
    let uncertain = PostgresStore::connect(&proxy.database_url).await.unwrap();
    let request = batch(2);
    let key = Uuid::now_v7();
    let before = snapshot!(store, organization.id);
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        uncertain
            .import_organization_inventory(
                &native,
                expires(),
                ORIGIN,
                organization.id,
                key,
                &request
            )
            .await,
        Err(Error::CommitOutcomeUnknown)
    ));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    let after = snapshot!(store, organization.id);
    assert_eq!(
        after,
        Snapshot {
            revision: before.revision + 1,
            sequence: 4,
            objects: 4,
            references: 4,
            versions: 4,
            receipts: 1,
            audit: before.audit + 4
        }
    );
    let retained:Vec<u8>=sqlx::query_scalar("SELECT response_json FROM organization_inventory_receipts WHERE account_id=$1 AND idempotency_key=$2")
        .bind(native.account_id.as_slice()).bind(key.as_bytes().as_slice()).fetch_one(store.pool()).await.unwrap();
    InventoryImportResult::from_json(&retained).unwrap().validate_for_request(&request).unwrap();
    let confirmed = store
        .import_organization_inventory(&native, expires(), ORIGIN, organization.id, key, &request)
        .await
        .unwrap();
    assert!(!confirmed.changed);
    assert_eq!(confirmed.result.to_json().unwrap(), retained);
    assert_eq!(snapshot!(store, organization.id), after);
    uncertain.pool().close().await;
    drop(proxy);
    store.pool().close().await;
    assert!(
        schema.starts_with("organization_import_commit_")
            && schema.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE")).execute(&admin).await.unwrap();
    admin.close().await;
}
