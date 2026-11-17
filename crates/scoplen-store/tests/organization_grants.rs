// SPDX-License-Identifier: AGPL-3.0-only

#[path = "support/legacy_identity.rs"]
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
    grant::{GrantFields, GrantResource},
    inventory::{InventoryCreateRequest, InventoryFields, InventoryType},
    organization::{OrganizationCreateRequest, OrganizationListQuery},
};
use scoplen_crypto::{
    Ed25519SigningKey, P256SigningKey, PasswordArkWrap, PasswordBootstrapContext, PasswordSecrets,
    SecretBytes, SecretVec, dpop_jwk_thumbprint,
};
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
        grants::{GrantTarget, GrantWrite},
        inventory::{InventoryTarget, InventoryWrite},
    },
};
use tokio::time::Instant;
use uuid::Uuid;

const ORIGIN: &str = "https://grants.example.test";

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

fn password_fixture() -> (AccountRegistrationPayload, PasswordSecrets, CurrentPrincipal) {
    let signing = Ed25519SigningKey::from_bytes(&[1; 32]).expect("Account signing key");
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let device = P256SigningKey::from_bytes(&scalar).expect("Device key");
    let identity = legacy_identity::LegacyIdentity::new(&signing, &device);
    let secrets = PasswordSecrets::create(
        ORIGIN,
        "grant-owner",
        SecretVec::new(b"real encrypted grant test bootstrap".to_vec()),
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
        username: "grant-owner".into(),
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

macro_rules! setup {
    ($store:expr, $create:ident) => {{
        let store = $store;
        store.initialize_account_id_retention(16).await.expect("retention ceiling");
        let (payload, secrets, native) = password_fixture();
        let mut tx = store.pool().begin().await.expect("owned Account transaction");
        let _ =
            $create(&mut tx, ORIGIN, 16, &payload, now_ms()).await.expect("real signed bootstrap");
        tx.commit().await.expect("Account committed");
        let organization = store
            .create_organization(
                &native,
                expires(),
                true,
                Uuid::now_v7(),
                &OrganizationCreateRequest::new("Grant team").expect("team name"),
            )
            .await
            .expect("public team creation");
        let host = Uuid::now_v7();
        let request = InventoryCreateRequest {
            id: host,
            fields: InventoryFields::from_json(
                InventoryType::Host,
                br#"{"name":"Granted Host","address":"host.example.test"}"#,
            )
            .expect("Host fields"),
        };
        let host_resource = store
            .write_organization_inventory(
                &native,
                expires(),
                ORIGIN,
                InventoryTarget { org: organization.id, kind: InventoryType::Host, id: host },
                InventoryWrite::Create { key: Uuid::now_v7(), request: &request },
            )
            .await
            .expect("public Host creation")
            .resource
            .expect("Host Resource");
        (payload, secrets, native, organization, host_resource)
    }};
}

macro_rules! browser {
    ($store:expr, $payload:expr, $secrets:expr, $jkt:expr) => {{
        let source = "192.0.2.51".parse().expect("source");
        $store.ensure_account_probe_key(&Kms).await.expect("password probe key");
        assert_eq!(
            $store
                .admit_account_entry_source(AccountEntryEndpoint::PasswordOptions, source)
                .await
                .expect("browser options source admission"),
            AccountEntryAdmissionDecision::Admitted,
        );
        let options = AccountBrowserPasswordOptionsRequest(AccountPasswordOptionsRequest {
            username: $payload.username.clone(),
        })
        .to_json()
        .expect("browser options");
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
            .expect("real browser password attempt")
            .0;
        let request = AccountBrowserPasswordLoginRequest(AccountPasswordLoginRequest {
            attempt_id: options.attempt_id,
            auth_secret: $secrets.auth_secret().clone(),
        })
        .to_json()
        .expect("browser password proof");
        assert_eq!(
            $store
                .admit_account_entry_source(AccountEntryEndpoint::PasswordLogin, source)
                .await
                .expect("browser login source admission"),
            AccountEntryAdmissionDecision::Admitted,
        );
        let response = $store
            .execute_account_browser_password_login(source, ORIGIN, request, $jkt, &Kms, deadline())
            .await
            .expect("real browser password login");
        let token = AccountBrowserAccessToken::parse(&response.browser.access_token)
            .expect("opaque access token");
        $store
            .current_account_browser_session(&token, ORIGIN)
            .await
            .expect("durable family lookup")
            .expect("current browser identity")
    }};
}

macro_rules! snapshot {
    ($store:expr, $org:expr) => {{
        let revision: Vec<u8> =
            sqlx::query_scalar("SELECT view_revision FROM organizations WHERE id=$1")
                .bind($org.as_bytes().as_slice())
                .fetch_one($store.pool())
                .await
                .expect("revision");
        let audit: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE organization_id=$1")
                .bind($org.as_bytes().as_slice())
                .fetch_one($store.pool())
                .await
                .expect("audit count");
        let rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM organization_grants WHERE organization_id=$1")
                .bind($org.as_bytes().as_slice())
                .fetch_one($store.pool())
                .await
                .expect("Grant count");
        let receipts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM organization_inventory_receipts WHERE organization_id=$1",
        )
        .bind($org.as_bytes().as_slice())
        .fetch_one($store.pool())
        .await
        .expect("receipt count");
        (revision, audit, rows, receipts)
    }};
}

macro_rules! store_checks {
    ($name:ident, $store:ty, $create:ident, $seed:ident, $postgres:literal) => {
        #[allow(clippy::too_many_lines)]
        async fn $name(store: &$store) {
            let (payload, secrets, native, organization, host) = setup!(store, $create);
            let org = organization.id;
            let fields = GrantFields {
                membership: organization.membership.id, host: host.id,
                remote_user: "ops-精确".into(), valid_from: 0, valid_until: None,
            };
            let target = GrantTarget { organization: org, id: Uuid::now_v7() };
            let key = Uuid::now_v7();
            let before = snapshot!(store, org);
            let created = store.write_organization_grant(
                &native, expires(), ORIGIN, target, GrantWrite::Create { key, fields: &fields },
            ).await.expect("Grant creation");
            assert!(created.changed);
            let original = created.response_json.expect("original bytes");
            let resource = GrantResource::from_json(&original).expect("bounded Grant Resource");
            assert_eq!(resource.fields, fields);
            let after_create = snapshot!(store, org);
            assert_eq!(after_create.1, before.1 + 1);
            assert_eq!(after_create.2, before.2 + 1);
            assert_eq!(after_create.3, before.3 + 1);
            assert_ne!(after_create.0, before.0);
            assert_eq!(store.read_organization_grant(&native, expires(), target).await.expect("current read"), resource);
            let confirm = store.write_organization_grant(
                &native, expires(), ORIGIN, target, GrantWrite::Create { key, fields: &fields },
            ).await.expect("exact create confirmation");
            assert!(!confirm.changed);
            assert_eq!(confirm.response_json.as_deref(), Some(original.as_slice()));
            let noop = store.write_organization_grant(
                &native, expires(), ORIGIN, target,
                GrantWrite::Replace { if_match: Some(&resource.etag), fields: &fields },
            ).await.expect("equal fields");
            assert!(!noop.changed);
            assert_eq!(noop.response_json.as_deref(), Some(original.as_slice()));
            assert_eq!(snapshot!(store, org), after_create);

            for (tag, error) in [(None, Error::PreconditionRequired), (Some("W/\"weak\""), Error::InvalidRequest), (Some("\"stale\""), Error::PreconditionFailed)] {
                assert!(matches!(store.write_organization_grant(
                    &native, expires(), ORIGIN, target, GrantWrite::Delete { if_match: tag },
                ).await, Err(actual) if actual==error));
            }
            sqlx::query("UPDATE organization_memberships SET roles_json='[\"member\"]' WHERE id=$1")
                .bind(organization.membership.id.as_bytes().as_slice()).execute(store.pool()).await.expect("current policy change");
            for tag in [None, Some("malformed"), Some(resource.etag.as_str())] {
                assert!(matches!(store.write_organization_grant(
                    &native, expires(), ORIGIN, target, GrantWrite::Delete { if_match: tag },
                ).await, Err(Error::PermissionDenied)));
            }
            assert!(matches!(store.write_organization_grant(
                &native, expires(), ORIGIN, target, GrantWrite::Create { key, fields: &fields },
            ).await, Err(Error::PermissionDenied)));
            assert!(matches!(store.read_organization_grant(&native, expires(), target).await, Err(Error::PermissionDenied)));
            sqlx::query("UPDATE organization_memberships SET roles_json='[\"owner\"]' WHERE id=$1")
                .bind(organization.membership.id.as_bytes().as_slice()).execute(store.pool()).await.expect("restore fixture authority");
            assert_eq!(snapshot!(store, org), after_create);

            let other = store.create_organization(
                &native, expires(), true, Uuid::now_v7(), &OrganizationCreateRequest::new("Other team").expect("name"),
            ).await.expect("other team");
            let foreign_host = Uuid::now_v7();
            let foreign_request = InventoryCreateRequest {
                id: foreign_host,
                fields: InventoryFields::from_json(InventoryType::Host,
                    br#"{"name":"Foreign Host","address":"foreign.example.test"}"#).expect("Host fields"),
            };
            store.write_organization_inventory(&native, expires(), ORIGIN,
                InventoryTarget { org: other.id, kind: InventoryType::Host, id: foreign_host },
                InventoryWrite::Create { key: Uuid::now_v7(), request: &foreign_request },
            ).await.expect("other team's live Host");
            let other_fields = GrantFields {
                membership: other.membership.id, host: foreign_host, ..fields.clone()
            };
            let other_target = GrantTarget { organization: other.id, id: target.id };
            assert!(matches!(store.write_organization_grant(
                &native, expires(), ORIGIN, other_target,
                GrantWrite::Create { key: Uuid::now_v7(), fields: &other_fields },
            ).await, Err(Error::Conflict)), "Grant ids are globally unique across teams");
            assert!(matches!(store.read_organization_grant(&native, expires(), other_target).await, Err(Error::NotFound)));
            let non_host = Uuid::now_v7();
            let group_request = InventoryCreateRequest {
                id: non_host,
                fields: InventoryFields::from_json(InventoryType::HostGroup,
                    br#"{"name":"Not a Host"}"#).expect("HostGroup fields"),
            };
            store.write_organization_inventory(&native, expires(), ORIGIN,
                InventoryTarget { org, kind: InventoryType::HostGroup, id: non_host },
                InventoryWrite::Create { key: Uuid::now_v7(), request: &group_request },
            ).await.expect("same-team non-Host");
            let target_signing = Ed25519SigningKey::from_bytes(&[2;32]).expect("target Account key");
            let mut target_scalar = [0;32];
            target_scalar[31] = 2;
            let target_device = P256SigningKey::from_bytes(&target_scalar).expect("target Device key");
            let target_identity = legacy_identity::LegacyIdentity::new(&target_signing, &target_device);
            legacy_identity::$seed(store.pool(), &target_identity, true).await;
            let inactive_membership = Uuid::now_v7();
            sqlx::query("INSERT INTO organization_memberships (id,organization_id,account_id,status,roles_json,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,'suspended','[\"member\"]',$4,$4)")
                .bind(inactive_membership.as_bytes().as_slice()).bind(org.as_bytes().as_slice())
                .bind(target_identity.account_id.as_bytes().as_slice()).bind(now_ms())
                .execute(store.pool()).await.expect("inactive same-team Membership");
            for invalid in [
                GrantFields { membership: other.membership.id, ..fields.clone() },
                GrantFields { membership: inactive_membership, ..fields.clone() },
                GrantFields { membership: Uuid::now_v7(), ..fields.clone() },
                GrantFields { host: foreign_host, ..fields.clone() },
                GrantFields { host: non_host, ..fields.clone() },
                GrantFields { host: Uuid::now_v7(), ..fields.clone() },
            ] {
                assert!(matches!(store.write_organization_grant(
                    &native, expires(), ORIGIN, GrantTarget { organization: org, id: Uuid::now_v7() },
                    GrantWrite::Create { key: Uuid::now_v7(), fields: &invalid },
                ).await, Err(Error::InvalidRequest)));
            }
            for (origin, supplied_key, supplied_target, supplied_fields) in [
                ("https://other.example.test", key, target, fields.clone()),
                (ORIGIN, key, target, GrantFields { remote_user: "other".into(), ..fields.clone() }),
                (ORIGIN, key, GrantTarget { organization: org, id: Uuid::now_v7() }, fields.clone()),
                (ORIGIN, Uuid::now_v7(), target, fields.clone()),
            ] {
                assert!(matches!(store.write_organization_grant(
                    &native, expires(), origin, supplied_target,
                    GrantWrite::Create { key: supplied_key, fields: &supplied_fields },
                ).await, Err(Error::Conflict)));
            }

            let changed_fields = GrantFields { remote_user: "deploy".into(), ..fields.clone() };
            let replaced = store.write_organization_grant(
                &native, expires(), ORIGIN, target,
                GrantWrite::Replace { if_match: Some(&resource.etag), fields: &changed_fields },
            ).await.expect("complete replacement");
            assert!(replaced.changed);
            let replacement = GrantResource::from_json(&replaced.response_json.expect("replacement bytes")).expect("replacement");
            assert_eq!(replacement.created_at, resource.created_at);
            assert_ne!(replacement.etag, resource.etag);
            let confirmed = store.write_organization_grant(
                &native, expires(), ORIGIN, target, GrantWrite::Create { key, fields: &fields },
            ).await.expect("old creation after replacement");
            assert_eq!(confirmed.response_json.as_deref(), Some(original.as_slice()));
            assert_eq!(store.read_organization_grant(&native, expires(), target).await.expect("replacement remains current"), replacement);

            let future = GrantTarget { organization: org, id: Uuid::now_v7() };
            let expired = GrantTarget { organization: org, id: Uuid::now_v7() };
            let mut guard_hosts=vec![host.clone()];
            for (target, start, end) in [(future, 253_402_300_798, Some(253_402_300_799)), (expired, 0, Some(1))] {
                let request=InventoryCreateRequest{id:Uuid::now_v7(),fields:host.fields.clone()};
                let guard_host=store.write_organization_inventory(
                    &native,expires(),ORIGIN,InventoryTarget{org,kind:InventoryType::Host,id:request.id},
                    InventoryWrite::Create{key:Uuid::now_v7(),request:&request},
                ).await.expect("independent interval Host").resource.expect("Host Resource");
                store.write_organization_grant(
                    &native, expires(), ORIGIN, target, GrantWrite::Create {
                        key: Uuid::now_v7(), fields: &GrantFields { host:guard_host.id, valid_from: start, valid_until: end, ..fields.clone() },
                    },
                ).await.expect("future and expired intervals remain administrable");
                guard_hosts.push(guard_host);
            }
            let first = store.list_organization_grants(&native, expires(), org, OrganizationListQuery { limit: 2, cursor: None })
                .await.expect("first ascending page");
            assert_eq!(first.items.iter().map(|item|item.id).collect::<Vec<_>>(), [target.id, future.id]);
            assert_eq!(first.next_cursor, Some(future.id));
            let second = store.list_organization_grants(&native, expires(), org, OrganizationListQuery { limit: 2, cursor: first.next_cursor })
                .await.expect("second ascending page");
            assert_eq!(second.items.iter().map(|item|item.id).collect::<Vec<_>>(), [expired.id]);
            assert_eq!(second.next_cursor, None);
            for (current,guard_host) in [replacement, first.items[1].clone(), second.items[0].clone()].into_iter().zip(&guard_hosts) {
                assert!(matches!(store.write_organization_inventory(
                    &native, expires(), ORIGIN, InventoryTarget { org, kind: InventoryType::Host, id: guard_host.id },
                    InventoryWrite::Delete { if_match: &guard_host.etag },
                ).await, Err(Error::Conflict)), "current, future and expired Grants each guard the Host");
                assert!(store.write_organization_grant(
                    &native, expires(), ORIGIN, GrantTarget { organization: org, id: current.id },
                    GrantWrite::Delete { if_match: Some(&current.etag) },
                ).await.expect("explicit withdrawal").changed);
                store.write_organization_inventory(
                    &native, expires(), ORIGIN, InventoryTarget { org, kind: InventoryType::Host, id: guard_host.id },
                    InventoryWrite::Delete { if_match: &guard_host.etag },
                ).await.expect("withdrawn references do not guard the Host");
            }
            assert!(matches!(store.read_organization_grant(&native, expires(), target).await, Err(Error::NotFound)));
            assert!(store.list_organization_grants(&native, expires(), org, OrganizationListQuery::default())
                .await.expect("withdrawn directory").items.is_empty());
            let withdrawn = snapshot!(store, org);
            assert!(matches!(store.write_organization_grant(
                &native, expires(), ORIGIN, other_target,
                GrantWrite::Create { key: Uuid::now_v7(), fields: &other_fields },
            ).await, Err(Error::Conflict)), "withdrawal never frees a Grant id in another team");
            assert_eq!(store.write_organization_grant(
                &native, expires(), ORIGIN, target, GrantWrite::Create { key, fields: &fields },
            ).await.expect("original receipt survives withdrawal and missing Host").response_json.as_deref(), Some(original.as_slice()));
            assert_eq!(snapshot!(store, org), withdrawn);
            sqlx::query("UPDATE organization_inventory_receipts SET created_at_ms=1,expires_at_ms=86400001 WHERE account_id=$1 AND idempotency_key=$2")
                .bind(native.account_id.as_slice()).bind(key.as_bytes().as_slice()).execute(store.pool()).await.expect("expired receipt");
            assert!(matches!(store.write_organization_grant(
                &native, expires(), ORIGIN, target, GrantWrite::Create { key, fields: &fields },
            ).await, Err(Error::Conflict)));

            let browser_host = Uuid::now_v7();
            let request = InventoryCreateRequest { id: browser_host, fields: InventoryFields::from_json(
                InventoryType::Host, br#"{"name":"Browser Host","address":"browser.example.test"}"#,
            ).expect("Host fields") };
            store.write_organization_inventory(&native, expires(), ORIGIN,
                InventoryTarget { org, kind: InventoryType::Host, id: browser_host },
                InventoryWrite::Create { key: Uuid::now_v7(), request: &request },
            ).await.expect("browser test Host");
            let browser = browser!(store, payload, secrets, &native.jkt);
            let browser_target = GrantTarget { organization: org, id: Uuid::now_v7() };
            let browser_key = Uuid::now_v7();
            let browser_fields = GrantFields { host: browser_host, ..fields.clone() };
            let browser_created = store.write_organization_grant(
                &browser, expires(), ORIGIN, browser_target, GrantWrite::Create { key: browser_key, fields: &browser_fields },
            ).await.expect("real browser Grant creation");
            let event: Vec<u8> = sqlx::query_scalar("SELECT event_bytes FROM audit_events WHERE organization_id=$1 ORDER BY sequence DESC LIMIT 1")
                .bind(org.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("attributable audit");
            let event: serde_json::Value = serde_json::from_slice(&event).expect("audit body");
            assert_eq!(event["browser_family_id"], Uuid::from_bytes(browser.family_id).to_string());
            assert!(event.get("device_id").is_none());
            assert_eq!(event["action"], "organization.grants_created");
            assert_eq!(event["object_id"], browser_target.id.to_string());
            let browser_state = snapshot!(store, org);
            let confirmation = store.write_organization_grant(
                &browser, expires(), ORIGIN, browser_target, GrantWrite::Create { key: browser_key, fields: &browser_fields },
            ).await.expect("same browser family confirmation");
            assert!(!confirmation.changed);
            assert_eq!(confirmation.response_json, browser_created.response_json);
            assert!(matches!(store.write_organization_grant(
                &native, expires(), ORIGIN, browser_target, GrantWrite::Create { key: browser_key, fields: &browser_fields },
            ).await, Err(Error::Conflict)));
            let other_browser = browser!(store, payload, secrets, &native.jkt);
            assert_ne!(other_browser.family_id, browser.family_id);
            assert!(matches!(store.write_organization_grant(
                &other_browser, expires(), ORIGIN, browser_target, GrantWrite::Create { key: browser_key, fields: &browser_fields },
            ).await, Err(Error::Conflict)));
            assert_eq!(snapshot!(store, org), browser_state);
            sqlx::query("UPDATE account_browser_families SET revoked_at_ms=$1 WHERE family_id=$2")
                .bind(now_ms()).bind(browser.family_id.as_slice()).execute(store.pool()).await.expect("real family revocation");
            assert!(matches!(store.read_organization_grant(&browser, expires(), browser_target).await, Err(Error::AuthenticationRequired)));

            let rollback_target = GrantTarget { organization: org, id: Uuid::now_v7() };
            let rollback_key = Uuid::now_v7();
            let before_failure = snapshot!(store, org);
            if $postgres {
                sqlx::query("CREATE FUNCTION reject_grant_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned audit failure'; END; $$")
                    .execute(store.pool()).await.expect("owned failure function");
                sqlx::query("CREATE TRIGGER reject_grant_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_grant_audit()")
                    .execute(store.pool()).await.expect("owned audit trigger");
            } else {
                sqlx::query("CREATE TRIGGER reject_grant_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'owned audit failure'); END")
                    .execute(store.pool()).await.expect("owned audit trigger");
            }
            assert!(matches!(store.write_organization_grant(
                &native, expires(), ORIGIN, rollback_target, GrantWrite::Create { key: rollback_key, fields: &browser_fields },
            ).await, Err(Error::StorageUnavailable)));
            assert_eq!(snapshot!(store, org), before_failure, "failed audit rolls back rows, receipt and revision");
            sqlx::query(if $postgres { "DROP TRIGGER reject_grant_audit ON audit_events" } else { "DROP TRIGGER reject_grant_audit" })
                .execute(store.pool()).await.expect("remove owned trigger");
            if $postgres {
                sqlx::query("DROP FUNCTION reject_grant_audit()").execute(store.pool()).await.expect("remove owned function");
            }
            store.write_organization_grant(
                &native, expires(), ORIGIN, rollback_target, GrantWrite::Create { key: rollback_key, fields: &browser_fields },
            ).await.expect("same create succeeds after rollback");
            let mut corrupt = store.read_organization_grant(&native, expires(), rollback_target).await.expect("current intact row");
            corrupt.fields.host = Uuid::now_v7();
            sqlx::query("UPDATE organization_grants SET response_json=$1 WHERE organization_id=$2 AND id=$3")
                .bind(corrupt.to_json().expect("valid but mismatched projection")).bind(org.as_bytes().as_slice())
                .bind(rollback_target.id.as_bytes().as_slice()).execute(store.pool()).await.expect("owned corruption fixture");
            assert!(matches!(store.read_organization_grant(&native, expires(), rollback_target).await, Err(Error::StorageUnavailable)));
        }
    };
}

store_checks!(
    sqlite_checks,
    SqliteStore,
    create_sqlite_password_account_in_transaction,
    seed_sqlite,
    false
);
#[cfg(feature = "postgres-integration")]
store_checks!(
    postgres_checks,
    PostgresStore,
    create_postgres_password_account_in_transaction,
    seed_postgres,
    true
);

#[tokio::test]
async fn sqlite_grants_keep_original_receipts_current_authority_and_atomic_audit() {
    let directory = std::env::temp_dir().join(format!("scoplen-grants-{}", Uuid::new_v4()));
    let store =
        SqliteStore::open(&directory.join("store.sqlite")).await.expect("owned SQLite store");
    sqlite_checks(&store).await;
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_grants_keep_original_receipts_current_authority_and_atomic_audit() {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned database");
    let admin = sqlx::PgPool::connect(&database).await.expect("admin");
    let schema = format!("organization_grants_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("database URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let store = PostgresStore::connect(url.as_str()).await.expect("owned PostgreSQL Store");
    postgres_checks(&store).await;
    store.pool().close().await;
    assert!(
        schema.starts_with("organization_grants_")
            && schema.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .expect("remove owned schema");
    admin.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_grant_lost_commit_ack_retains_one_original_create_without_resurrection() {
    use std::sync::atomic::Ordering;

    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned database");
    let admin = sqlx::PgPool::connect(&database).await.expect("admin");
    let schema = format!("organization_grant_commit_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("database URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let store = PostgresStore::connect(url.as_str()).await.expect("direct PostgreSQL Store");
    let (_, _, native, organization, host) =
        setup!(&store, create_postgres_password_account_in_transaction);
    let proxy = lost_commit::LostCommitProxy::start(url.as_str()).await;
    let uncertain = PostgresStore::connect(&proxy.database_url).await.expect("proxied Store");
    let target = GrantTarget { organization: organization.id, id: Uuid::now_v7() };
    let key = Uuid::now_v7();
    let fields = GrantFields {
        membership: organization.membership.id,
        host: host.id,
        remote_user: "ops".into(),
        valid_from: 0,
        valid_until: None,
    };
    let before = snapshot!(store, organization.id);
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        uncertain
            .write_organization_grant(
                &native,
                expires(),
                ORIGIN,
                target,
                GrantWrite::Create { key, fields: &fields },
            )
            .await,
        Err(Error::CommitOutcomeUnknown)
    ));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    let after = snapshot!(store, organization.id);
    assert_eq!((after.1, after.2, after.3), (before.1 + 1, before.2 + 1, before.3 + 1));
    let retained: Vec<u8> = sqlx::query_scalar("SELECT response_json FROM organization_inventory_receipts WHERE account_id=$1 AND idempotency_key=$2")
        .bind(native.account_id.as_slice()).bind(key.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("committed original receipt");
    let confirmed = store
        .write_organization_grant(
            &native,
            expires(),
            ORIGIN,
            target,
            GrantWrite::Create { key, fields: &fields },
        )
        .await
        .expect("exact original confirmation");
    assert!(!confirmed.changed);
    assert_eq!(confirmed.response_json.as_deref(), Some(retained.as_slice()));
    assert_eq!(snapshot!(store, organization.id), after);

    let current = GrantResource::from_json(&retained).expect("original Resource");
    let changed = GrantFields { remote_user: "deploy".into(), ..fields.clone() };
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        uncertain
            .write_organization_grant(
                &native,
                expires(),
                ORIGIN,
                target,
                GrantWrite::Replace { if_match: Some(&current.etag), fields: &changed },
            )
            .await,
        Err(Error::UpdateCommitOutcomeUnknown)
    ));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 2);
    let current = store
        .read_organization_grant(&native, expires(), target)
        .await
        .expect("replacement committed");
    assert_eq!(current.fields, changed);
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        uncertain
            .write_organization_grant(
                &native,
                expires(),
                ORIGIN,
                target,
                GrantWrite::Delete { if_match: Some(&current.etag) },
            )
            .await,
        Err(Error::UpdateCommitOutcomeUnknown)
    ));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 3);
    assert!(matches!(
        store.read_organization_grant(&native, expires(), target).await,
        Err(Error::NotFound)
    ));
    let withdrawn = snapshot!(store, organization.id);
    assert_eq!(
        store
            .write_organization_grant(
                &native,
                expires(),
                ORIGIN,
                target,
                GrantWrite::Create { key, fields: &fields },
            )
            .await
            .expect("original confirmation after lost withdrawal ACK")
            .response_json
            .as_deref(),
        Some(retained.as_slice())
    );
    assert_eq!(snapshot!(store, organization.id), withdrawn);
    uncertain.pool().close().await;
    drop(proxy);
    store.pool().close().await;
    assert!(
        schema.starts_with("organization_grant_commit_")
            && schema.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .expect("remove owned schema");
    admin.close().await;
}
