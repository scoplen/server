// SPDX-License-Identifier: AGPL-3.0-only

#[path = "support/legacy_identity.rs"]
mod legacy_identity;
#[cfg(feature = "postgres-integration")]
#[path = "support/lost_commit.rs"]
mod lost_commit;
mod support;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scoplen_api::{
    access_request::{
        AccessRequestCreateRequest, AccessRequestDecisionRequest, AccessRequestFields,
        AccessRequestListQuery, AccessRequestOutcome, AccessRequestResource, AccessRequestStatus,
        AccessRequestView,
    },
    audit::parse_audit_timestamp,
    group_policy::PolicyFields,
};
use scoplen_api::{
    account_admission::{
        AccountPasswordLoginRequest, AccountPasswordOptionsRequest, AccountRegistrationPayload,
    },
    account_browser::{
        AccountBrowserAccessToken, AccountBrowserPasswordLoginRequest,
        AccountBrowserPasswordOptionsRequest,
    },
    inventory::{InventoryCreateRequest, InventoryFields, InventoryType},
    organization::{OrganizationCreateRequest, OrganizationListQuery},
};
use scoplen_crypto::{
    Ed25519SigningKey, P256SigningKey, PasswordArkWrap, PasswordBootstrapContext, PasswordSecrets,
    SecretBytes, SecretVec, dpop_jwk_thumbprint,
};
use scoplen_store::organizations::{
    access_requests::{AccessRequestTarget, AccessRequestWrite},
    group_policy::{ControlFields, ControlKind, ControlTarget, ControlWrite},
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

const ORIGIN: &str = "https://requests.example.test";

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

fn password_fixture(
    username: &str,
) -> (AccountRegistrationPayload, PasswordSecrets, CurrentPrincipal) {
    let signing = Ed25519SigningKey::from_bytes(&[1; 32]).expect("Account signing key");
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let device = P256SigningKey::from_bytes(&scalar).expect("Device key");
    let identity = legacy_identity::LegacyIdentity::new(&signing, &device);
    let secrets = PasswordSecrets::create(
        ORIGIN,
        username,
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
        username: username.into(),
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
        let (payload, secrets, native) = password_fixture("request-owner");
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

macro_rules! add_actor {
    ($store:expr,$create:ident,$org:expr,$name:expr,$roles:expr) => {{
        let (payload,secrets,principal) = password_fixture($name);
        let mut tx = $store.pool().begin().await.unwrap();
        $create(&mut tx,ORIGIN,16,&payload,now_ms()).await.unwrap();
        let membership = Uuid::now_v7();
        sqlx::query("INSERT INTO organization_memberships (id,organization_id,account_id,status,roles_json,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,'active',$4,$5,$5)")
            .bind(membership.as_bytes().as_slice()).bind($org.as_bytes().as_slice()).bind(payload.account_id.as_bytes().as_slice())
            .bind($roles).bind(now_ms()).execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
        (payload,secrets,principal,membership)
    }};
}

macro_rules! policy {
    ($store:expr,$owner:expr,$org:expr,$source:expr) => {{
        let fields = ControlFields::Policy(PolicyFields {
            name: "Request fixture".into(),
            source: $source,
            enabled: true,
        });
        let id = Uuid::now_v7();
        $store
            .write_organization_control(
                $owner,
                expires(),
                ORIGIN,
                ControlTarget { organization: $org, kind: ControlKind::Policy, id },
                ControlWrite::Create { key: Uuid::now_v7(), fields: &fields },
            )
            .await
            .expect("public policy authoring");
        id
    }};
}

macro_rules! snapshot {
    ($store:expr,$org:expr) => {{
        let revision: Vec<u8> = sqlx::query_scalar("SELECT view_revision FROM organizations WHERE id=$1")
            .bind($org.as_bytes().as_slice()).fetch_one($store.pool()).await.unwrap();
        let counts: (i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT COUNT(*) FROM audit_events WHERE organization_id=$1),(SELECT COUNT(*) FROM organization_grants WHERE organization_id=$1),(SELECT COUNT(*) FROM organization_access_requests WHERE organization_id=$1),(SELECT COUNT(*) FROM organization_inventory_receipts WHERE organization_id=$1)")
            .bind($org.as_bytes().as_slice()).fetch_one($store.pool()).await.unwrap();
        (u64::from_be_bytes(revision.try_into().unwrap()),counts.0,counts.1,counts.2,counts.3)
    }};
}

macro_rules! create_request {
    ($store:expr,$actor:expr,$org:expr,$fields:expr) => {{
        let request = AccessRequestCreateRequest { id: Uuid::now_v7(), fields: $fields.clone() };
        let target = AccessRequestTarget { organization: $org, id: request.id };
        let key = Uuid::now_v7();
        let response = $store
            .write_organization_access_request(
                $actor,
                expires(),
                ORIGIN,
                target,
                AccessRequestWrite::Create { key, request: &request },
            )
            .await
            .expect("create request");
        let resource = AccessRequestResource::from_json(&response.response_json).unwrap();
        (target, key, request, resource, response.response_json)
    }};
}

macro_rules! overdue {
    ($store:expr,$target:expr,$resource:expr) => {{
        let mut resource = $resource.clone();
        let expiry = now_ms()-10;
        let created = expiry-86_400_000;
        resource.created_at = scoplen_api::audit::format_audit_timestamp(created).unwrap();
        resource.updated_at = resource.created_at.clone();
        resource.expires_at = scoplen_api::audit::format_audit_timestamp(expiry).unwrap();
        resource.etag = "\"overdue-fixture\"".into();
        let bytes = resource.to_json().unwrap();
        sqlx::query("UPDATE organization_access_requests SET response_json=$1,created_at_ms=$2,updated_at_ms=$2,expires_at_ms=$3 WHERE organization_id=$4 AND id=$5")
            .bind(bytes).bind(created).bind(expiry).bind($target.organization.as_bytes().as_slice()).bind($target.id.as_bytes().as_slice())
            .execute($store.pool()).await.unwrap();
        resource
    }};
}

macro_rules! request_checks {
    ($name:ident,$store:ty,$create:ident,$seed:ident,$postgres:literal) => {
        #[allow(clippy::too_many_lines)]
        async fn $name(store: &$store) {
            let (_,_,owner,organization,host) = setup!(store,$create);
            let org = organization.id;
            let (payload,secrets,requester,membership) = add_actor!(store,$create,org,"request-member","[\"member\"]");
            let (_,_,approver,_) = add_actor!(store,$create,org,"request-approver","[\"approver\"]");
            let fields = AccessRequestFields {host:host.id,remote_user:"deploy".into(),duration_seconds:120,reason:"maintenance".into()};
            let outsider_signing = Ed25519SigningKey::from_bytes(&[4;32]).unwrap();
            let mut outsider_scalar = [0;32];
            outsider_scalar[31] = 4;
            let outsider_device = P256SigningKey::from_bytes(&outsider_scalar).unwrap();
            let outsider_identity = legacy_identity::LegacyIdentity::new(&outsider_signing,&outsider_device);
            legacy_identity::$seed(store.pool(),&outsider_identity,true).await;
            let outsider = CurrentPrincipal {
                account_id:outsider_identity.account_id.into_bytes(),
                device_id:outsider_identity.device_certificate.device_id.into_bytes(),
                signing_public_key:outsider_device.public_key_sec1(),
                jkt:dpop_jwk_thumbprint(&outsider_device.public_key_sec1()).unwrap(),
                certificate:outsider_identity.device_certificate.encode().unwrap(),
            };
            assert!(matches!(store.check_organization_access_request(&outsider,expires(),org,&fields).await,Err(Error::NotFound)),"an accepted Account outside the tenant cannot probe eligibility");
            assert!(matches!(store.check_organization_access_request(&requester,expires(),org,&fields).await,Err(Error::NotFound)));
            let view_policy = policy!(store,&owner,org,format!("permit(principal, action == Action::\"view_inventory\", resource == Host::\"{}\");",host.id));
            let before = snapshot!(store,org);
            assert!(!store.check_organization_access_request(&requester,expires(),org,&fields).await.unwrap().allowed);
            assert_eq!(snapshot!(store,org),before,"check never mutates business state");
            let denied = AccessRequestCreateRequest {id:Uuid::now_v7(),fields:fields.clone()};
            assert!(matches!(store.write_organization_access_request(&requester,expires(),ORIGIN,AccessRequestTarget {organization:org,id:denied.id},
                AccessRequestWrite::Create {key:Uuid::now_v7(),request:&denied}).await,Err(Error::PermissionDenied)));
            let request_source = format!("permit(principal, action == Action::\"request_access\", resource == Host::\"{}\") when {{ context.membership == Membership::\"{}\" && context.duration_seconds <= 120 && context.reason == \"maintenance\" }};",host.id,membership);
            let request_policy = policy!(store,&owner,org,request_source.clone());
            assert!(store.check_organization_access_request(&requester,expires(),org,&fields).await.unwrap().allowed);
            let altered = AccessRequestFields {duration_seconds:121,..fields.clone()};
            assert!(!store.check_organization_access_request(&requester,expires(),org,&altered).await.unwrap().allowed);
            sqlx::query("UPDATE organization_policies SET source='damaged Cedar' WHERE organization_id=$1 AND id=$2")
                .bind(org.as_bytes().as_slice()).bind(request_policy.as_bytes().as_slice()).execute(store.pool()).await.unwrap();
            assert!(matches!(store.check_organization_access_request(&requester,expires(),org,&fields).await,Err(Error::StorageUnavailable)));
            sqlx::query("UPDATE organization_policies SET source=$1 WHERE organization_id=$2 AND id=$3")
                .bind(&request_source).bind(org.as_bytes().as_slice()).bind(request_policy.as_bytes().as_slice()).execute(store.pool()).await.unwrap();

            let before = snapshot!(store,org);
            let (target,key,request,pending,original) = create_request!(store,&requester,org,fields);
            assert_eq!(pending.requester_account_id,payload.account_id);
            assert_eq!(pending.requester_membership_id,membership);
            let foreign = store.create_organization(&requester,expires(),true,Uuid::now_v7(),
                &OrganizationCreateRequest::new("Other request team").unwrap()).await.unwrap();
            assert!(matches!(store.read_organization_access_request(&requester,expires(),AccessRequestTarget {organization:foreign.id,id:target.id}).await,Err(Error::NotFound)));
            assert!(matches!(store.check_organization_access_request(&requester,expires(),foreign.id,&fields).await,Err(Error::NotFound)));
            assert_eq!(parse_audit_timestamp(&pending.expires_at).unwrap()-parse_audit_timestamp(&pending.created_at).unwrap(),86_400_000);
            let after_create = snapshot!(store,org);
            assert_eq!(after_create,(before.0,before.1+1,before.2,before.3+1,before.4+1));
            assert_eq!(store.read_organization_access_request(&requester,expires(),target).await.unwrap(),pending);
            assert_eq!(store.read_organization_access_request(&approver,expires(),target).await.unwrap(),pending);
            let mine = AccessRequestListQuery {view:AccessRequestView::Mine,page:OrganizationListQuery::default()};
            let inbox = AccessRequestListQuery {view:AccessRequestView::Approvals,page:OrganizationListQuery::default()};
            assert_eq!(store.list_organization_access_requests(&requester,expires(),org,&mine).await.unwrap().items,vec![pending.clone()]);
            assert_eq!(store.list_organization_access_requests(&approver,expires(),org,&inbox).await.unwrap().items,vec![pending.clone()]);
            assert!(store.list_organization_access_requests(&requester,expires(),org,&inbox).await.unwrap().items.is_empty());
            assert!(matches!(store.read_organization_grant(&approver,expires(),GrantTarget {organization:org,id:Uuid::now_v7()}).await,Err(Error::PermissionDenied)),"approver has no manage_policy");
            let approve = AccessRequestDecisionRequest {decision:AccessRequestOutcome::Approve};
            for tag in [None,Some("malformed"),Some(pending.etag.as_str())] {
                assert!(matches!(store.write_organization_access_request(&requester,expires(),ORIGIN,target,
                    AccessRequestWrite::Decide {key:Uuid::now_v7(),if_match:tag,request:approve}).await,Err(Error::NotFound)),"self authority precedes preconditions");
            }
            for (tag,error) in [(None,Error::PreconditionRequired),(Some("W/\"weak\""),Error::InvalidRequest),(Some("\"stale\""),Error::PreconditionFailed)] {
                assert!(matches!(store.write_organization_access_request(&approver,expires(),ORIGIN,target,
                    AccessRequestWrite::Decide {key:Uuid::now_v7(),if_match:tag,request:approve}).await,Err(actual) if actual==error));
            }
            let (probe,_,_,probe_pending,_) = create_request!(store,&requester,org,fields);
            let transient_policy = policy!(store,&owner,org,format!("forbid(principal, action == Action::\"approve_access\", resource == AccessRequest::\"{}\") when {{ AccessRequest::\"{}\".requester == Account::\"{}\" }};",probe.id,target.id,payload.account_id));
            assert!(matches!(store.read_organization_access_request(&approver,expires(),probe).await,Err(Error::StorageUnavailable)));
            assert!(matches!(store.list_organization_access_requests(&approver,expires(),org,&inbox).await,Err(Error::StorageUnavailable)),"a list cannot inherit an earlier row's AccessRequest projection");
            sqlx::query("UPDATE organization_policies SET enabled=0 WHERE id=$1").bind(transient_policy.as_bytes().as_slice()).execute(store.pool()).await.unwrap();
            store.write_organization_access_request(&requester,expires(),ORIGIN,probe,
                AccessRequestWrite::Cancel {key:Uuid::now_v7(),if_match:Some(&probe_pending.etag)}).await.unwrap();
            let browser = browser!(store,payload,secrets,&requester.jkt);
            assert!(matches!(store.write_organization_access_request(&browser,expires(),ORIGIN,target,
                AccessRequestWrite::Create {key,request:&request}).await,Err(Error::Conflict)),"a browser cannot confirm Device bytes");
            let second_family = browser!(store,payload,secrets,&requester.jkt);
            let (browser_target,browser_key,browser_request,browser_pending,browser_original) = create_request!(store,&browser,org,fields);
            assert!(matches!(store.write_organization_access_request(&second_family,expires(),ORIGIN,browser_target,
                AccessRequestWrite::Create {key:browser_key,request:&browser_request}).await,Err(Error::Conflict)));
            let cancelled = store.write_organization_access_request(&browser,expires(),ORIGIN,browser_target,
                AccessRequestWrite::Cancel {key:Uuid::now_v7(),if_match:Some(&browser_pending.etag)}).await.unwrap();
            assert!(!cancelled.view_changed);
            assert_eq!(store.write_organization_access_request(&browser,expires(),ORIGIN,browser_target,
                AccessRequestWrite::Create {key:browser_key,request:&browser_request}).await.unwrap().response_json,browser_original);

            let decision_key = Uuid::now_v7();
            let before_approval = snapshot!(store,org);
            if $postgres {
                sqlx::query("CREATE FUNCTION reject_request_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF convert_from(NEW.event_bytes,'UTF8')::jsonb->>'action'='organization.access_request_approved' THEN RAISE EXCEPTION 'owned request audit failure'; END IF; RETURN NEW; END; $$")
                    .execute(store.pool()).await.unwrap();
                sqlx::query("CREATE TRIGGER reject_request_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_request_audit()")
                    .execute(store.pool()).await.unwrap();
            } else {
                sqlx::query("CREATE TRIGGER reject_request_audit BEFORE INSERT ON audit_events WHEN CAST(NEW.event_bytes AS TEXT) LIKE '%organization.access_request_approved%' BEGIN SELECT RAISE(ABORT,'owned request audit failure'); END")
                    .execute(store.pool()).await.unwrap();
            }
            assert!(matches!(store.write_organization_access_request(&approver,expires(),ORIGIN,target,
                AccessRequestWrite::Decide {key:decision_key,if_match:Some(&pending.etag),request:approve}).await,Err(Error::StorageUnavailable)));
            assert_eq!(snapshot!(store,org),before_approval,"audit failure rolls back request, Grant, revision, audit and receipt");
            sqlx::query(if $postgres {"DROP TRIGGER reject_request_audit ON audit_events"} else {"DROP TRIGGER reject_request_audit"}).execute(store.pool()).await.unwrap();
            if $postgres {sqlx::query("DROP FUNCTION reject_request_audit()").execute(store.pool()).await.unwrap();}
            let approved = store.write_organization_access_request(&approver,expires(),ORIGIN,target,
                AccessRequestWrite::Decide {key:decision_key,if_match:Some(&pending.etag),request:approve}).await.unwrap();
            assert!(approved.changed && approved.view_changed);
            let after = snapshot!(store,org);
            assert_eq!(after,(before_approval.0+1,before_approval.1+2,before_approval.2+1,before_approval.3,before_approval.4+1));
            let approved_resource = AccessRequestResource::from_json(&approved.response_json).unwrap();
            let history = approved_resource.grant.as_ref().unwrap();
            assert_eq!(history.valid_from,u64::try_from(parse_audit_timestamp(&approved_resource.decision.as_ref().unwrap().decided_at).unwrap()/1000).unwrap());
            assert_eq!(history.valid_until-history.valid_from,120);
            let grant_target = GrantTarget {organization:org,id:history.id};
            let grant = store.read_organization_grant(&owner,expires(),grant_target).await.unwrap();
            assert_eq!((grant.fields.membership,grant.fields.host,grant.fields.remote_user.as_str()),(membership,host.id,"deploy"));
            assert_eq!(store.write_organization_access_request(&requester,expires(),ORIGIN,target,
                AccessRequestWrite::Create {key,request:&request}).await.unwrap().response_json,original);
            store.write_organization_grant(&owner,expires(),ORIGIN,grant_target,GrantWrite::Delete {if_match:Some(&grant.etag)}).await.unwrap();
            let before_confirm = snapshot!(store,org);
            let confirmed = store.write_organization_access_request(&approver,expires(),ORIGIN,target,
                AccessRequestWrite::Decide {key:decision_key,if_match:Some(&pending.etag),request:approve}).await.unwrap();
            assert!(!confirmed.changed && !confirmed.view_changed);
            assert_eq!(confirmed.response_json,approved.response_json);
            assert_eq!(snapshot!(store,org),before_confirm,"confirmation never resurrects a Grant");
            assert!(matches!(store.write_organization_access_request(&approver,expires(),ORIGIN,target,
                AccessRequestWrite::Decide {key:decision_key,if_match:Some(&pending.etag),request:AccessRequestDecisionRequest {decision:AccessRequestOutcome::Deny}}).await,Err(Error::Conflict)));

            let (late,_,_,pending_late,_) = create_request!(store,&requester,org,fields);
            let pending_late = overdue!(store,late,pending_late);
            let before_expiry = snapshot!(store,org);
            assert!(matches!(store.write_organization_access_request(&approver,expires(),ORIGIN,late,
                AccessRequestWrite::Decide {key:Uuid::now_v7(),if_match:Some(&pending_late.etag),request:approve}).await,Err(Error::Conflict)));
            assert_eq!(store.read_organization_access_request(&requester,expires(),late).await.unwrap(),pending_late,"ordinary reads retain persisted Pending/ETag");
            assert!(store.list_organization_access_requests(&approver,expires(),org,&inbox).await.unwrap().items.is_empty());
            assert_eq!(store.expire_organization_access_requests().await.unwrap(),1);
            assert_eq!(store.expire_organization_access_requests().await.unwrap(),0);
            let after_expiry = snapshot!(store,org);
            assert_eq!(after_expiry,(before_expiry.0,before_expiry.1+1,before_expiry.2,before_expiry.3,before_expiry.4));
            assert_eq!(store.read_organization_access_request(&requester,expires(),late).await.unwrap().status,AccessRequestStatus::Expired);

            let (stale,_,_,stale_pending,_) = create_request!(store,&requester,org,fields);
            sqlx::query("UPDATE organization_memberships SET status='suspended' WHERE id=$1").bind(membership.as_bytes().as_slice()).execute(store.pool()).await.unwrap();
            assert!(matches!(store.write_organization_access_request(&approver,expires(),ORIGIN,stale,
                AccessRequestWrite::Decide {key:Uuid::now_v7(),if_match:Some(&stale_pending.etag),request:approve}).await,Err(Error::Conflict)));
            sqlx::query("UPDATE organization_memberships SET status='active' WHERE id=$1").bind(membership.as_bytes().as_slice()).execute(store.pool()).await.unwrap();
            sqlx::query("UPDATE organization_policies SET enabled=0 WHERE id=$1").bind(request_policy.as_bytes().as_slice()).execute(store.pool()).await.unwrap();
            assert!(matches!(store.write_organization_access_request(&approver,expires(),ORIGIN,stale,
                AccessRequestWrite::Decide {key:Uuid::now_v7(),if_match:Some(&stale_pending.etag),request:approve}).await,Err(Error::Conflict)));
            sqlx::query("UPDATE organization_policies SET enabled=1 WHERE id=$1").bind(request_policy.as_bytes().as_slice()).execute(store.pool()).await.unwrap();
            let before_deny = snapshot!(store,org);
            let denied = store.write_organization_access_request(&approver,expires(),ORIGIN,stale,
                AccessRequestWrite::Decide {key:Uuid::now_v7(),if_match:Some(&stale_pending.etag),request:AccessRequestDecisionRequest {decision:AccessRequestOutcome::Deny}}).await.unwrap();
            assert!(!denied.view_changed);
            let after_deny = snapshot!(store,org);
            assert_eq!(after_deny,(before_deny.0,before_deny.1+1,before_deny.2,before_deny.3,before_deny.4+1));

            let (race,_,_,race_pending,_) = create_request!(store,&requester,org,fields);
            let (decision,cancel) = tokio::join!(
                store.write_organization_access_request(&approver,expires(),ORIGIN,race,AccessRequestWrite::Decide {key:Uuid::now_v7(),if_match:Some(&race_pending.etag),request:AccessRequestDecisionRequest {decision:AccessRequestOutcome::Deny}}),
                store.write_organization_access_request(&requester,expires(),ORIGIN,race,AccessRequestWrite::Cancel {key:Uuid::now_v7(),if_match:Some(&race_pending.etag)})
            );
            assert_eq!(usize::from(decision.is_ok())+usize::from(cancel.is_ok()),1,"one terminal winner");
            let loser = if decision.is_ok() {cancel.err()} else {decision.err()};
            assert!(matches!(loser,Some(Error::PreconditionFailed|Error::Conflict)));

            let (cancel_target,cancel_key,cancel_request,cancel_pending,_) = create_request!(store,&requester,org,fields);
            assert!(matches!(store.write_organization_inventory(&owner,expires(),ORIGIN,
                InventoryTarget {org,kind:InventoryType::Host,id:host.id},InventoryWrite::Delete {if_match:&host.etag}).await,Err(Error::Conflict)));
            sqlx::query("UPDATE organization_policies SET enabled=0 WHERE id=$1").bind(view_policy.as_bytes().as_slice()).execute(store.pool()).await.unwrap();
            assert_eq!(store.read_organization_access_request(&requester,expires(),cancel_target).await.unwrap(),cancel_pending);
            assert!(matches!(store.read_organization_access_request(&approver,expires(),cancel_target).await,Err(Error::NotFound)));
            assert!(matches!(store.write_organization_access_request(&approver,expires(),ORIGIN,target,
                AccessRequestWrite::Decide {key:decision_key,if_match:Some(&pending.etag),request:approve}).await,Err(Error::NotFound)),"current routing precedes historical approval receipt");
            assert!(store.list_organization_access_requests(&approver,expires(),org,&inbox).await.unwrap().items.is_empty());
            let before_cancel = snapshot!(store,org);
            let cancel_op = Uuid::now_v7();
            let cancelled = store.write_organization_access_request(&requester,expires(),ORIGIN,cancel_target,
                AccessRequestWrite::Cancel {key:cancel_op,if_match:Some(&cancel_pending.etag)}).await.unwrap();
            assert!(!cancelled.view_changed);
            let after_cancel = snapshot!(store,org);
            assert_eq!(after_cancel,(before_cancel.0,before_cancel.1+1,before_cancel.2,before_cancel.3,before_cancel.4+1));
            assert_eq!(store.write_organization_access_request(&requester,expires(),ORIGIN,cancel_target,
                AccessRequestWrite::Cancel {key:cancel_op,if_match:Some(&cancel_pending.etag)}).await.unwrap().response_json,cancelled.response_json);
            assert!(store.write_organization_access_request(&requester,expires(),ORIGIN,cancel_target,
                AccessRequestWrite::Create {key:cancel_key,request:&cancel_request}).await.is_ok(),"create confirmation requires own read, not fresh eligibility");
            store.write_organization_inventory(&owner,expires(),ORIGIN,InventoryTarget {org,kind:InventoryType::Host,id:host.id},
                InventoryWrite::Delete {if_match:&host.etag}).await.expect("terminal request history does not block Host deletion");
            assert_eq!(store.read_organization_access_request(&requester,expires(),cancel_target).await.unwrap().fields.host,host.id);
            let all = store.list_organization_access_requests(&requester,expires(),org,&mine).await.unwrap();
            let mut paged = Vec::new();
            let mut query = AccessRequestListQuery {view:AccessRequestView::Mine,page:OrganizationListQuery {limit:2,cursor:None}};
            loop {
                let page = store.list_organization_access_requests(&requester,expires(),org,&query).await.unwrap();
                paged.extend(page.items);
                let Some(cursor) = page.next_cursor else {break;};
                query.page.cursor=Some(cursor);
            }
            assert_eq!(paged,all.items,"current own history uses distinct ascending cursor pages");
            let before_retired = snapshot!(store,org);
            let retired = now_ms()-1;
            sqlx::query("UPDATE organization_inventory_receipts SET created_at_ms=$1,expires_at_ms=$2 WHERE account_id=$3 AND idempotency_key=$4")
                .bind(retired-86_400_000).bind(retired).bind(requester.account_id.as_slice()).bind(cancel_key.as_bytes().as_slice()).execute(store.pool()).await.unwrap();
            assert!(matches!(store.write_organization_access_request(&requester,expires(),ORIGIN,cancel_target,
                AccessRequestWrite::Create {key:cancel_key,request:&cancel_request}).await,Err(Error::Conflict)),"an expired original receipt cannot recreate its terminal request");
            assert_eq!(snapshot!(store,org),before_retired);
            let events: Vec<Vec<u8>> = sqlx::query_scalar("SELECT event_bytes FROM audit_events WHERE organization_id=$1")
                .bind(org.as_bytes().as_slice()).fetch_all(store.pool()).await.unwrap();
            let mut saw_browser = false;
            let mut saw_system = false;
            for bytes in events {
                let event: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                if event["action"].as_str().unwrap_or_default().starts_with("organization.access_request_") {
                    assert!(event.get("request_id").is_some());
                    assert!(event.get("reason").is_none() && event.get("remote_user").is_none());
                    saw_browser |= event.get("browser_family_id").is_some();
                    if event["action"] == "organization.access_request_expired" {
                        saw_system = true;
                        assert!(event.get("account_id").is_none() && event.get("device_id").is_none() && event.get("browser_family_id").is_none());
                    }
                }
            }
            assert!(saw_browser && saw_system);
        }
    };
}

request_checks!(
    sqlite_checks,
    SqliteStore,
    create_sqlite_password_account_in_transaction,
    seed_sqlite,
    false
);
#[cfg(feature = "postgres-integration")]
request_checks!(
    postgres_checks,
    PostgresStore,
    create_postgres_password_account_in_transaction,
    seed_postgres,
    true
);

#[tokio::test]
async fn sqlite_requests_keep_current_authority_atomic_grants_and_original_receipts() {
    let directory = std::env::temp_dir().join(format!("scoplen-requests-{}", Uuid::new_v4()));
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.unwrap();
    Box::pin(sqlite_checks(&store)).await;
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_requests_keep_current_authority_atomic_grants_and_original_receipts() {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").unwrap();
    let admin = sqlx::PgPool::connect(&database).await.unwrap();
    let schema = format!("organization_requests_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.unwrap();
    let mut url = url::Url::parse(&database).unwrap();
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let store = PostgresStore::connect(url.as_str()).await.unwrap();
    Box::pin(postgres_checks(&store)).await;
    store.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE")).execute(&admin).await.unwrap();
    admin.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_request_lost_commit_preserves_exact_create_decision_cancel_receipts() {
    use std::sync::atomic::Ordering;

    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").unwrap();
    let admin = sqlx::PgPool::connect(&database).await.unwrap();
    let schema = format!("request_commit_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.unwrap();
    let mut url = url::Url::parse(&database).unwrap();
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let store = PostgresStore::connect(url.as_str()).await.unwrap();
    let (_, _, owner, organization, host) =
        setup!(&store, create_postgres_password_account_in_transaction);
    let org = organization.id;
    let (_, _, approver, _) = add_actor!(
        &store,
        create_postgres_password_account_in_transaction,
        org,
        "commit-approver",
        "[\"owner\"]"
    );
    let fields = AccessRequestFields {
        host: host.id,
        remote_user: "ops".into(),
        duration_seconds: 60,
        reason: "maintenance".into(),
    };
    policy!(&store, &owner, org, "permit(principal, action, resource);".into());
    let proxy = lost_commit::LostCommitProxy::start(url.as_str()).await;
    let uncertain = PostgresStore::connect(&proxy.database_url).await.unwrap();
    let request = AccessRequestCreateRequest { id: Uuid::now_v7(), fields: fields.clone() };
    let target = AccessRequestTarget { organization: org, id: request.id };
    let create_key = Uuid::now_v7();
    let before = snapshot!(store, org);
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        uncertain
            .write_organization_access_request(
                &owner,
                expires(),
                ORIGIN,
                target,
                AccessRequestWrite::Create { key: create_key, request: &request }
            )
            .await,
        Err(Error::CommitOutcomeUnknown)
    ));
    let created = store
        .write_organization_access_request(
            &owner,
            expires(),
            ORIGIN,
            target,
            AccessRequestWrite::Create { key: create_key, request: &request },
        )
        .await
        .unwrap();
    assert!(!created.changed);
    let pending = AccessRequestResource::from_json(&created.response_json).unwrap();
    assert_eq!(
        snapshot!(store, org),
        (before.0, before.1 + 1, before.2, before.3 + 1, before.4 + 1)
    );
    let decision_key = Uuid::now_v7();
    let approve = AccessRequestDecisionRequest { decision: AccessRequestOutcome::Approve };
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        uncertain
            .write_organization_access_request(
                &approver,
                expires(),
                ORIGIN,
                target,
                AccessRequestWrite::Decide {
                    key: decision_key,
                    if_match: Some(&pending.etag),
                    request: approve
                }
            )
            .await,
        Err(Error::CommitOutcomeUnknown)
    ));
    let decision_result = store
        .write_organization_access_request(
            &approver,
            expires(),
            ORIGIN,
            target,
            AccessRequestWrite::Decide {
                key: decision_key,
                if_match: Some(&pending.etag),
                request: approve,
            },
        )
        .await
        .unwrap();
    assert!(!decision_result.changed && !decision_result.view_changed);
    assert_eq!(
        snapshot!(store, org),
        (before.0 + 1, before.1 + 3, before.2 + 1, before.3 + 1, before.4 + 2)
    );
    let grant_id =
        AccessRequestResource::from_json(&decision_result.response_json).unwrap().grant.unwrap().id;
    let grant_target = GrantTarget { organization: org, id: grant_id };
    let grant = store.read_organization_grant(&owner, expires(), grant_target).await.unwrap();
    store
        .write_organization_grant(
            &owner,
            expires(),
            ORIGIN,
            grant_target,
            GrantWrite::Delete { if_match: Some(&grant.etag) },
        )
        .await
        .unwrap();
    let withdrawn = snapshot!(store, org);
    assert_eq!(
        store
            .write_organization_access_request(
                &approver,
                expires(),
                ORIGIN,
                target,
                AccessRequestWrite::Decide {
                    key: decision_key,
                    if_match: Some(&pending.etag),
                    request: approve
                }
            )
            .await
            .unwrap()
            .response_json,
        decision_result.response_json
    );
    assert_eq!(
        store
            .write_organization_access_request(
                &owner,
                expires(),
                ORIGIN,
                target,
                AccessRequestWrite::Create { key: create_key, request: &request }
            )
            .await
            .unwrap()
            .response_json,
        created.response_json
    );
    assert_eq!(snapshot!(store, org), withdrawn);
    assert!(matches!(
        store.read_organization_grant(&owner, expires(), grant_target).await,
        Err(Error::NotFound)
    ));

    let (cancel_target, _, _, cancellable, _) = create_request!(store, &owner, org, fields);
    let cancel_key = Uuid::now_v7();
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        uncertain
            .write_organization_access_request(
                &owner,
                expires(),
                ORIGIN,
                cancel_target,
                AccessRequestWrite::Cancel { key: cancel_key, if_match: Some(&cancellable.etag) }
            )
            .await,
        Err(Error::CommitOutcomeUnknown)
    ));
    let after_cancel = snapshot!(store, org);
    let cancelled = store
        .write_organization_access_request(
            &owner,
            expires(),
            ORIGIN,
            cancel_target,
            AccessRequestWrite::Cancel { key: cancel_key, if_match: Some(&cancellable.etag) },
        )
        .await
        .unwrap();
    assert!(!cancelled.changed);
    assert_eq!(
        AccessRequestResource::from_json(&cancelled.response_json).unwrap().status,
        AccessRequestStatus::Cancelled
    );
    assert_eq!(snapshot!(store, org), after_cancel);
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 3);
    uncertain.pool().close().await;
    store.pool().close().await;
    drop(proxy);
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE")).execute(&admin).await.unwrap();
    admin.close().await;
}
