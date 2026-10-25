// SPDX-License-Identifier: AGPL-3.0-only

mod support;

#[path = "support/pool_close.rs"]
mod pool_close;

#[path = "pairing/maintenance.rs"]
mod maintenance;

#[path = "pairing/retention.rs"]
mod retention;

use std::net::IpAddr;

use scoplen_api::{
    pairing::{
        PairingCompleteRequest, PairingContext, PairingCreateRequest, PairingMessageRequest,
        PairingState, PairingStep,
    },
    personal_enrollment::PersonalEnrollmentRequest,
    sync::{SyncAccountDeviceWrap, SyncAccountKeyBundleUpdate},
};
use scoplen_crypto::{
    DeviceCertificate, DeviceKemKeyPair, Ed25519SigningKey, P256SigningKey,
    PairingApplicationContext, PairingCompletionContext, PairingContext as CryptoContext,
    PersonalEnrollmentArtifacts, PersonalEnrollmentContext, RevocationStatement,
    dpop_jwk_thumbprint,
};
use scoplen_identity::verify_personal_enrollment;
use scoplen_store::{
    RelationalStore, SqliteStore,
    device_authentication::CurrentPrincipal,
    pairing::{PairingActor, PairingStoreError},
};
use sqlx::Row as _;
use uuid::Uuid;

const ORIGIN: &str = "https://pairing.example.test";

fn source() -> IpAddr {
    "192.0.2.81".parse().expect("test source")
}

fn account_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[1; 32]).expect("test account key")
}

fn device_key(value: u8) -> P256SigningKey {
    let mut scalar = [0; 32];
    scalar[31] = value;
    P256SigningKey::from_bytes(&scalar).expect("test device key")
}

fn certificate(account: Uuid, device: Uuid, value: u8) -> DeviceCertificate {
    DeviceCertificate::issue(
        &account_key(),
        device,
        account,
        device_key(value).public_key_sec1(),
        DeviceKemKeyPair::from_private_bytes(&[value + 1; 32])
            .expect("test KEM")
            .public_key()
            .to_vec(),
        format!("Device {value}"),
        "windows".to_owned(),
        1,
    )
    .expect("test certificate")
}

fn enrollment(token: [u8; 32]) -> PersonalEnrollmentRequest {
    let account_id = Uuid::now_v7();
    let device_id = Uuid::now_v7();
    let mut request = PersonalEnrollmentRequest {
        invitation_token: token,
        account_id,
        personal_vault_id: Uuid::now_v7(),
        account_signing_public_key: account_key().public_key(),
        account_kem_public_key: [4; 32],
        key_bundle_update: SyncAccountKeyBundleUpdate {
            revision: 1,
            device_wraps: vec![SyncAccountDeviceWrap { device_id, wrapped_ark: vec![5] }],
            account_signing_key: vec![6],
            account_kem_key: vec![7],
            recovery_blob: vec![8],
            signature: vec![0; 64],
        },
        device_certificate: certificate(account_id, device_id, 1),
        wrapped_personal_vault_key: vec![9],
        device_signature: [0; 64],
    };
    request.key_bundle_update.signature = account_key()
        .sign(&request.key_bundle_update.signature_input().expect("signature input"))
        .to_vec();
    let bundle = request.key_bundle_update.to_cbor().expect("bundle");
    let certificate = request.device_certificate.encode().expect("certificate");
    let context = PersonalEnrollmentContext::new(
        ORIGIN,
        &token,
        account_id,
        request.personal_vault_id,
        PersonalEnrollmentArtifacts {
            account_signing_public_key: &request.account_signing_public_key,
            account_kem_public_key: &request.account_kem_public_key,
            key_bundle_update: &bundle,
            device_certificate: &certificate,
            wrapped_personal_vault_key: &request.wrapped_personal_vault_key,
        },
    )
    .expect("enrollment context");
    request.device_signature = context.sign(&device_key(1)).expect("proof");
    request
}

fn principal(request: &PersonalEnrollmentRequest) -> CurrentPrincipal {
    CurrentPrincipal {
        account_id: request.account_id.into_bytes(),
        device_id: request.device_certificate.device_id.into_bytes(),
        signing_public_key: device_key(1).public_key_sec1(),
        jkt: dpop_jwk_thumbprint(&device_key(1).public_key_sec1()).expect("thumbprint"),
        certificate: request.device_certificate.encode().expect("certificate"),
    }
}

fn completion(
    context: &PairingContext,
    request: &PersonalEnrollmentRequest,
    key: u8,
) -> PairingCompleteRequest {
    let cert = certificate(request.account_id, context.responder_device_id, key)
        .encode()
        .expect("new certificate");
    let mut update = request.key_bundle_update.clone();
    update.revision += 1;
    update.device_wraps.push(SyncAccountDeviceWrap {
        device_id: context.responder_device_id,
        wrapped_ark: vec![10],
    });
    update.device_wraps.sort_by_key(|wrap| wrap.device_id);
    update.signature =
        account_key().sign(&update.signature_input().expect("update input")).to_vec();
    let update = update.to_cbor().expect("signed update");
    let crypto = CryptoContext::new(
        context.pairing_id,
        context.initiator_device_id.expect("claimed"),
        context.responder_device_id,
    )
    .expect("context");
    let context = PairingApplicationContext::new(ORIGIN, crypto).expect("origin");
    let signature =
        PairingCompletionContext::new(&context, request.account_id, &[2; 41], &cert, &update)
            .expect("completion context")
            .sign(&device_key(key))
            .expect("acceptance");
    PairingCompleteRequest {
        device_certificate: cert,
        key_bundle_update: update,
        new_device_signature: signature,
    }
}

macro_rules! pairing_tests {
    ($module:ident,$store:ty,$open:ident,$postgres:expr) => {
        mod $module {
            use super::*;

            fn sql(source:&str)->String {
                if !$postgres {return source.to_owned();}
                let mut n=0;
                source.chars().map(|c|if c=='?' {n+=1;format!("${n}")}else{c.to_string()}).collect()
            }

            pub(super) async fn fixture(store:&$store)->PersonalEnrollmentRequest {
                let invitation=store.issue_personal_invitation(*Uuid::now_v7().as_bytes(),ORIGIN).await.expect("invitation");
                let request=enrollment(*invitation.token_bytes());
                let verified=verify_personal_enrollment(ORIGIN,&request).expect("verify");
                store.redeem_verified_personal_invitation(&verified).await.expect("enroll");
                request
            }

            pub(super) async fn ready(store:&$store,request:&PersonalEnrollmentRequest)->(PairingContext,[u8;32],PairingCompleteRequest) {
                ready_with_device_id(store,request,Uuid::now_v7()).await
            }

            async fn ready_with_device_id(store:&$store,request:&PersonalEnrollmentRequest,device_id:Uuid)->(PairingContext,[u8;32],PairingCompleteRequest) {
                ready_with_device_id_and_key(store,request,device_id,3).await
            }

            pub(super) async fn ready_with_key(store:&$store,request:&PersonalEnrollmentRequest,key:u8)->(PairingContext,[u8;32],PairingCompleteRequest) {
                ready_with_device_id_and_key(store,request,Uuid::now_v7(),key).await
            }

            async fn ready_with_device_id_and_key(store:&$store,request:&PersonalEnrollmentRequest,device_id:Uuid,key:u8)->(PairingContext,[u8;32],PairingCompleteRequest) {
                let created=store.create_pairing(ORIGIN,&PairingCreateRequest {device_id},source()).await.expect("create");
                let token=*created.new_device_token.as_bytes();
                let principal=principal(request);
                let context=store.claim_pairing(ORIGIN,created.context.pairing_id,&principal,source()).await.expect("claim").context;
                let completion=completion(&context,request,key);
                for step in PairingStep::ALL {
                    let payload=match step {PairingStep::NewDevice=>vec![1;41],PairingStep::Handoff=>vec![2;41],
                        PairingStep::Acceptance=>completion.new_device_signature.to_vec(),_=>vec![3;32]};
                    let actor=match step.role() {scoplen_api::pairing::PairingRole::Initiator=>PairingActor::Initiator(&principal),
                        scoplen_api::pairing::PairingRole::Responder=>PairingActor::Responder(&token)};
                    store.post_pairing_message(ORIGIN,context.pairing_id,actor,&PairingMessageRequest {step,payload},source()).await.expect("slot");
                }
                (context,token,completion)
            }

            #[tokio::test]
            async fn complete_is_atomic_replayable_and_never_resurrects_revoked_identity() {
                let (store,directory)=$open().await;
                let request=fixture(&store).await;
                let old=principal(&request);
                let (context,token,complete)=ready(&store,&request).await;
                let before=store.deployment_audit_head().await.expect("audit").expect("head").sequence;
                let (first,second)=tokio::join!(store.complete_pairing(ORIGIN,context.pairing_id,&old,&complete,source()),store.complete_pairing(ORIGIN,context.pairing_id,&old,&complete,source()));
                let receipt=first.expect("first confirmed result");
                assert_eq!(second.expect("exact concurrent replay"),receipt);
                assert_eq!(receipt.revision,2);
                assert_eq!(store.read_accepted_account_key_put(old.account_id).await.expect("accepted membership PUT"),Some(complete.key_bundle_update.clone()));
                assert_eq!(store.deployment_audit_head().await.expect("audit").expect("head").sequence,before+1);
                let snapshot=store.read_pairing(ORIGIN,context.pairing_id,PairingActor::Responder(&token),source()).await.expect("terminal read");
                assert_eq!(snapshot.state,PairingState::Completed);
                assert_eq!(snapshot.receipt.as_ref(),Some(&receipt));
                assert!(snapshot.messages.is_empty());
                assert_eq!(store.cancel_pairing(ORIGIN,context.pairing_id,PairingActor::Responder(&token),source()).await,Err(PairingStoreError::Conflict));
                let outsider=fixture(&store).await;let outsider=principal(&outsider);
                assert_eq!(store.claim_pairing(ORIGIN,context.pairing_id,&outsider,source()).await,Err(PairingStoreError::Denied));
                let terminal_message=PairingMessageRequest {step:PairingStep::InitiatorShare,payload:vec![5;32]};
                assert_eq!(store.post_pairing_message(ORIGIN,context.pairing_id,PairingActor::Initiator(&outsider),&terminal_message,source()).await,Err(PairingStoreError::Denied));
                assert_eq!(store.post_pairing_message(ORIGIN,context.pairing_id,PairingActor::Initiator(&old),&terminal_message,source()).await,Err(PairingStoreError::Conflict));
                let payloads:i64=sqlx::query_scalar(&sql("SELECT COUNT(*) FROM pairing_slots WHERE pairing_id=? AND payload IS NOT NULL")).bind(context.pairing_id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("payload cleanup");
                assert_eq!(payloads,0);
                let row=sqlx::query(&sql("SELECT revision,account_signing_key,account_kem_key,recovery_blob FROM sync_account_key_bundles WHERE account_id=?")).bind(request.account_id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("bundle");
                assert_eq!(row.get::<i64,_>("revision"),2);
                assert_eq!(row.get::<Vec<u8>,_>("account_signing_key"),vec![6]);
                assert_eq!(row.get::<Vec<u8>,_>("account_kem_key"),vec![7]);
                assert_eq!(row.get::<Vec<u8>,_>("recovery_blob"),vec![8]);
                let mut substituted=complete.clone();substituted.new_device_signature[0]^=1;
                assert_eq!(store.complete_pairing(ORIGIN,context.pairing_id,&old,&substituted,source()).await,Err(PairingStoreError::Conflict));
                sqlx::query(&sql("UPDATE identity_devices SET active=? WHERE device_id=?")).bind(false).bind(context.responder_device_id.as_bytes().as_slice()).execute(store.pool()).await.expect("deactivate new device");
                assert_eq!(store.complete_pairing(ORIGIN,context.pairing_id,&old,&complete,source()).await.expect("lost response recovery"),receipt);
                let active:bool=sqlx::query_scalar(&sql("SELECT active FROM identity_devices WHERE device_id=?")).bind(context.responder_device_id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("active state");
                assert!(!active);
                sqlx::query(&sql("UPDATE identity_devices SET active=? WHERE device_id=?")).bind(false).bind(old.device_id.as_slice()).execute(store.pool()).await.expect("deactivate old device");
                assert_eq!(store.complete_pairing(ORIGIN,context.pairing_id,&old,&complete,source()).await,Err(PairingStoreError::AuthenticationDenied));
                assert_eq!(store.claim_pairing(ORIGIN,context.pairing_id,&old,source()).await,Err(PairingStoreError::AuthenticationDenied));
                assert_eq!(store.read_pairing(ORIGIN,context.pairing_id,PairingActor::Initiator(&old),source()).await,Err(PairingStoreError::AuthenticationDenied));
                assert_eq!(store.post_pairing_message(ORIGIN,context.pairing_id,PairingActor::Initiator(&old),&terminal_message,source()).await,Err(PairingStoreError::AuthenticationDenied));
                assert_eq!(store.cancel_pairing(ORIGIN,context.pairing_id,PairingActor::Initiator(&old),source()).await,Err(PairingStoreError::AuthenticationDenied));
                pool_close::close(store.pool()).await;
                if let Some(directory)=directory {support::remove_test_directory(directory).await;}
            }

            #[tokio::test]
            async fn relay_checks_capability_role_order_replay_and_original_cancel_retention() {
                let (store,directory)=$open().await;
                let request=fixture(&store).await;
                let old=principal(&request);
                let created=store.create_pairing(ORIGIN,&PairingCreateRequest {device_id:Uuid::now_v7()},source()).await.expect("create");
                let id=created.context.pairing_id;let token=*created.new_device_token.as_bytes();
                assert_eq!(store.verify_pairing_responder(ORIGIN,id,&[0;32]).await,Err(PairingStoreError::Denied));
                assert_eq!(store.verify_pairing_responder("https://other.example",id,&token).await,Err(PairingStoreError::Denied));
                store.verify_pairing_responder(ORIGIN,id,&token).await.expect("capability");
                let saved:Vec<u8>=sqlx::query_scalar(&sql("SELECT capability_digest FROM pairing_sessions WHERE pairing_id=?")).bind(id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("digest");
                assert_ne!(saved,token);
                let first=store.claim_pairing(ORIGIN,id,&old,source()).await.expect("claim");
                assert_eq!(store.claim_pairing(ORIGIN,id,&old,source()).await.expect("claim replay"),first);
                let message=PairingMessageRequest {step:PairingStep::InitiatorShare,payload:vec![5;32]};
                assert_eq!(store.post_pairing_message(ORIGIN,id,PairingActor::Responder(&token),&message,source()).await,Err(PairingStoreError::Denied));
                let out_of_order=PairingMessageRequest {step:PairingStep::InitiatorConfirmation,payload:vec![5;32]};
                assert_eq!(store.post_pairing_message(ORIGIN,id,PairingActor::Initiator(&old),&out_of_order,source()).await,Err(PairingStoreError::Conflict));
                store.post_pairing_message(ORIGIN,id,PairingActor::Initiator(&old),&message,source()).await.expect("first slot");
                store.post_pairing_message(ORIGIN,id,PairingActor::Initiator(&old),&message,source()).await.expect("exact replay");
                let changed=PairingMessageRequest {payload:vec![6;32],..message};
                assert_eq!(store.post_pairing_message(ORIGIN,id,PairingActor::Initiator(&old),&changed,source()).await,Err(PairingStoreError::Conflict));
                let retained:i64=sqlx::query_scalar(&sql("SELECT retain_until_ms FROM pairing_sessions WHERE pairing_id=?")).bind(id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("retention");
                store.cancel_pairing(ORIGIN,id,PairingActor::Responder(&token),source()).await.expect("cancel");
                store.cancel_pairing(ORIGIN,id,PairingActor::Responder(&token),source()).await.expect("cancel replay");
                let row=sqlx::query(&sql("SELECT retain_until_ms,payload_bytes FROM pairing_sessions WHERE pairing_id=?")).bind(id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("terminal");
                assert_eq!(row.get::<i64,_>("retain_until_ms"),retained);assert_eq!(row.get::<i64,_>("payload_bytes"),0);
                assert_eq!(store.read_pairing(ORIGIN,id,PairingActor::Responder(&token),source()).await.expect("cancelled").state,PairingState::Cancelled);
                pool_close::close(store.pool()).await;if let Some(directory)=directory {support::remove_test_directory(directory).await;}
            }

            #[tokio::test]
            async fn expiry_erases_payloads_once_and_preserves_original_terminal_retention() {
                let (store,directory)=$open().await;let request=fixture(&store).await;let old=principal(&request);
                let (context,token,complete)=ready(&store,&request).await;
                let retained:i64=sqlx::query_scalar(&sql("SELECT retain_until_ms FROM pairing_sessions WHERE pairing_id=?")).bind(context.pairing_id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("retention");
                sqlx::query(&sql("UPDATE pairing_sessions SET created_at_ms=created_at_ms-301000,expires_at_ms=expires_at_ms-301000 WHERE pairing_id=?")).bind(context.pairing_id.as_bytes().as_slice()).execute(store.pool()).await.expect("expire session");
                let snapshot=store.read_pairing(ORIGIN,context.pairing_id,PairingActor::Responder(&token),source()).await.expect("expired read");assert_eq!(snapshot.state,PairingState::Expired);assert!(snapshot.messages.is_empty());
                let before=store.deployment_audit_head().await.expect("audit").expect("head").sequence;
                assert_eq!(store.cancel_pairing(ORIGIN,context.pairing_id,PairingActor::Responder(&token),source()).await,Err(PairingStoreError::Denied));
                assert_eq!(store.complete_pairing(ORIGIN,context.pairing_id,&old,&complete,source()).await,Err(PairingStoreError::Denied));
                let row=sqlx::query(&sql("SELECT retain_until_ms,payload_bytes FROM pairing_sessions WHERE pairing_id=?")).bind(context.pairing_id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("terminal row");
                assert_eq!(row.get::<i64,_>("retain_until_ms"),retained);assert_eq!(row.get::<i64,_>("payload_bytes"),0);
                assert_eq!(store.deployment_audit_head().await.expect("audit").expect("head").sequence,before);
                pool_close::close(store.pool()).await;if let Some(directory)=directory {support::remove_test_directory(directory).await;}
            }

            #[tokio::test]
            async fn deployment_live_session_limit_is_serialized_across_concurrent_creates() {
                let (store,directory)=$open().await;
                let active:i64=sqlx::query_scalar("SELECT COUNT(*) FROM pairing_sessions WHERE state IN ('waiting','exchanging','ready')").fetch_one(store.pool()).await.expect("active baseline");
                assert!(active<999);
                let now=i64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_millis()).expect("time")/1000*1000;
                let mut holder=store.pool().begin().await.expect("seed tx");let mut ids=Vec::new();
                for _ in active..999 {
                    let id=Uuid::now_v7();ids.push(id);
                    sqlx::query(&sql("INSERT INTO pairing_sessions(pairing_id,trusted_origin,responder_device_id,capability_digest,created_at_ms,expires_at_ms,retain_until_ms,state,slot_count,payload_bytes) VALUES(?,?,?,?,?,?,?,'waiting',0,0)"))
                        .bind(id.as_bytes().as_slice()).bind(ORIGIN).bind(Uuid::now_v7().as_bytes().as_slice()).bind([0_u8;32].as_slice()).bind(now).bind(now+300000).bind(now+86700000)
                        .execute(&mut *holder).await.expect("seed resource boundary");
                }
                holder.commit().await.expect("commit resource boundary");
                let one=PairingCreateRequest {device_id:Uuid::now_v7()};let two=PairingCreateRequest {device_id:Uuid::now_v7()};
                let (one,two)=tokio::join!(store.create_pairing(ORIGIN,&one,source()),store.create_pairing(ORIGIN,&two,source()));
                assert_eq!(usize::from(one.is_ok())+usize::from(two.is_ok()),1);
                assert!(matches!(one,Ok(_)|Err(PairingStoreError::ResourceLimited)));assert!(matches!(two,Ok(_)|Err(PairingStoreError::ResourceLimited)));
                let mut holder=store.pool().begin().await.expect("cleanup tx");
                for id in ids {sqlx::query(&sql("DELETE FROM pairing_sessions WHERE pairing_id=?")).bind(id.as_bytes().as_slice()).execute(&mut *holder).await.expect("remove seeded row");}
                holder.commit().await.expect("seed cleanup");
                pool_close::close(store.pool()).await;if let Some(directory)=directory {support::remove_test_directory(directory).await;}
            }

            #[tokio::test]
            async fn retained_session_limit_rejects_without_dropping_unexpired_receipts() {
                let (store,directory)=$open().await;
                let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM pairing_sessions").fetch_one(store.pool()).await.expect("retained baseline");assert!(count<10000);
                let now=i64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_millis()).expect("time")/1000*1000;
                let random=if $postgres {"decode(md5(x::text || 'pairing-retained-test'),'hex')"}else{"randomblob(16)"};
                let query=format!("WITH RECURSIVE n(x) AS (SELECT CAST(1 AS BIGINT) UNION ALL SELECT x+1 FROM n WHERE x<?) INSERT INTO pairing_sessions(pairing_id,trusted_origin,responder_device_id,capability_digest,created_at_ms,expires_at_ms,retain_until_ms,state,slot_count,payload_bytes) SELECT {random},?,?,?,?,?,?,'cancelled',0,0 FROM n");
                sqlx::query(&sql(&query)).bind(10000-count).bind("https://retained.pairing-budget.test").bind(Uuid::now_v7().as_bytes().as_slice()).bind([0_u8;32].as_slice()).bind(now).bind(now+300000).bind(now+86700000).execute(store.pool()).await.expect("fill retained capacity");
                assert!(matches!(store.create_pairing(ORIGIN,&PairingCreateRequest {device_id:Uuid::now_v7()},source()).await,Err(PairingStoreError::ResourceLimited)));
                let current:i64=sqlx::query_scalar("SELECT COUNT(*) FROM pairing_sessions").fetch_one(store.pool()).await.expect("retained cap");assert_eq!(current,10000);
                sqlx::query("DELETE FROM pairing_sessions WHERE trusted_origin='https://retained.pairing-budget.test'").execute(store.pool()).await.expect("remove boundary fixtures");
                store.create_pairing(ORIGIN,&PairingCreateRequest {device_id:Uuid::now_v7()},source()).await.expect("released capacity");
                pool_close::close(store.pool()).await;if let Some(directory)=directory {support::remove_test_directory(directory).await;}
            }

            #[tokio::test]
            async fn aggregate_payload_budget_counts_replay_as_zero_and_releases_on_cancel() {
                let (store,directory)=$open().await;let request=fixture(&store).await;let old=principal(&request);
                let created=store.create_pairing(ORIGIN,&PairingCreateRequest {device_id:Uuid::now_v7()},source()).await.expect("create");let id=created.context.pairing_id;
                store.claim_pairing(ORIGIN,id,&old,source()).await.expect("claim");
                let message=PairingMessageRequest {step:PairingStep::InitiatorShare,payload:vec![1;32]};
                store.post_pairing_message(ORIGIN,id,PairingActor::Initiator(&old),&message,source()).await.expect("initial slot");
                sqlx::query(&sql("UPDATE pairing_sessions SET payload_bytes=268435456 WHERE pairing_id=?")).bind(id.as_bytes().as_slice()).execute(store.pool()).await.expect("deployment budget boundary");
                store.post_pairing_message(ORIGIN,id,PairingActor::Initiator(&old),&message,source()).await.expect("replay adds zero");
                let next=PairingMessageRequest {step:PairingStep::ResponderShare,payload:vec![1;32]};
                assert_eq!(store.post_pairing_message(ORIGIN,id,PairingActor::Responder(created.new_device_token.as_bytes()),&next,source()).await,Err(PairingStoreError::ResourceLimited));
                store.cancel_pairing(ORIGIN,id,PairingActor::Initiator(&old),source()).await.expect("release capacity");
                let bytes:i64=sqlx::query_scalar(&sql("SELECT payload_bytes FROM pairing_sessions WHERE pairing_id=?")).bind(id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("released");assert_eq!(bytes,0);
                pool_close::close(store.pool()).await;if let Some(directory)=directory {support::remove_test_directory(directory).await;}
            }

            #[tokio::test]
            async fn audit_failure_rolls_back_entire_membership_and_keeps_ready_transcript() {
                let (store,directory)=$open().await;let request=fixture(&store).await;let old=principal(&request);
                let (context,token,complete)=ready(&store,&request).await;
                let trigger=if $postgres {
                    "CREATE FUNCTION pairing_reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'pairing audit unavailable'; END $$;
                     CREATE TRIGGER pairing_reject_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION pairing_reject_audit()"
                } else {"CREATE TRIGGER pairing_reject_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(FAIL,'pairing audit unavailable'); END"};
                sqlx::raw_sql(trigger).execute(store.pool()).await.expect("deny audit");
                assert_eq!(store.complete_pairing(ORIGIN,context.pairing_id,&old,&complete,source()).await,Err(PairingStoreError::Audit));
                let remove=if $postgres {"DROP TRIGGER pairing_reject_audit ON deployment_audit_events; DROP FUNCTION pairing_reject_audit()"}else{"DROP TRIGGER pairing_reject_audit"};
                sqlx::raw_sql(remove).execute(store.pool()).await.expect("restore audit");
                let devices:i64=sqlx::query_scalar(&sql("SELECT COUNT(*) FROM identity_devices WHERE device_id=?")).bind(context.responder_device_id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("rolled-back identity");assert_eq!(devices,0);
                let revision:i64=sqlx::query_scalar(&sql("SELECT revision FROM sync_account_key_bundles WHERE account_id=?")).bind(old.account_id.as_slice()).fetch_one(store.pool()).await.expect("original revision");assert_eq!(revision,1);
                assert_eq!(store.read_accepted_account_key_put(old.account_id).await.expect("original evidence after rollback"),Some(request.key_bundle_update.to_cbor().expect("original PUT")));
                let snapshot=store.read_pairing(ORIGIN,context.pairing_id,PairingActor::Responder(&token),source()).await.expect("ready after rollback");assert_eq!(snapshot.state,PairingState::Ready);assert_eq!(snapshot.messages.len(),7);
                store.complete_pairing(ORIGIN,context.pairing_id,&old,&complete,source()).await.expect("retry after confirmed rollback");
                pool_close::close(store.pool()).await;if let Some(directory)=directory {support::remove_test_directory(directory).await;}
            }

            #[tokio::test]
            async fn concurrent_distinct_sessions_at_same_revision_commit_one_device() {
                let (store,directory)=$open().await;let request=fixture(&store).await;let old=principal(&request);
                let (first,_,first_complete)=ready(&store,&request).await;
                let (second,_,second_complete)=ready(&store,&request).await;
                let (left,right)=tokio::join!(store.complete_pairing(ORIGIN,first.pairing_id,&old,&first_complete,source()),store.complete_pairing(ORIGIN,second.pairing_id,&old,&second_complete,source()));
                assert_eq!(usize::from(left.is_ok())+usize::from(right.is_ok()),1);
                assert!(matches!(left,Ok(_)|Err(PairingStoreError::Conflict)));
                assert!(matches!(right,Ok(_)|Err(PairingStoreError::Conflict)));
                let devices:i64=sqlx::query_scalar(&sql("SELECT COUNT(*) FROM identity_devices WHERE account_id=?")).bind(old.account_id.as_slice()).fetch_one(store.pool()).await.expect("atomic membership");assert_eq!(devices,2);
                pool_close::close(store.pool()).await;if let Some(directory)=directory {support::remove_test_directory(directory).await;}
            }

            #[tokio::test]
            async fn projected_key_response_overflow_rolls_back_candidate_identity_and_keys() {
                let (store,directory)=$open().await;let mut request=fixture(&store).await;let old=principal(&request);
                request.key_bundle_update.account_signing_key=vec![6;65536];request.key_bundle_update.account_kem_key=vec![7;65536];request.key_bundle_update.recovery_blob=vec![8;65536];
                request.key_bundle_update.signature=account_key().sign(&request.key_bundle_update.signature_input().expect("current signature input")).to_vec();
                sqlx::query(&sql("UPDATE sync_account_key_bundles SET account_signing_key=?,account_kem_key=?,recovery_blob=?,signature=? WHERE account_id=?"))
                    .bind(&request.key_bundle_update.account_signing_key).bind(&request.key_bundle_update.account_kem_key).bind(&request.key_bundle_update.recovery_blob).bind(&request.key_bundle_update.signature).bind(old.account_id.as_slice()).execute(store.pool()).await.expect("large current ciphertexts");
                for _ in 0..63 {
                    let id=Uuid::now_v7();
                    let cert=DeviceCertificate::issue(&account_key(),id,request.account_id,device_key(5).public_key_sec1(),DeviceKemKeyPair::from_private_bytes(&[6;32]).expect("KEM").public_key().to_vec(),"x".repeat(65000),"windows".to_owned(),1).expect("large certificate").encode().expect("certificate bytes");
                    assert!(cert.len()<=65536);
                    sqlx::query(&sql("INSERT INTO sync_account_key_certificates(account_id,certificate) VALUES(?,?)")).bind(old.account_id.as_slice()).bind(cert).execute(store.pool()).await.expect("large signed history");
                    request.key_bundle_update.device_wraps.push(SyncAccountDeviceWrap {device_id:id,wrapped_ark:vec![11]});
                }
                let (context,_,complete)=ready(&store,&request).await;
                assert_eq!(store.complete_pairing(ORIGIN,context.pairing_id,&old,&complete,source()).await,Err(PairingStoreError::QuotaExceeded));
                let count:i64=sqlx::query_scalar(&sql("SELECT COUNT(*) FROM identity_devices WHERE device_id=?")).bind(context.responder_device_id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("candidate rollback");assert_eq!(count,0);
                let revision:i64=sqlx::query_scalar(&sql("SELECT revision FROM sync_account_key_bundles WHERE account_id=?")).bind(old.account_id.as_slice()).fetch_one(store.pool()).await.expect("key rollback");assert_eq!(revision,1);
                pool_close::close(store.pool()).await;if let Some(directory)=directory {support::remove_test_directory(directory).await;}
            }

            #[tokio::test]
            async fn signed_certificate_history_includes_inactive_wrap_recipients() {
                let (store,directory)=$open().await;let mut request=fixture(&store).await;let old=principal(&request);
                let pending_device_id=Uuid::now_v7();
                let inactive_id=Uuid::now_v7();
                let inactive=certificate(request.account_id,inactive_id,5).encode().expect("inactive certificate");
                sqlx::query(&sql("INSERT INTO sync_account_key_certificates(account_id,certificate) VALUES(?,?)")).bind(old.account_id.as_slice()).bind(&inactive).execute(store.pool()).await.expect("publish inactive history");
                let (context,_,complete)=ready(&store,&request).await;
                assert_eq!(store.complete_pairing(ORIGIN,context.pairing_id,&old,&complete,source()).await,Err(PairingStoreError::InvalidRequest));
                let row:i64=sqlx::query_scalar(&sql("SELECT revision FROM sync_account_key_bundles WHERE account_id=?")).bind(old.account_id.as_slice()).fetch_one(store.pool()).await.expect("unchanged keys");assert_eq!(row,1);
                request.key_bundle_update.device_wraps.push(SyncAccountDeviceWrap {device_id:inactive_id,wrapped_ark:vec![11]});
                let (context,_,complete)=ready_with_device_id(&store,&request,pending_device_id).await;
                store.complete_pairing(ORIGIN,context.pairing_id,&old,&complete,source()).await.expect("complete certified recipient set");
                let saved:Vec<u8>=sqlx::query_scalar(&sql("SELECT wrapped_ark FROM sync_account_key_device_wraps WHERE account_id=? AND device_id=?")).bind(old.account_id.as_slice()).bind(inactive_id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("inactive wrap retained");assert_eq!(saved,vec![11]);
                pool_close::close(store.pool()).await;if let Some(directory)=directory {support::remove_test_directory(directory).await;}
            }

            #[tokio::test]
            async fn completion_rejects_changed_artifacts_recipients_signatures_and_reused_ids() {
                let (store,directory)=$open().await;let request=fixture(&store).await;let old=principal(&request);
                let (context,_,complete)=ready(&store,&request).await;
                for kind in 0..4 {
                    let mut altered=complete.clone();
                    if kind==0 {altered.new_device_signature[0]^=1;}
                    else if kind==1 {let mut cert=DeviceCertificate::decode(&altered.device_certificate).expect("certificate");cert.signature[0]^=1;altered.device_certificate=cert.encode().expect("tampered certificate");}
                    else {let mut update=SyncAccountKeyBundleUpdate::from_cbor(&altered.key_bundle_update).expect("update");
                        if kind==2 {update.recovery_blob=vec![23];}else{update.device_wraps.retain(|wrap|wrap.device_id==context.responder_device_id);}
                        update.signature=account_key().sign(&update.signature_input().expect("input")).to_vec();altered.key_bundle_update=update.to_cbor().expect("signed substitution");}
                    assert_eq!(store.complete_pairing(ORIGIN,context.pairing_id,&old,&altered,source()).await,Err(PairingStoreError::InvalidRequest));
                }
                let count:i64=sqlx::query_scalar(&sql("SELECT COUNT(*) FROM identity_devices WHERE device_id=?")).bind(context.responder_device_id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("no candidate");assert_eq!(count,0);
                let revoked=RevocationStatement::issue(&account_key(),context.responder_device_id,2,"retired id".to_owned()).expect("historical revocation").encode().expect("revocation bytes");
                sqlx::query(&sql("INSERT INTO sync_account_key_revocations(account_id,revocation) VALUES(?,?)")).bind(old.account_id.as_slice()).bind(&revoked).execute(store.pool()).await.expect("publish revocation history");
                assert_eq!(store.complete_pairing(ORIGIN,context.pairing_id,&old,&complete,source()).await,Err(PairingStoreError::Conflict));
                sqlx::query(&sql("DELETE FROM sync_account_key_revocations WHERE account_id=? AND revocation=?")).bind(old.account_id.as_slice()).bind(&revoked).execute(store.pool()).await.expect("restore fixture history");
                sqlx::query(&sql("INSERT INTO identity_devices(device_id,account_id,certificate,active,created_at_ms) VALUES(?,?,?,?,1)"))
                    .bind(context.responder_device_id.as_bytes().as_slice()).bind(request.account_id.as_bytes().as_slice()).bind(&complete.device_certificate).bind(false).execute(store.pool()).await.expect("inactive historical id");
                assert_eq!(store.complete_pairing(ORIGIN,context.pairing_id,&old,&complete,source()).await,Err(PairingStoreError::Conflict));
                pool_close::close(store.pool()).await;if let Some(directory)=directory {support::remove_test_directory(directory).await;}
            }
        }
    }
}

async fn sqlite_open() -> (SqliteStore, Option<std::path::PathBuf>) {
    let path = std::env::temp_dir().join(format!("scoplen-pairing-{}", Uuid::now_v7()));
    let store = SqliteStore::open(&path.join("scoplen.sqlite")).await.expect("SQLite store");
    (store, Some(path))
}

pairing_tests!(sqlite, SqliteStore, sqlite_open, false);

#[cfg(feature = "postgres-integration")]
async fn postgres_open() -> (scoplen_store::PostgresStore, Option<std::path::PathBuf>) {
    let url = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL test URL");
    (scoplen_store::PostgresStore::connect(&url).await.expect("PostgreSQL store"), None)
}

#[cfg(feature = "postgres-integration")]
pairing_tests!(postgres, scoplen_store::PostgresStore, postgres_open, true);

#[cfg(feature = "postgres-integration")]
#[path = "support/lost_commit.rs"]
mod lost_commit;

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_committed_membership_with_lost_ack_discloses_no_receipt_and_recovers_exactly() {
    use std::sync::atomic::Ordering;
    let url = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL test URL");
    let direct = scoplen_store::PostgresStore::connect(&url).await.expect("direct store");
    let request = postgres::fixture(&direct).await;
    let (context, token, complete) = postgres::ready(&direct, &request).await;
    let old = principal(&request);
    let proxy = lost_commit::LostCommitProxy::start(&url).await;
    let uncertain =
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxied store");
    proxy.armed.store(true, Ordering::SeqCst);
    assert_eq!(
        uncertain.complete_pairing(ORIGIN, context.pairing_id, &old, &complete, source()).await,
        Err(PairingStoreError::CommitOutcomeUnknown)
    );
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    let snapshot = direct
        .read_pairing(ORIGIN, context.pairing_id, PairingActor::Responder(&token), source())
        .await
        .expect("durable completion");
    assert_eq!(snapshot.state, PairingState::Completed);
    let receipt = direct
        .complete_pairing(ORIGIN, context.pairing_id, &old, &complete, source())
        .await
        .expect("exact outcome recovery");
    assert_eq!(snapshot.receipt, Some(receipt));
    proxy.armed.store(true, Ordering::SeqCst);
    assert_eq!(
        uncertain
            .read_pairing(ORIGIN, context.pairing_id, PairingActor::Responder(&token), source())
            .await,
        Err(PairingStoreError::Database)
    );
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 2);
    proxy.armed.store(true, Ordering::SeqCst);
    assert_eq!(
        uncertain.complete_pairing(ORIGIN, context.pairing_id, &old, &complete, source()).await,
        Err(PairingStoreError::Database)
    );
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 3);
    pool_close::close(uncertain.pool()).await;
    pool_close::close(direct.pool()).await;
}

#[tokio::test]
async fn sqlite_expiry_is_rechecked_after_waiting_for_writer_lock() {
    let (store, directory) = sqlite_open().await;
    let request = sqlite::fixture(&store).await;
    let (context, _, complete) = sqlite::ready(&store, &request).await;
    let old = principal(&request);
    let mut holder = store.pool().begin_with("BEGIN IMMEDIATE").await.expect("writer lock");
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("time");
    sqlx::query("UPDATE pairing_sessions SET created_at_ms=?,expires_at_ms=? WHERE pairing_id=?")
        .bind(now + 500 - 300_000)
        .bind(now + 500)
        .bind(context.pairing_id.as_bytes().as_slice())
        .execute(&mut *holder)
        .await
        .expect("expiry while locked");
    let attempting = store.clone();
    let task = tokio::spawn(async move {
        attempting.complete_pairing(ORIGIN, context.pairing_id, &old, &complete, source()).await
    });
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    holder.commit().await.expect("unlock after expiry");
    assert_eq!(task.await.expect("complete task"), Err(PairingStoreError::Denied));
    pool_close::close(store.pool()).await;
    support::remove_test_directory(directory.expect("SQLite directory")).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_expiry_is_rechecked_after_waiting_for_exclusive_account_lock() {
    let (store, _) = postgres_open().await;
    let request = postgres::fixture(&store).await;
    let (context, _, complete) = postgres::ready(&store, &request).await;
    let old = principal(&request);
    let mut holder = store.pool().begin().await.expect("account tx");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1,'hex'),0))")
        .bind(old.account_id.as_slice())
        .execute(&mut *holder)
        .await
        .expect("account lock");
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("time");
    sqlx::query(
        "UPDATE pairing_sessions SET created_at_ms=$1,expires_at_ms=$2 WHERE pairing_id=$3",
    )
    .bind(now + 500 - 300_000)
    .bind(now + 500)
    .bind(context.pairing_id.as_bytes().as_slice())
    .execute(&mut *holder)
    .await
    .expect("expiry while locked");
    let attempting = store.clone();
    let task = tokio::spawn(async move {
        attempting.complete_pairing(ORIGIN, context.pairing_id, &old, &complete, source()).await
    });
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    holder.commit().await.expect("unlock after expiry");
    assert_eq!(task.await.expect("complete task"), Err(PairingStoreError::Denied));
    pool_close::close(store.pool()).await;
}
