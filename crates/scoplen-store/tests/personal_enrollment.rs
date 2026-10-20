// SPDX-License-Identifier: AGPL-3.0-only

use std::{path::PathBuf, time::Duration};

use scoplen_api::{
    personal_enrollment::PersonalEnrollmentRequest,
    sync::{SyncAccountDeviceWrap, SyncAccountKeyBundleUpdate},
};
use scoplen_crypto::{
    DeviceCertificate, DeviceKemKeyPair, Ed25519SigningKey, P256SigningKey,
    PersonalEnrollmentArtifacts, PersonalEnrollmentContext,
};
use scoplen_identity::verify_personal_enrollment;
use scoplen_store::{PersonalInvitationStoreError, RelationalStore, SqliteStore};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const ORIGIN: &str = "https://example.com";

fn account_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[1; 32]).expect("account key")
}

fn device_key() -> P256SigningKey {
    let mut scalar = [0; 32];
    scalar[31] = 1;
    P256SigningKey::from_bytes(&scalar).expect("device key")
}

fn sign_proof(request: &mut PersonalEnrollmentRequest) {
    let bundle = request.key_bundle_update.to_cbor().expect("bundle CBOR");
    let certificate = request.device_certificate.encode().expect("certificate CBOR");
    let context = PersonalEnrollmentContext::new(
        ORIGIN,
        &request.invitation_token,
        request.account_id,
        request.personal_vault_id,
        PersonalEnrollmentArtifacts {
            account_signing_public_key: &request.account_signing_public_key,
            account_kem_public_key: &request.account_kem_public_key,
            key_bundle_update: &bundle,
            device_certificate: &certificate,
            wrapped_personal_vault_key: &request.wrapped_personal_vault_key,
        },
    )
    .expect("proof context");
    request.device_signature = context.sign(&device_key()).expect("device proof");
}

fn enrollment(token: [u8; 32]) -> PersonalEnrollmentRequest {
    let account_id = Uuid::now_v7();
    let device_id = Uuid::now_v7();
    let kem = DeviceKemKeyPair::from_private_bytes(&[2; 32]).expect("device KEM");
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
        device_certificate: DeviceCertificate::issue(
            &account_key(),
            device_id,
            account_id,
            device_key().public_key_sec1(),
            kem.public_key().to_vec(),
            "first device".into(),
            "windows".into(),
            1,
        )
        .expect("certificate"),
        wrapped_personal_vault_key: vec![9],
        device_signature: [0; 64],
    };
    request.key_bundle_update.signature = account_key()
        .sign(&request.key_bundle_update.signature_input().expect("signature input"))
        .to_vec();
    sign_proof(&mut request);
    request
}

fn test_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!("scoplen-personal-{}", Uuid::now_v7()));
    std::fs::create_dir(&path).expect("test directory");
    path
}

async fn remove_test_directory(path: PathBuf) {
    for attempt in 0..20 {
        match std::fs::remove_dir_all(&path) {
            Ok(()) => return,
            Err(error) if error.raw_os_error() == Some(32) && attempt < 19 => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("remove test directory {}: {error}", path.display()),
        }
    }
}

#[tokio::test]
async fn sqlite_invitation_enrolls_once_with_redacted_audit_and_readback() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
    let issuer = *Uuid::now_v7().as_bytes();
    let invitation = store.issue_personal_invitation(issuer, ORIGIN).await.expect("issue");
    let token = *invitation.token_bytes();
    let digest: [u8; 32] = Sha256::digest(token).into();
    assert_eq!(invitation.trusted_origin(), ORIGIN);
    assert!(!format!("{invitation:?}").contains(&format!("{token:?}")));
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT token_digest FROM personal_invitations WHERE invitation_id = ?")
            .bind(invitation.invitation_id().as_slice())
            .fetch_one(store.pool())
            .await
            .expect("digest");
    assert_eq!(stored, digest);
    let request = enrollment(token);
    let verified = verify_personal_enrollment(ORIGIN, &request).expect("verified");
    let receipt = store.redeem_verified_personal_invitation(&verified).await.expect("enroll");
    assert_eq!(receipt.account_id, *request.account_id.as_bytes());
    assert_eq!(receipt.device_id, *request.device_certificate.device_id.as_bytes());
    assert_eq!(receipt.personal_vault_id, *request.personal_vault_id.as_bytes());
    let email: Option<String> =
        sqlx::query_scalar("SELECT email FROM identity_accounts WHERE account_id = ?")
            .bind(receipt.account_id.as_slice())
            .fetch_one(store.pool())
            .await
            .expect("account");
    assert!(email.is_none());
    let device = store
        .find_active_personal_device(receipt.device_id)
        .await
        .expect("device")
        .expect("active");
    assert_eq!(device.account_id, receipt.account_id);
    assert_eq!(device.certificate_cbor(), verified.device_certificate_cbor());
    assert_eq!(device.account_signing_public_key(), verified.account_signing_public_key());
    let bundle =
        store.get_account_key_bundle(receipt.account_id, receipt.device_id).await.expect("K-4");
    assert_eq!(bundle.revision, 1);
    assert_eq!(bundle.wrapped_ark, vec![5]);
    assert_eq!(bundle.certificates, vec![verified.device_certificate_cbor().to_vec()]);
    store
        .replace_account_key_statements(
            receipt.account_id,
            &[verified.device_certificate_cbor().to_vec()],
            &[],
        )
        .await
        .expect("K-4 statement replacement keeps existing certificate");
    store
        .replace_account_key_statements(receipt.account_id, &[], &[vec![1]])
        .await
        .expect("K-4 statement replacement removes certificate");
    assert!(
        store
            .find_active_personal_device(receipt.device_id)
            .await
            .expect("device lookup")
            .is_some()
    );
    assert_eq!(
        store
            .get_account_key_bundle(receipt.account_id, receipt.device_id)
            .await
            .expect("K-4 after removal")
            .certificates,
        Vec::<Vec<u8>>::new()
    );
    let (vault_id, wrap) =
        store.get_personal_sync_vault_key(receipt.account_id).await.expect("vault");
    assert_eq!(vault_id, receipt.personal_vault_id);
    assert_eq!(wrap, request.wrapped_personal_vault_key);
    assert!(matches!(
        store.redeem_verified_personal_invitation(&verified).await,
        Err(PersonalInvitationStoreError::Denied)
    ));
    assert_eq!(store.verify_deployment_audit_chain().await.expect("audit").unwrap().sequence, 2);
    let events: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT event_bytes FROM deployment_audit_events ORDER BY sequence")
            .fetch_all(store.pool())
            .await
            .expect("events");
    assert!(events.iter().all(|event| !event.windows(token.len()).any(|bytes| bytes == token)));
    assert!(events.iter().all(|event| !event.windows(digest.len()).any(|bytes| bytes == digest)));
    assert!(events.iter().all(|event| {
        !event
            .windows(verified.device_certificate_cbor().len())
            .any(|bytes| bytes == verified.device_certificate_cbor())
    }));
    store.pool().close().await;
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_denials_do_not_consume_invitation_and_late_failure_rolls_back() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
    let invitation =
        store.issue_personal_invitation(*Uuid::now_v7().as_bytes(), ORIGIN).await.expect("issue");
    let request = enrollment(*invitation.token_bytes());
    let verified = verify_personal_enrollment(ORIGIN, &request).expect("verified");
    let mut bad = enrollment(*invitation.token_bytes());
    bad.device_signature[0] ^= 1;
    assert!(verify_personal_enrollment(ORIGIN, &bad).is_err());
    let mut unknown = enrollment([0; 32]);
    sign_proof(&mut unknown);
    let unknown = verify_personal_enrollment(ORIGIN, &unknown).expect("valid unknown proof");
    assert!(matches!(
        store.redeem_verified_personal_invitation(&unknown).await,
        Err(PersonalInvitationStoreError::Denied)
    ));
    sqlx::query("CREATE TRIGGER fail_personal_vault BEFORE INSERT ON sync_personal_vaults BEGIN SELECT RAISE(ABORT, 'late failure'); END")
        .execute(store.pool()).await.expect("trigger");
    assert!(store.redeem_verified_personal_invitation(&verified).await.is_err());
    for table in [
        "identity_accounts",
        "identity_devices",
        "sync_account_key_bundles",
        "sync_account_key_device_wraps",
        "sync_account_key_certificates",
        "sync_vaults",
        "sync_personal_vaults",
    ] {
        let query = format!("SELECT COUNT(*) FROM {table}");
        let count: i64 =
            sqlx::query_scalar(&query).fetch_one(store.pool()).await.expect("row count");
        assert_eq!(count, 0, "{table} rolled back");
    }
    let consumed: Option<i64> = sqlx::query_scalar(
        "SELECT consumed_at_ms FROM personal_invitations WHERE invitation_id = ?",
    )
    .bind(invitation.invitation_id().as_slice())
    .fetch_one(store.pool())
    .await
    .expect("invitation");
    assert!(consumed.is_none());
    assert_eq!(store.deployment_audit_head().await.expect("audit").unwrap().sequence, 1);
    sqlx::query("DROP TRIGGER fail_personal_vault")
        .execute(store.pool())
        .await
        .expect("drop trigger");
    store.redeem_verified_personal_invitation(&verified).await.expect("retry succeeds");
    store.pool().close().await;
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_legacy_and_identity_id_collisions_are_generic_and_leave_invitation_unused() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
    for collision in
        ["account", "bundle", "certificate", "revocation", "wrap", "device", "personal", "vault"]
    {
        let invitation = store
            .issue_personal_invitation(*Uuid::now_v7().as_bytes(), ORIGIN)
            .await
            .expect("issue");
        let request = enrollment(*invitation.token_bytes());
        let account = request.account_id.as_bytes();
        let device = request.device_certificate.device_id.as_bytes();
        let vault = request.personal_vault_id.as_bytes();
        match collision {
            "account" => {
                sqlx::query("INSERT INTO identity_accounts (account_id, email, account_signing_public_key, account_kem_public_key, created_at_ms) VALUES (?, NULL, ?, ?, 1)")
                    .bind(account.as_slice()).bind([1; 32].as_slice()).bind([2; 32].as_slice())
                    .execute(store.pool()).await.expect("existing account");
            }
            "bundle" | "wrap" => {
                let bundle_account =
                    if collision == "bundle" { *account } else { *Uuid::now_v7().as_bytes() };
                sqlx::query("INSERT INTO sync_account_key_bundles (account_id, revision, account_signing_key, account_kem_key, recovery_blob, signature, updated_at_ms) VALUES (?, 1, ?, ?, ?, ?, 1)")
                    .bind(bundle_account.as_slice()).bind([1].as_slice()).bind([2].as_slice())
                    .bind([3].as_slice()).bind([4; 64].as_slice())
                    .execute(store.pool()).await.expect("legacy bundle");
                if collision == "wrap" {
                    sqlx::query("INSERT INTO sync_account_key_device_wraps (account_id, device_id, wrapped_ark) VALUES (?, ?, ?)")
                        .bind(bundle_account.as_slice()).bind(device.as_slice()).bind([5].as_slice())
                        .execute(store.pool()).await.expect("legacy wrap");
                }
            }
            "certificate" => {
                sqlx::query("INSERT INTO sync_account_key_certificates (account_id, certificate) VALUES (?, ?)")
                    .bind(account.as_slice()).bind([1].as_slice())
                    .execute(store.pool()).await.expect("legacy certificate");
            }
            "revocation" => {
                sqlx::query("INSERT INTO sync_account_key_revocations (account_id, revocation) VALUES (?, ?)")
                    .bind(account.as_slice()).bind([1].as_slice())
                    .execute(store.pool()).await.expect("legacy revocation");
            }
            "device" => {
                let other_account = Uuid::now_v7();
                sqlx::query("INSERT INTO identity_accounts (account_id, email, account_signing_public_key, account_kem_public_key, created_at_ms) VALUES (?, NULL, ?, ?, 1)")
                    .bind(other_account.as_bytes().as_slice()).bind([1; 32].as_slice()).bind([2; 32].as_slice())
                    .execute(store.pool()).await.expect("other account");
                sqlx::query("INSERT INTO identity_devices (device_id, account_id, certificate, active, created_at_ms) VALUES (?, ?, ?, 1, 1)")
                    .bind(device.as_slice()).bind(other_account.as_bytes().as_slice()).bind([1].as_slice())
                    .execute(store.pool()).await.expect("existing device");
            }
            "personal" => {
                let other_vault = Uuid::now_v7();
                sqlx::query("INSERT INTO sync_vaults (vault_id, kind) VALUES (?, 'personal')")
                    .bind(other_vault.as_bytes().as_slice())
                    .execute(store.pool())
                    .await
                    .expect("other vault");
                sqlx::query("INSERT INTO sync_personal_vaults (account_id, vault_id, wrapped_vault_key) VALUES (?, ?, ?)")
                    .bind(account.as_slice()).bind(other_vault.as_bytes().as_slice()).bind([1].as_slice())
                    .execute(store.pool()).await.expect("legacy personal vault");
            }
            "vault" => {
                sqlx::query("INSERT INTO sync_vaults (vault_id, kind) VALUES (?, 'personal')")
                    .bind(vault.as_slice())
                    .execute(store.pool())
                    .await
                    .expect("legacy vault");
            }
            _ => unreachable!(),
        }
        let verified = verify_personal_enrollment(ORIGIN, &request).expect("verified");
        assert!(
            matches!(
                store.redeem_verified_personal_invitation(&verified).await,
                Err(PersonalInvitationStoreError::Denied)
            ),
            "{collision}"
        );
        let consumed: Option<i64> = sqlx::query_scalar(
            "SELECT consumed_at_ms FROM personal_invitations WHERE invitation_id = ?",
        )
        .bind(invitation.invitation_id().as_slice())
        .fetch_one(store.pool())
        .await
        .expect("invitation");
        assert!(consumed.is_none(), "{collision}");
    }
    store.pool().close().await;
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_wrong_origin_expired_and_concurrent_redeemers_have_no_extra_state() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
    let wrong_origin = store
        .issue_personal_invitation(*Uuid::now_v7().as_bytes(), "https://other.example")
        .await
        .expect("issue");
    let verified = verify_personal_enrollment(ORIGIN, &enrollment(*wrong_origin.token_bytes()))
        .expect("verified");
    assert!(matches!(
        store.redeem_verified_personal_invitation(&verified).await,
        Err(PersonalInvitationStoreError::Denied)
    ));
    let expired =
        store.issue_personal_invitation(*Uuid::now_v7().as_bytes(), ORIGIN).await.expect("issue");
    sqlx::query("UPDATE personal_invitations SET issued_at_ms = issued_at_ms - 86400001, expires_at_ms = expires_at_ms - 86400001 WHERE invitation_id = ?")
        .bind(expired.invitation_id().as_slice()).execute(store.pool()).await.expect("expire");
    let verified =
        verify_personal_enrollment(ORIGIN, &enrollment(*expired.token_bytes())).expect("verified");
    assert!(matches!(
        store.redeem_verified_personal_invitation(&verified).await,
        Err(PersonalInvitationStoreError::Denied)
    ));

    let invitation =
        store.issue_personal_invitation(*Uuid::now_v7().as_bytes(), ORIGIN).await.expect("issue");
    let verified = verify_personal_enrollment(ORIGIN, &enrollment(*invitation.token_bytes()))
        .expect("verified");
    let (first, second) = tokio::join!(
        store.redeem_verified_personal_invitation(&verified),
        store.redeem_verified_personal_invitation(&verified)
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert_eq!(store.deployment_audit_head().await.expect("audit").unwrap().sequence, 4);
    store.pool().close().await;
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_personal_invitation_expiry_is_checked_after_writer_lock_wait() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
    let invitation =
        store.issue_personal_invitation(*Uuid::now_v7().as_bytes(), ORIGIN).await.expect("issue");
    let verified = verify_personal_enrollment(ORIGIN, &enrollment(*invitation.token_bytes()))
        .expect("verified");
    let mut holder = store.pool().begin_with("BEGIN IMMEDIATE").await.expect("writer lock");
    let expiry = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("representable time")
        + 700;
    sqlx::query("UPDATE personal_invitations SET issued_at_ms = ?, expires_at_ms = ? WHERE invitation_id = ?")
        .bind(expiry - 86_400_000).bind(expiry).bind(invitation.invitation_id().as_slice())
        .execute(&mut *holder).await.expect("shorten invitation");
    let store_for_redeem = store.clone();
    let attempt = tokio::spawn(async move {
        store_for_redeem.redeem_verified_personal_invitation(&verified).await
    });
    tokio::time::sleep(Duration::from_millis(900)).await;
    holder.commit().await.expect("release writer lock after expiry");
    assert!(matches!(attempt.await.expect("join"), Err(PersonalInvitationStoreError::Denied)));
    store.pool().close().await;
    remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_personal_enrollment_is_atomic_and_preserves_mutable_k4_statements() {
    use scoplen_store::PostgresStore;

    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("PostgreSQL store");
    let baseline =
        store.deployment_audit_head().await.expect("baseline").map_or(0, |head| head.sequence);
    let invitation =
        store.issue_personal_invitation(*Uuid::now_v7().as_bytes(), ORIGIN).await.expect("issue");
    let request = enrollment(*invitation.token_bytes());
    let verified = verify_personal_enrollment(ORIGIN, &request).expect("verified");
    let receipt = store.redeem_verified_personal_invitation(&verified).await.expect("enroll");
    assert_eq!(receipt.account_id, *request.account_id.as_bytes());
    assert_eq!(
        store
            .get_account_key_bundle(receipt.account_id, receipt.device_id)
            .await
            .expect("K-4")
            .revision,
        1
    );
    assert_eq!(
        store.get_personal_sync_vault_key(receipt.account_id).await.expect("vault").0,
        receipt.personal_vault_id
    );
    assert_eq!(
        store
            .find_active_personal_device(receipt.device_id)
            .await
            .expect("device")
            .unwrap()
            .certificate_cbor(),
        verified.device_certificate_cbor()
    );
    store
        .replace_account_key_statements(
            receipt.account_id,
            &[verified.device_certificate_cbor().to_vec()],
            &[],
        )
        .await
        .expect("replace existing certificate");
    store
        .replace_account_key_statements(receipt.account_id, &[], &[vec![1]])
        .await
        .expect("remove certificate on K-4 revocation");
    assert_eq!(
        store
            .get_account_key_bundle(receipt.account_id, receipt.device_id)
            .await
            .expect("K-4")
            .certificates,
        Vec::<Vec<u8>>::new()
    );
    assert!(matches!(
        store.redeem_verified_personal_invitation(&verified).await,
        Err(PersonalInvitationStoreError::Denied)
    ));

    let collision =
        store.issue_personal_invitation(*Uuid::now_v7().as_bytes(), ORIGIN).await.expect("issue");
    let request = enrollment(*collision.token_bytes());
    let other_account = Uuid::now_v7();
    sqlx::query("INSERT INTO sync_account_key_bundles (account_id, revision, account_signing_key, account_kem_key, recovery_blob, signature, updated_at_ms) VALUES ($1, 1, $2, $3, $4, $5, 1)")
        .bind(other_account.as_bytes().as_slice()).bind(vec![1u8]).bind(vec![2u8])
        .bind(vec![3u8]).bind(vec![4u8; 64]).execute(store.pool()).await.expect("legacy bundle");
    sqlx::query("INSERT INTO sync_account_key_device_wraps (account_id, device_id, wrapped_ark) VALUES ($1, $2, $3)")
        .bind(other_account.as_bytes().as_slice()).bind(request.device_certificate.device_id.as_bytes().as_slice())
        .bind(vec![5u8]).execute(store.pool()).await.expect("legacy wrap");
    let colliding = verify_personal_enrollment(ORIGIN, &request).expect("verified");
    assert!(matches!(
        store.redeem_verified_personal_invitation(&colliding).await,
        Err(PersonalInvitationStoreError::Denied)
    ));
    let consumed: Option<i64> = sqlx::query_scalar(
        "SELECT consumed_at_ms FROM personal_invitations WHERE invitation_id = $1",
    )
    .bind(collision.invitation_id().as_slice())
    .fetch_one(store.pool())
    .await
    .expect("collision invitation");
    assert!(consumed.is_none());

    let late =
        store.issue_personal_invitation(*Uuid::now_v7().as_bytes(), ORIGIN).await.expect("issue");
    let late_request = enrollment(*late.token_bytes());
    let late_verified = verify_personal_enrollment(ORIGIN, &late_request).expect("verified");
    sqlx::query("CREATE FUNCTION personal_enrollment_late_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'late failure'; END; $$")
        .execute(store.pool()).await.expect("test trigger function");
    sqlx::query("CREATE TRIGGER personal_enrollment_late_failure BEFORE INSERT ON sync_personal_vaults FOR EACH ROW EXECUTE FUNCTION personal_enrollment_late_failure()")
        .execute(store.pool()).await.expect("test trigger");
    assert!(store.redeem_verified_personal_invitation(&late_verified).await.is_err());
    sqlx::query("DROP TRIGGER personal_enrollment_late_failure ON sync_personal_vaults")
        .execute(store.pool())
        .await
        .expect("drop trigger");
    sqlx::query("DROP FUNCTION personal_enrollment_late_failure()")
        .execute(store.pool())
        .await
        .expect("drop function");
    let account_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM identity_accounts WHERE account_id = $1")
            .bind(late_request.account_id.as_bytes().as_slice())
            .fetch_one(store.pool())
            .await
            .expect("account count");
    assert_eq!(account_count, 0);
    let consumed: Option<i64> = sqlx::query_scalar(
        "SELECT consumed_at_ms FROM personal_invitations WHERE invitation_id = $1",
    )
    .bind(late.invitation_id().as_slice())
    .fetch_one(store.pool())
    .await
    .expect("late invitation");
    assert!(consumed.is_none());
    assert_eq!(store.deployment_audit_head().await.expect("audit").unwrap().sequence, baseline + 4);
    store.redeem_verified_personal_invitation(&late_verified).await.expect("retry after rollback");
    assert_eq!(store.deployment_audit_head().await.expect("audit").unwrap().sequence, baseline + 5);
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_personal_invitation_concurrent_redeemers_have_one_winner() {
    use scoplen_store::PostgresStore;

    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL test URL");
    let store = PostgresStore::connect(&database_url).await.expect("PostgreSQL store");
    let baseline =
        store.deployment_audit_head().await.expect("baseline").map_or(0, |head| head.sequence);
    let invitation =
        store.issue_personal_invitation(*Uuid::now_v7().as_bytes(), ORIGIN).await.expect("issue");
    let request = enrollment(*invitation.token_bytes());
    let verified = verify_personal_enrollment(ORIGIN, &request).expect("verified");
    let (first, second) = tokio::join!(
        store.redeem_verified_personal_invitation(&verified),
        store.redeem_verified_personal_invitation(&verified)
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert!(
        first
            .as_ref()
            .err()
            .or(second.as_ref().err())
            .is_some_and(|error| matches!(error, PersonalInvitationStoreError::Denied))
    );
    let account_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM identity_accounts WHERE account_id = $1")
            .bind(request.account_id.as_bytes().as_slice())
            .fetch_one(store.pool())
            .await
            .expect("account count");
    assert_eq!(account_count, 1);
    assert_eq!(store.deployment_audit_head().await.expect("audit").unwrap().sequence, baseline + 2);
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_personal_invitation_expiry_is_checked_after_row_lock_wait() {
    use scoplen_store::PostgresStore;

    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL test URL");
    let store = PostgresStore::connect(&database_url).await.expect("PostgreSQL store");
    let invitation =
        store.issue_personal_invitation(*Uuid::now_v7().as_bytes(), ORIGIN).await.expect("issue");
    let verified = verify_personal_enrollment(ORIGIN, &enrollment(*invitation.token_bytes()))
        .expect("verified");
    let mut holder = store.pool().begin().await.expect("holder transaction");
    let expiry = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("representable time")
        + 700;
    sqlx::query("UPDATE personal_invitations SET issued_at_ms = $1, expires_at_ms = $2 WHERE invitation_id = $3")
        .bind(expiry - 86_400_000).bind(expiry).bind(invitation.invitation_id().as_slice())
        .execute(&mut *holder).await.expect("lock and shorten invitation");
    let store_for_redeem = store.clone();
    let attempt = tokio::spawn(async move {
        store_for_redeem.redeem_verified_personal_invitation(&verified).await
    });
    tokio::time::sleep(Duration::from_millis(900)).await;
    holder.commit().await.expect("release row lock after expiry");
    assert!(matches!(attempt.await.expect("join"), Err(PersonalInvitationStoreError::Denied)));
    let consumed: Option<i64> = sqlx::query_scalar(
        "SELECT consumed_at_ms FROM personal_invitations WHERE invitation_id = $1",
    )
    .bind(invitation.invitation_id().as_slice())
    .fetch_one(store.pool())
    .await
    .expect("invitation");
    assert!(consumed.is_none());
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_personal_invitation_audit_failures_roll_back_issue_and_redemption() {
    use scoplen_store::PostgresStore;

    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL test URL");
    let store = PostgresStore::connect(&database_url).await.expect("PostgreSQL store");
    let baseline =
        store.deployment_audit_head().await.expect("baseline").map_or(0, |head| head.sequence);
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM personal_invitations")
        .fetch_one(store.pool())
        .await
        .expect("count invitations");
    sqlx::query("CREATE FUNCTION personal_enrollment_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test audit failure'; END; $$")
        .execute(store.pool()).await.expect("audit test function");
    sqlx::query("CREATE TRIGGER personal_enrollment_audit_failure BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION personal_enrollment_audit_failure()")
        .execute(store.pool()).await.expect("audit test trigger");
    assert!(store.issue_personal_invitation(*Uuid::now_v7().as_bytes(), ORIGIN).await.is_err());
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM personal_invitations")
        .fetch_one(store.pool())
        .await
        .expect("count invitations");
    assert_eq!(after, before);
    assert_eq!(
        store.deployment_audit_head().await.expect("audit").map_or(0, |head| head.sequence),
        baseline
    );
    sqlx::query("DROP TRIGGER personal_enrollment_audit_failure ON deployment_audit_events")
        .execute(store.pool())
        .await
        .expect("drop trigger");
    let invitation =
        store.issue_personal_invitation(*Uuid::now_v7().as_bytes(), ORIGIN).await.expect("issue");
    let request = enrollment(*invitation.token_bytes());
    let verified = verify_personal_enrollment(ORIGIN, &request).expect("verified");
    sqlx::query("CREATE TRIGGER personal_enrollment_audit_failure BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION personal_enrollment_audit_failure()")
        .execute(store.pool()).await.expect("audit test trigger");
    assert!(store.redeem_verified_personal_invitation(&verified).await.is_err());
    sqlx::query("DROP TRIGGER personal_enrollment_audit_failure ON deployment_audit_events")
        .execute(store.pool())
        .await
        .expect("drop trigger");
    sqlx::query("DROP FUNCTION personal_enrollment_audit_failure()")
        .execute(store.pool())
        .await
        .expect("drop function");
    for (table, column, id) in [
        ("identity_accounts", "account_id", request.account_id),
        ("identity_devices", "device_id", request.device_certificate.device_id),
        ("sync_account_key_bundles", "account_id", request.account_id),
        ("sync_vaults", "vault_id", request.personal_vault_id),
    ] {
        let query = format!("SELECT COUNT(*) FROM {table} WHERE {column} = $1");
        let count: i64 = sqlx::query_scalar(&query)
            .bind(id.as_bytes().as_slice())
            .fetch_one(store.pool())
            .await
            .expect("rolled-back row count");
        assert_eq!(count, 0, "{table} rolled back");
    }
    let consumed: Option<i64> = sqlx::query_scalar(
        "SELECT consumed_at_ms FROM personal_invitations WHERE invitation_id = $1",
    )
    .bind(invitation.invitation_id().as_slice())
    .fetch_one(store.pool())
    .await
    .expect("invitation");
    assert!(consumed.is_none());
    assert_eq!(store.deployment_audit_head().await.expect("audit").unwrap().sequence, baseline + 1);
    store.redeem_verified_personal_invitation(&verified).await.expect("retry after audit failure");
    assert_eq!(store.deployment_audit_head().await.expect("audit").unwrap().sequence, baseline + 2);
    store.pool().close().await;
}
