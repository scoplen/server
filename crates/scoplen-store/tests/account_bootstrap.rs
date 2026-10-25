// SPDX-License-Identifier: AGPL-3.0-only

#[path = "support/legacy_identity.rs"]
mod legacy_identity;
#[path = "support/pool_close.rs"]
mod pool_close;
mod support;

use legacy_identity::LegacyIdentity;
use scoplen_api::{
    account_admission::{AccountBootstrapSnapshot, AccountRegistrationPayload},
    sync::SyncAccountKeyBundleUpdate,
};
use scoplen_crypto::{
    AccountKemKeyWrap, AccountSigningKeyWrap, DeviceArkWrap, DeviceCertificate, DeviceKemKeyPair,
    Ed25519SigningKey, P256SigningKey, PasswordArkWrap, PasswordBootstrapContext, PasswordSecrets,
    PasswordVerifier, PersonalVaultKeyWrap, SecretBytes, SecretVec,
};
#[cfg(feature = "postgres-integration")]
use scoplen_store::{
    PostgresStore,
    account_bootstrap::{
        create_postgres_password_account_in_transaction,
        read_postgres_password_bootstrap_in_transaction,
    },
    append_deployment_audit_event_in_postgres_transaction,
};
use scoplen_store::{
    RelationalStore, SqliteStore,
    account_bootstrap::{
        AccountBootstrapError, create_sqlite_password_account_in_transaction,
        read_sqlite_password_bootstrap_in_transaction,
    },
    account_keys::{AccountKeyBundlePut, AccountKeyBundleUpdate, AccountKeyStoreError},
    account_used_ids::AccountIdRetentionError,
    append_deployment_audit_event_in_transaction,
    sync::SyncStoreError,
};
use std::path::PathBuf;
use uuid::Uuid;

const ORIGIN: &str = "https://bootstrap.test";
const CEILING: u64 = 16;

struct Fixture {
    payload: AccountRegistrationPayload,
    secrets: PasswordSecrets,
}

fn signing_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[1; 32]).expect("Account signing key")
}

fn device_key() -> P256SigningKey {
    let mut scalar = [0; 32];
    scalar[31] = 1;
    P256SigningKey::from_bytes(&scalar).expect("Device signing key")
}

fn fixture(username: &str) -> Fixture {
    let identity = LegacyIdentity::new(&signing_key(), &device_key());
    let secrets = PasswordSecrets::create(
        ORIGIN,
        username,
        SecretVec::new(b"a long test password for bootstrap".to_vec()),
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
    .expect("password context");
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
        key_bundle: identity.key_bundle_update.to_cbor().expect("signed PUT"),
        personal_wrapped_key: identity
            .wrapped_personal_vault_key
            .try_into()
            .expect("Personal wrap"),
    };
    payload.validate().expect("real initial material");
    Fixture { payload, secrets }
}

fn certificate(account: Uuid, device: Uuid) -> Vec<u8> {
    DeviceCertificate::issue(
        &signing_key(),
        device,
        account,
        device_key().public_key_sec1(),
        DeviceKemKeyPair::from_private_bytes(&[3; 32]).expect("Device KEM").public_key().to_vec(),
        "Bootstrap test device".into(),
        "test".into(),
        1,
    )
    .expect("signed Device certificate")
    .encode()
    .expect("certificate bytes")
}

fn set_device(fixture: &mut Fixture, device: Uuid) {
    let payload = &mut fixture.payload;
    payload.device_id = device;
    payload.device_certificate = certificate(payload.account_id, device);
    let mut bundle = SyncAccountKeyBundleUpdate::from_cbor(&payload.key_bundle).expect("bundle");
    bundle.device_wraps[0].device_id = device;
    bundle.device_wraps[0].wrapped_ark = DeviceArkWrap::seal(
        payload.account_id,
        device,
        DeviceKemKeyPair::from_private_bytes(&[3; 32]).expect("Device KEM").public_key(),
        &SecretBytes::new([11; 32]),
    )
    .expect("Device wrap")
    .encode()
    .to_vec();
    sign(&mut bundle);
    payload.key_bundle = bundle.to_cbor().expect("signed bundle");
}

fn set_vault(fixture: &mut Fixture, vault: Uuid) {
    let payload = &mut fixture.payload;
    payload.personal_vault_id = vault;
    let context = PasswordBootstrapContext::new(
        fixture.secrets.context().clone(),
        payload.account_id,
        vault,
        &payload.account_signing_public_key,
        &payload.account_kem_public_key,
        1,
    )
    .expect("new vault binding");
    payload.password_ark =
        PasswordArkWrap::seal(&fixture.secrets, &context, &SecretBytes::new([11; 32]))
            .expect("rebound password wrap")
            .encode();
    payload.personal_wrapped_key = PersonalVaultKeyWrap::seal(
        payload.account_id,
        vault,
        1,
        &SecretBytes::new([11; 32]),
        &SecretBytes::new([8; 32]),
    )
    .expect("rebound Personal key")
    .encode();
}

fn sign(bundle: &mut SyncAccountKeyBundleUpdate) {
    bundle.signature =
        signing_key().sign(&bundle.signature_input().expect("bundle signature input")).to_vec();
}

fn verify_open(snapshot: &AccountBootstrapSnapshot, fixture: &Fixture) {
    let context = PasswordBootstrapContext::new(
        fixture.secrets.context().clone(),
        snapshot.account_id,
        snapshot.personal_vault_id,
        &snapshot.account_signing_public_key,
        &snapshot.account_kem_public_key,
        snapshot.credential_generation,
    )
    .expect("snapshot password context");
    let bundle = SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle).expect("complete PUT");
    fixture
        .secrets
        .open_bootstrap(
            &context,
            &PasswordArkWrap::decode(&snapshot.password_ark).expect("password wrap"),
            &AccountSigningKeyWrap::decode(&bundle.account_signing_key).expect("signing wrap"),
            &AccountKemKeyWrap::decode(&bundle.account_kem_key).expect("KEM wrap"),
        )
        .expect("real password opens both matching roots");
}

fn test_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!("scoplen-account-bootstrap-{}", Uuid::new_v4()));
    std::fs::create_dir(&path).expect("owned test directory");
    path
}

fn sql(source: &str, postgres: bool) -> String {
    if !postgres {
        return source.into();
    }
    let mut parameter = 0;
    source
        .chars()
        .map(|character| {
            if character == '?' {
                parameter += 1;
                format!("${parameter}")
            } else {
                character.to_string()
            }
        })
        .collect()
}

macro_rules! lifecycle {
    ($store:expr, $create:ident, $read:ident, $append:ident, $pg:literal) => {{
        let store = &$store;
        store.initialize_account_id_retention(CEILING).await.expect("retention admission");
        let fixture = fixture("bootstrap-user");
        let payload = &fixture.payload;
        sqlx::query("CREATE TABLE bootstrap_outer_marker (value BIGINT PRIMARY KEY)")
            .execute(store.pool())
            .await
            .expect("caller-owned protocol marker");
        let mut tx = store.pool().begin().await.expect("business transaction");
        sqlx::query("INSERT INTO bootstrap_outer_marker (value) VALUES (1)")
            .execute(&mut *tx)
            .await
            .expect("caller protocol state");
        let staged =
            $create(&mut tx, ORIGIN, CEILING, payload, 1).await.expect("complete aggregate staged");
        let snapshot = AccountBootstrapSnapshot::from_cbor(staged.as_bytes())
            .expect("published complete snapshot");
        assert_eq!(snapshot.account_id, payload.account_id);
        assert_eq!(snapshot.personal_vault_id, payload.personal_vault_id);
        assert!(snapshot.key_bundle == payload.key_bundle);
        assert_eq!(snapshot.certificates.len(), 1);
        assert!(snapshot.revocations.is_empty());
        verify_open(&snapshot, &fixture);
        let repeated =
            $read(&mut tx, ORIGIN, payload.account_id).await.expect("same transaction snapshot");
        assert!(staged.as_bytes() == repeated.as_bytes());
        let hidden: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_password_bootstrap")
            .fetch_one(store.pool())
            .await
            .expect("uncommitted state stays hidden");
        assert_eq!(hidden, 0);
        $append(&mut tx, b"bootstrap outer success", 1).await.expect("mandatory caller audit");
        tx.commit().await.expect("one outer commit");
        let mut tx = store.pool().begin().await.expect("fresh read transaction");
        let current =
            $read(&mut tx, ORIGIN, payload.account_id).await.expect("committed complete snapshot");
        assert!(current.as_bytes() == staged.as_bytes());
        tx.commit().await.expect("read completed");
        let stored: Vec<u8> = sqlx::query_scalar("SELECT verifier FROM account_password_bootstrap")
            .fetch_one(store.pool())
            .await
            .expect("verifier only");
        assert!(stored.as_slice() == payload.verifier);
        assert!(stored.as_slice() != fixture.secrets.auth_secret().as_ref());
        PasswordVerifier::from_bytes(&stored)
            .expect("verifier representation")
            .verify(SecretVec::new(fixture.secrets.auth_secret().as_ref().to_vec()))
            .expect("published constant-time verifier");
        for table in [
            "identity_accounts",
            "identity_devices",
            "sync_vaults",
            "sync_personal_vaults",
            "account_password_bootstrap",
            "account_used_ids",
            "bootstrap_outer_marker",
        ] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(store.pool())
                .await
                .expect("aggregate count");
            assert_eq!(count, 1, "{table}");
        }
        for table in [
            "device_auth_challenges",
            "device_refresh_families",
            "device_refresh_tokens",
            "device_dpop_replays",
        ] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(store.pool())
                .await
                .expect("no session issuance");
            assert_eq!(count, 0, "{table}");
        }
        assert_eq!(
            store.deployment_audit_head().await.expect("audit head").expect("outer audit").sequence,
            2
        );
        staged
    }};
}

macro_rules! rollback {
    ($store:expr, $create:ident, $append:ident, $pg:literal) => {{
        let store = &$store;
        store.initialize_account_id_retention(1).await.expect("one lifetime slot");
        let fixture = fixture("bootstrap-rollback");
        sqlx::query("CREATE TABLE bootstrap_outer_marker (value BIGINT PRIMARY KEY)")
            .execute(store.pool())
            .await
            .expect("owned outer state");
        let mut tx = store.pool().begin().await.expect("transaction");
        sqlx::query("INSERT INTO bootstrap_outer_marker (value) VALUES (1)")
            .execute(&mut *tx)
            .await
            .expect("outer state staged");
        $create(&mut tx, ORIGIN, 1, &fixture.payload, 1).await.expect("staged aggregate");
        assert!($append(&mut tx, b"bootstrap outer success", 1).await.is_err());
        tx.rollback().await.expect("whole transaction rollback");
        for table in [
            "identity_accounts",
            "identity_devices",
            "sync_vaults",
            "sync_personal_vaults",
            "sync_account_key_bundles",
            "sync_account_key_certificates",
            "sync_account_key_device_wraps",
            "account_password_bootstrap",
            "account_used_ids",
            "bootstrap_outer_marker",
        ] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(store.pool())
                .await
                .expect("rolled-back rows");
            assert_eq!(count, 0, "{table}");
        }
        assert_eq!(
            store
                .deployment_audit_head()
                .await
                .expect("audit")
                .expect("initialization only")
                .sequence,
            1
        );
        fixture
    }};
}

macro_rules! retry_and_capacity {
    ($store:expr, $payload:expr, $create:ident, $append:ident) => {{
        let store = &$store;
        let mut tx =
            store.pool().begin().await.expect("same exact Account can be staged after rollback");
        $create(&mut tx, ORIGIN, 1, $payload, 1).await.expect("reservation rolled back too");
        $append(&mut tx, b"bootstrap retry success", 1).await.expect("caller audit after recovery");
        tx.commit().await.expect("test capacity occupant");
        let next = fixture("bootstrap-capacity");
        let mut tx = store.pool().begin().await.expect("quota transaction");
        assert!(matches!(
            $create(&mut tx, ORIGIN, 1, &next.payload, 1).await,
            Err(AccountBootstrapError::Retention(AccountIdRetentionError::QuotaExceeded))
        ));
        tx.rollback().await.expect("quota rollback");
        assert_eq!(store.account_id_retention_summary().await.expect("retention summary").used, 1);
    }};
}

macro_rules! conflicts {
    ($store:expr, $create:ident, $pg:literal) => {{
        let store = &$store;
        store.initialize_account_id_retention(CEILING).await.expect("retention admission");
        let existing = fixture("bootstrap-existing");
        let mut tx = store.pool().begin().await.expect("initial transaction");
        $create(&mut tx, ORIGIN, CEILING, &existing.payload, 1).await.expect("existing Account");
        tx.commit().await.expect("fixture commit");
        let mut username = fixture("bootstrap-existing");
        let mut device = fixture("bootstrap-device");
        set_device(&mut device, existing.payload.device_id);
        let mut vault = fixture("bootstrap-vault");
        set_vault(&mut vault, existing.payload.personal_vault_id);
        for candidate in [&mut username, &mut device, &mut vault] {
            candidate.payload.validate().expect("valid conflicting registration material");
            let mut tx = store.pool().begin().await.expect("conflict transaction");
            assert!(matches!(
                $create(&mut tx, ORIGIN, CEILING, &candidate.payload, 1).await,
                Err(AccountBootstrapError::Conflict)
            ));
            tx.rollback().await.expect("partial inserts rolled back");
            assert_eq!(
                store.account_id_retention_summary().await.expect("guard unchanged").used,
                1
            );
        }
        let mut tx = store.pool().begin().await.expect("existing id transaction");
        assert!(matches!(
            $create(&mut tx, ORIGIN, CEILING, &existing.payload, 1).await,
            Err(AccountBootstrapError::Retention(AccountIdRetentionError::Conflict))
        ));
        tx.rollback().await.expect("existing id rollback");
        let mut invalid = fixture("bootstrap-invalid");
        for (origin, time) in [("https://another.test", 1), (ORIGIN, 0)] {
            let mut tx = store.pool().begin().await.expect("invalid context");
            assert!(matches!(
                $create(&mut tx, origin, CEILING, &invalid.payload, time).await,
                Err(AccountBootstrapError::InvalidInput)
            ));
            tx.rollback().await.expect("invalid context rollback");
        }
        invalid.payload.device_certificate[0] ^= 1;
        let mut tx = store.pool().begin().await.expect("invalid artifact");
        assert!(matches!(
            $create(&mut tx, ORIGIN, CEILING, &invalid.payload, 1).await,
            Err(AccountBootstrapError::InvalidInput)
        ));
        tx.rollback().await.expect("invalid artifact rollback");
        for table in [
            "identity_accounts",
            "identity_devices",
            "sync_vaults",
            "account_password_bootstrap",
            "account_used_ids",
        ] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(store.pool())
                .await
                .expect("no partial aggregate");
            assert_eq!(count, 1, "{table}");
        }
    }};
}

macro_rules! corruption {
    ($store:expr, $create:ident, $read:ident, $pg:literal) => {{
        let store = &$store;
        store.initialize_account_id_retention(CEILING).await.expect("retention admission");
        let fixture = fixture("bootstrap-corruption");
        let payload = &fixture.payload;
        let mut tx = store.pool().begin().await.expect("initial transaction");
        let original =
            $create(&mut tx, ORIGIN, CEILING, payload, 1).await.expect("initial aggregate");
        tx.commit().await.expect("fixture commit");
        let remove_guard = if $pg {
            "DROP TRIGGER account_password_bootstrap_guard ON account_password_bootstrap"
        } else {
            "DROP TRIGGER account_password_bootstrap_immutable"
        };
        sqlx::query(remove_guard)
            .execute(store.pool())
            .await
            .expect("private fixture removes immutability guard to model corruption");
        for query in [
            "UPDATE sync_account_key_bundles SET accepted_put_cbor=NULL",
            "UPDATE sync_personal_vaults SET key_epoch=2",
            "UPDATE sync_vaults SET rotation_pending=TRUE",
            "DELETE FROM sync_account_key_certificates",
            "DELETE FROM sync_personal_vaults",
        ] {
            let mut tx = store.pool().begin().await.expect("owned damage transaction");
            sqlx::query(query).execute(&mut *tx).await.expect("owned damage");
            assert!($read(&mut tx, ORIGIN, payload.account_id).await.is_err(), "{query}");
            tx.rollback().await.expect("restore original snapshot");
        }
        for (query, bytes) in [
            ("UPDATE account_password_bootstrap SET password_ark=?", vec![0_u8; 73]),
            (
                "UPDATE account_password_bootstrap SET personal_vault_id=?",
                Uuid::now_v7().as_bytes().to_vec(),
            ),
            (
                "UPDATE identity_accounts SET account_signing_public_key=?",
                signing_key().sign(b"wrong root")[..32].to_vec(),
            ),
            ("UPDATE identity_accounts SET account_kem_public_key=?", vec![9_u8; 32]),
            ("UPDATE sync_personal_vaults SET wrapped_vault_key=?", vec![0_u8; 73]),
            ("UPDATE sync_account_key_bundles SET account_signing_key=?", vec![0_u8; 73]),
            ("UPDATE sync_account_key_certificates SET certificate=?", vec![0_u8; 20]),
        ] {
            let mut tx = store.pool().begin().await.expect("owned artifact corruption");
            sqlx::query(&sql(query, $pg))
                .bind(bytes)
                .execute(&mut *tx)
                .await
                .expect("damage artifact");
            assert!($read(&mut tx, ORIGIN, payload.account_id).await.is_err(), "{query}");
            tx.rollback().await.expect("restore artifact");
        }
        let mut tx = store.pool().begin().await.expect("complete recipient corruption");
        sqlx::query(&sql(
            "INSERT INTO sync_account_key_certificates (account_id,certificate) VALUES (?,?)",
            $pg,
        ))
        .bind(payload.account_id.as_bytes().as_slice())
        .bind(certificate(payload.account_id, Uuid::now_v7()))
        .execute(&mut *tx)
        .await
        .expect("additional valid signed recipient");
        assert!(matches!(
            $read(&mut tx, ORIGIN, payload.account_id).await,
            Err(AccountBootstrapError::Integrity)
        ));
        tx.rollback().await.expect("restore recipient set");
        let mut bundle =
            SyncAccountKeyBundleUpdate::from_cbor(&payload.key_bundle).expect("signed PUT");
        bundle.signature = vec![99; 64];
        let mut tx =
            store.pool().begin().await.expect("self-consistent projection with bad signature");
        sqlx::query(&sql(
            "UPDATE sync_account_key_bundles SET signature=?,accepted_put_cbor=?",
            $pg,
        ))
        .bind(&bundle.signature)
        .bind(bundle.to_cbor().expect("structurally valid PUT"))
        .execute(&mut *tx)
        .await
        .expect("damage signature and evidence together");
        assert!(matches!(
            $read(&mut tx, ORIGIN, payload.account_id).await,
            Err(AccountBootstrapError::Integrity)
        ));
        tx.rollback().await.expect("restore valid signature");
        let mut tx = store.pool().begin().await.expect("inactive server admission row");
        sqlx::query("UPDATE identity_devices SET active=FALSE")
            .execute(&mut *tx)
            .await
            .expect("inactivate admission row");
        let unchanged = $read(&mut tx, ORIGIN, payload.account_id)
            .await
            .expect("unrevoked signed certificate is not filtered out");
        assert!(unchanged.as_bytes() == original.as_bytes());
        tx.rollback().await.expect("restore active flag");
        let mut tx = store.pool().begin().await.expect("trusted origin mismatch");
        assert!(matches!(
            $read(&mut tx, "https://another.test", payload.account_id).await,
            Err(AccountBootstrapError::Integrity)
        ));
        tx.rollback().await.expect("failed read rollback");
    }};
}

macro_rules! writers {
    ($store:expr, $create:ident, $read:ident, $pg:literal) => {{
        let store = &$store;
        store.initialize_account_id_retention(CEILING).await.expect("retention admission");
        let fixture = fixture("bootstrap-writers");
        let payload = &fixture.payload;
        let account = payload.account_id.into_bytes();
        let mut tx = store.pool().begin().await.expect("initial transaction");
        $create(&mut tx, ORIGIN, CEILING, payload, 1).await.expect("initial aggregate");
        tx.commit().await.expect("fixture commit");
        let principal = store
            .current_device_principal(payload.device_id.into_bytes())
            .await
            .expect("current principal")
            .expect("active Device");
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
            + scoplen_api::auth::ACCESS_TOKEN_EXPIRES_IN;
        let mut bundle =
            SyncAccountKeyBundleUpdate::from_cbor(&payload.key_bundle).expect("initial PUT");
        bundle.revision = 2;
        sign(&mut bundle);
        assert_eq!(
            store
                .publish_account_key_bundle(&principal, expiry, &bundle)
                .await
                .expect("unchanged protected artifacts"),
            AccountKeyBundlePut::Applied { revision: 2 }
        );
        let current = bundle.to_cbor().expect("accepted current PUT");
        let before = store.deployment_audit_head().await.expect("audit").expect("head");
        for field in 0..5 {
            let mut candidate = bundle.clone();
            candidate.revision = 3;
            match field {
                0 => candidate.account_signing_key[1] ^= 1,
                1 => candidate.account_kem_key[1] ^= 1,
                2 => candidate.recovery_blob[1] ^= 1,
                3 => candidate.device_wraps[0].wrapped_ark[1] ^= 1,
                _ => candidate.device_wraps[0].device_id = Uuid::now_v7(),
            }
            sign(&mut candidate);
            assert!(matches!(
                store.publish_account_key_bundle(&principal, expiry, &candidate).await,
                Err(AccountKeyStoreError::UnsupportedTransition)
            ));
        }
        let raw = AccountKeyBundleUpdate::try_from(&bundle).expect("current projection");
        assert_eq!(
            store.put_account_key_bundle(account, &raw).await.expect("lower-level exact replay"),
            AccountKeyBundlePut::Replay { revision: 2 }
        );
        let mut next = bundle.clone();
        next.revision = 3;
        sign(&mut next);
        assert!(matches!(
            store
                .put_account_key_bundle(
                    account,
                    &AccountKeyBundleUpdate::try_from(&next).expect("next projection")
                )
                .await,
            Err(AccountKeyStoreError::UnsupportedTransition)
        ));
        assert!(matches!(
            store
                .replace_account_key_statements(
                    account,
                    std::slice::from_ref(&payload.device_certificate),
                    &[]
                )
                .await,
            Err(AccountKeyStoreError::UnsupportedTransition)
        ));
        sqlx::query("UPDATE sync_vaults SET rotation_pending=TRUE")
            .execute(store.pool())
            .await
            .expect("unsupported pending lifecycle");
        assert_eq!(
            store
                .publish_account_key_bundle(&principal, expiry, &bundle)
                .await
                .expect("exact replay before unsupported-state check"),
            AccountKeyBundlePut::Replay { revision: 2 }
        );
        assert!(matches!(
            store.publish_account_key_bundle(&principal, expiry, &next).await,
            Err(AccountKeyStoreError::UnsupportedTransition)
        ));
        sqlx::query("UPDATE sync_vaults SET rotation_pending=FALSE")
            .execute(store.pool())
            .await
            .expect("restore pending state");
        assert_eq!(
            store.deployment_audit_head().await.expect("audit unchanged").expect("head"),
            before
        );
        assert!(
            store
                .read_accepted_account_key_put(account)
                .await
                .expect("acceptance retained")
                .expect("evidence")
                == current
        );
        let mut tx = store.pool().begin().await.expect("current bootstrap");
        let snapshot =
            $read(&mut tx, ORIGIN, payload.account_id).await.expect("consistent advanced snapshot");
        let snapshot =
            AccountBootstrapSnapshot::from_cbor(snapshot.as_bytes()).expect("validated snapshot");
        assert!(snapshot.key_bundle == current);
        verify_open(&snapshot, &fixture);
        tx.commit().await.expect("bootstrap read committed");
        sqlx::query("DELETE FROM sync_personal_vaults")
            .execute(store.pool())
            .await
            .expect("owned missing Personal projection");
        let replacement = Uuid::now_v7().into_bytes();
        assert!(matches!(
            store
                .create_personal_sync_vault(replacement, account, &payload.personal_wrapped_key)
                .await,
            Err(SyncStoreError::VaultAlreadyExists)
        ));
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sync_vaults")
            .fetch_one(store.pool())
            .await
            .expect("no replacement vault");
        assert_eq!(count, 1);
    }};
}

macro_rules! legacy {
    ($store:expr, $read:ident, $seed:path, $pg:literal) => {{
        let store = &$store;
        let identity = LegacyIdentity::new(&signing_key(), &device_key());
        $seed(store.pool(), &identity, true).await;
        store.initialize_account_id_retention(CEILING).await.expect("legacy id backfill");
        let marked: bool = sqlx::query_scalar("SELECT password_owned FROM identity_accounts").fetch_one(store.pool()).await.expect("legacy default marker");
        assert!(!marked);
        let mut tx = store.pool().begin().await.expect("forbidden legacy conversion");
        assert!(sqlx::query("UPDATE identity_accounts SET password_owned=TRUE").execute(&mut *tx).await.is_err());
        tx.rollback().await.expect("legacy marker unchanged");
        if !$pg {
            let mut tx = store.pool().begin().await.expect("forbidden legacy Account replacement conversion");
            assert!(sqlx::query("INSERT OR REPLACE INTO identity_accounts (account_id,account_signing_public_key,account_kem_public_key,created_at_ms,password_owned) VALUES (?,?,?,?,TRUE)")
                .bind(identity.account_id.as_bytes().as_slice()).bind(identity.account_signing_public_key.as_slice()).bind(identity.account_kem_public_key.as_slice()).bind(1_i64).execute(&mut *tx).await.is_err());
            tx.rollback().await.expect("legacy replacement rollback");
        }
        let attachment = fixture("legacy-attachment");
        let payload = &attachment.payload;
        let mut tx = store.pool().begin().await.expect("forbidden credential attachment");
        assert!(sqlx::query(&sql("INSERT INTO account_password_bootstrap (account_id,origin,username,credential_generation,password_profile,password_salt,verifier,password_ark,personal_vault_id,account_signing_public_key,account_kem_public_key) VALUES (?,?,?,1,1,?,?,?,?,?,?)", $pg))
            .bind(identity.account_id.as_bytes().as_slice()).bind(&payload.origin).bind(&payload.username).bind(payload.password_salt.as_slice()).bind(payload.verifier.as_slice()).bind(payload.password_ark.as_slice()).bind(payload.personal_vault_id.as_bytes().as_slice()).bind(payload.account_signing_public_key.as_slice()).bind(payload.account_kem_public_key.as_slice()).execute(&mut *tx).await.is_err());
        tx.rollback().await.expect("legacy attachment rollback");
        let mut tx = store.pool().begin().await.expect("legacy bootstrap read");
        assert!(matches!(
            $read(&mut tx, ORIGIN, identity.account_id).await,
            Err(AccountBootstrapError::NotEstablished)
        ));
        tx.rollback().await.expect("legacy read rollback");
        let current = AccountKeyBundleUpdate::try_from(&identity.key_bundle_update)
            .expect("legacy projection");
        assert_eq!(
            store
                .put_account_key_bundle(identity.account_id.into_bytes(), &current)
                .await
                .expect("legacy replay"),
            AccountKeyBundlePut::Replay { revision: 1 }
        );
        let mut next = identity.key_bundle_update.clone();
        next.revision = 2;
        next.device_wraps[0].wrapped_ark[1] ^= 1;
        sign(&mut next);
        assert_eq!(
            store
                .put_account_key_bundle(
                    identity.account_id.into_bytes(),
                    &AccountKeyBundleUpdate::try_from(&next).expect("legacy next projection")
                )
                .await
                .expect("ordinary legacy mutation"),
            AccountKeyBundlePut::Applied { revision: 2 }
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_password_bootstrap")
            .fetch_one(store.pool())
            .await
            .expect("legacy password absence");
        assert_eq!(count, 0);
    }};
}

macro_rules! ownership {
    ($store:expr, $create:ident, $read:ident, $pg:literal) => {{
        let store = &$store;
        store.initialize_account_id_retention(CEILING).await.expect("guard");
        let fixture = fixture("bootstrap-ownership");
        let payload = &fixture.payload;
        let account = payload.account_id.into_bytes();
        let mut tx = store.pool().begin().await.expect("initial transaction");
        $create(&mut tx, ORIGIN, CEILING, payload, 1).await.expect("password aggregate");
        tx.commit().await.expect("fixture committed");
        for query in [
            "UPDATE identity_accounts SET password_owned=FALSE",
            "DELETE FROM account_password_bootstrap",
            "UPDATE account_password_bootstrap SET credential_generation=2",
        ] {
            let mut tx = store.pool().begin().await.expect("forbidden ownership mutation");
            assert!(sqlx::query(query).execute(&mut *tx).await.is_err(), "{query}");
            tx.rollback().await.expect("guard failure rollback");
        }
        if $pg {
            let mut tx = store.pool().begin().await.expect("owned shadow-schema fixture");
            sqlx::query("CREATE TEMP TABLE identity_accounts (account_id BYTEA, password_owned BOOLEAN)").execute(&mut *tx).await.expect("empty shadow cannot bypass production guard");
            assert!(sqlx::query("TRUNCATE account_password_bootstrap").execute(&mut *tx).await.is_err());
            tx.rollback().await.expect("remove shadow fixture");
        } else {
            for marked in [false, true] {
                let mut tx = store.pool().begin().await.expect("forbidden password Account replacement");
                assert!(sqlx::query("INSERT OR REPLACE INTO identity_accounts (account_id,account_signing_public_key,account_kem_public_key,created_at_ms,password_owned) VALUES (?,?,?,?,?)")
                    .bind(account.as_slice()).bind(payload.account_signing_public_key.as_slice()).bind(payload.account_kem_public_key.as_slice()).bind(1_i64).bind(marked).execute(&mut *tx).await.is_err());
                tx.rollback().await.expect("replacement rollback");
            }
        }
        let remove_guard = if $pg { "DROP TRIGGER account_password_bootstrap_guard ON account_password_bootstrap" } else { "DROP TRIGGER account_password_bootstrap_delete" };
        let restore_guard = if $pg {
            "CREATE TRIGGER account_password_bootstrap_guard BEFORE INSERT OR UPDATE OR DELETE ON account_password_bootstrap FOR EACH ROW EXECUTE FUNCTION guard_account_password_bootstrap()"
        } else {
            "CREATE TRIGGER account_password_bootstrap_delete BEFORE DELETE ON account_password_bootstrap WHEN EXISTS (SELECT 1 FROM identity_accounts WHERE account_id=OLD.account_id) BEGIN SELECT RAISE(ABORT,'Account password bootstrap requires Account deletion'); END"
        };
        let mut tx = store.pool().begin().await.expect("owned missing-credential corruption");
        sqlx::query(remove_guard).execute(&mut *tx).await.expect("private fixture removes deletion guard");
        sqlx::query("DELETE FROM account_password_bootstrap").execute(&mut *tx).await.expect("simulate missing credential");
        sqlx::query(restore_guard).execute(&mut *tx).await.expect("restore production guard before exercising APIs");
        tx.commit().await.expect("owned damaged credential state");
        let marked: bool = sqlx::query_scalar("SELECT password_owned FROM identity_accounts").fetch_one(store.pool()).await.expect("durable ownership marker");
        assert!(marked);
        let mut tx = store.pool().begin().await.expect("damaged bootstrap read");
        let error = $read(&mut tx, ORIGIN, payload.account_id).await.expect_err("missing password bootstrap fails closed");
        assert!(!matches!(error, AccountBootstrapError::NotEstablished));
        tx.rollback().await.expect("damaged read rollback");
        let bundle = SyncAccountKeyBundleUpdate::from_cbor(&payload.key_bundle).expect("exact current PUT");
        let principal = store.current_device_principal(payload.device_id.into_bytes()).await.expect("principal").expect("active Device");
        let expiry = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_secs() + scoplen_api::auth::ACCESS_TOKEN_EXPIRES_IN;
        assert!(store.publish_account_key_bundle(&principal, expiry, &bundle).await.is_err());
        assert!(store.put_account_key_bundle(account, &AccountKeyBundleUpdate::try_from(&bundle).expect("exact projection")).await.is_err());
        assert!(store.replace_account_key_statements(account, std::slice::from_ref(&payload.device_certificate), &[]).await.is_err());
        assert!(store.create_personal_sync_vault(Uuid::now_v7().into_bytes(), account, &payload.personal_wrapped_key).await.is_err());
        sqlx::query(&sql("INSERT INTO account_password_bootstrap (account_id,origin,username,credential_generation,password_profile,password_salt,verifier,password_ark,personal_vault_id,account_signing_public_key,account_kem_public_key) VALUES (?,?,?,1,1,?,?,?,?,?,?)", $pg))
            .bind(account.as_slice()).bind(&payload.origin).bind(&payload.username).bind(payload.password_salt.as_slice()).bind(payload.verifier.as_slice()).bind(payload.password_ark.as_slice()).bind(payload.personal_vault_id.as_bytes().as_slice()).bind(payload.account_signing_public_key.as_slice()).bind(payload.account_kem_public_key.as_slice()).execute(store.pool()).await.expect("restore exact owned credential fixture");
        let mut tx = store.pool().begin().await.expect("parent cascade transaction");
        sqlx::query("DELETE FROM identity_devices").execute(&mut *tx).await.expect("remove independent non-cascading Device reference");
        sqlx::query("DELETE FROM identity_accounts").execute(&mut *tx).await.expect("parent Account deletion permits password cascade");
        tx.commit().await.expect("cascade committed");
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_password_bootstrap").fetch_one(store.pool()).await.expect("password ordinary-lifetime state removed");
        assert_eq!(remaining, 0);
        assert_eq!(store.account_id_retention_summary().await.expect("permanent used id retained").used, 1);
    }};
}

macro_rules! skipped_device {
    ($store:expr, $create:ident) => {{
        let store = &$store;
        let fixture = fixture("bootstrap-skipped-device");
        let mut tx = store.pool().begin().await.expect("owned transaction");
        assert!(matches!(
            $create(&mut tx, ORIGIN, CEILING, &fixture.payload, 1).await,
            Err(AccountBootstrapError::Integrity)
        ));
        tx.rollback().await.expect("whole caller rollback");
        assert_eq!(store.account_id_retention_summary().await.expect("no retained slot").used, 0);
        for table in
            ["identity_accounts", "identity_devices", "sync_vaults", "account_password_bootstrap"]
        {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(store.pool())
                .await
                .expect("no partial aggregate");
            assert_eq!(count, 0, "{table}");
        }
    }};
}

#[tokio::test]
async fn sqlite_initial_password_aggregate_is_atomic_complete_and_reopens() {
    let directory = test_directory();
    let path = directory.join("store.sqlite");
    let store = SqliteStore::open(&path).await.expect("store");
    let bytes = lifecycle!(
        store,
        create_sqlite_password_account_in_transaction,
        read_sqlite_password_bootstrap_in_transaction,
        append_deployment_audit_event_in_transaction,
        false
    );
    let snapshot = AccountBootstrapSnapshot::from_cbor(bytes.as_bytes()).expect("snapshot");
    pool_close::close(store.pool()).await;
    drop(store);
    let reopened = SqliteStore::open(&path).await.expect("reopen");
    let mut tx = reopened.pool().begin().await.expect("reopened transaction");
    let current =
        read_sqlite_password_bootstrap_in_transaction(&mut tx, ORIGIN, snapshot.account_id)
            .await
            .expect("durable complete state");
    assert_eq!(current, bytes);
    tx.commit().await.expect("read committed");
    pool_close::close(reopened.pool()).await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_outer_audit_failure_rolls_back_every_row_and_lifetime_slot() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    store.initialize_account_id_retention(1).await.expect("guard initialized before fault");
    let mut fault = store.pool().acquire().await.expect("owned fault connection");
    sqlx::query("CREATE TRIGGER fail_bootstrap_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END").execute(&mut *fault).await.expect("audit fault");
    let retry = rollback!(
        store,
        create_sqlite_password_account_in_transaction,
        append_deployment_audit_event_in_transaction,
        false
    );
    sqlx::query("DROP TRIGGER fail_bootstrap_audit")
        .execute(&mut *fault)
        .await
        .expect("remove owned fault");
    drop(fault);
    retry_and_capacity!(
        store,
        &retry.payload,
        create_sqlite_password_account_in_transaction,
        append_deployment_audit_event_in_transaction
    );
    pool_close::close(store.pool()).await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_registration_namespace_and_validation_failures_leave_no_partial_aggregate() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    conflicts!(store, create_sqlite_password_account_in_transaction, false);
    pool_close::close(store.pool()).await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_complete_bootstrap_rejects_corrupt_missing_and_unsupported_state() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    corruption!(
        store,
        create_sqlite_password_account_in_transaction,
        read_sqlite_password_bootstrap_in_transaction,
        false
    );
    pool_close::close(store.pool()).await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_password_account_writers_preserve_current_bootstrap_and_exact_replay() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    writers!(
        store,
        create_sqlite_password_account_in_transaction,
        read_sqlite_password_bootstrap_in_transaction,
        false
    );
    pool_close::close(store.pool()).await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_legacy_accounts_keep_existing_key_behavior_without_password_conversion() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    legacy!(
        store,
        read_sqlite_password_bootstrap_in_transaction,
        legacy_identity::seed_sqlite,
        false
    );
    pool_close::close(store.pool()).await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_bootstrap_bounds_damaged_metadata_before_loading_artifacts() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    store.initialize_account_id_retention(CEILING).await.expect("guard");
    let fixture = fixture("bootstrap-metadata");
    let mut tx = store.pool().begin().await.expect("initial transaction");
    create_sqlite_password_account_in_transaction(&mut tx, ORIGIN, CEILING, &fixture.payload, 1)
        .await
        .expect("initial aggregate");
    tx.commit().await.expect("fixture commit");
    sqlx::query("DROP TRIGGER account_password_bootstrap_immutable")
        .execute(store.pool())
        .await
        .expect("private fixture removes immutability guard to model corruption");
    for query in [
        "UPDATE account_password_bootstrap SET origin=zeroblob(2049)",
        "UPDATE account_password_bootstrap SET username=zeroblob(65)",
        "UPDATE account_password_bootstrap SET password_salt=zeroblob(17)",
        "UPDATE account_password_bootstrap SET verifier=zeroblob(33)",
        "UPDATE account_password_bootstrap SET verifier='01234567890123456789012345678901'",
        "UPDATE account_password_bootstrap SET password_ark=zeroblob(74)",
        "UPDATE account_password_bootstrap SET personal_vault_id=zeroblob(17)",
        "UPDATE identity_accounts SET account_signing_public_key=zeroblob(65537)",
        "UPDATE sync_account_key_certificates SET certificate=zeroblob(65537)",
    ] {
        let mut tx = store.pool().begin().await.expect("owned corruption transaction");
        sqlx::query("PRAGMA ignore_check_constraints=ON")
            .execute(&mut *tx)
            .await
            .expect("allow owned corruption");
        sqlx::query(query).execute(&mut *tx).await.expect("damaged metadata");
        assert!(
            read_sqlite_password_bootstrap_in_transaction(
                &mut tx,
                ORIGIN,
                fixture.payload.account_id
            )
            .await
            .is_err(),
            "{query}"
        );
        sqlx::query("PRAGMA ignore_check_constraints=OFF")
            .execute(&mut *tx)
            .await
            .expect("restore constraints");
        tx.rollback().await.expect("restore original bytes");
    }
    pool_close::close(store.pool()).await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_password_ownership_survives_missing_credentials_and_requires_parent_deletion() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    ownership!(
        store,
        create_sqlite_password_account_in_transaction,
        read_sqlite_password_bootstrap_in_transaction,
        false
    );
    pool_close::close(store.pool()).await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_initial_aggregate_rejects_a_silently_skipped_device_insert() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    store.initialize_account_id_retention(CEILING).await.expect("guard");
    let mut fault = store.pool().acquire().await.expect("owned fault connection");
    sqlx::query("CREATE TRIGGER skip_bootstrap_device BEFORE INSERT ON identity_devices BEGIN SELECT RAISE(IGNORE); END").execute(&mut *fault).await.expect("owned skipped-insert fault");
    skipped_device!(store, create_sqlite_password_account_in_transaction);
    sqlx::query("DROP TRIGGER skip_bootstrap_device")
        .execute(&mut *fault)
        .await
        .expect("remove owned fault");
    drop(fault);
    pool_close::close(store.pool()).await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
fn postgres_url(schema: &str) -> String {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL fixture URL");
    let mut url = url::Url::parse(&database).expect("database URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    url.to_string()
}

#[cfg(feature = "postgres-integration")]
async fn postgres_fixture() -> (PostgresStore, sqlx::PgPool, String) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL fixture URL");
    let admin = sqlx::PgPool::connect(&database).await.expect("fixture pool");
    let schema = format!("password_bootstrap_{}", Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.expect("owned schema");
    let store = PostgresStore::connect(&postgres_url(&schema)).await.expect("store");
    (store, admin, schema)
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
#[tokio::test]
async fn postgres_initial_password_aggregate_is_atomic_complete_and_reopens() {
    let (store, admin, schema) = postgres_fixture().await;
    let bytes = lifecycle!(
        store,
        create_postgres_password_account_in_transaction,
        read_postgres_password_bootstrap_in_transaction,
        append_deployment_audit_event_in_postgres_transaction,
        true
    );
    let snapshot = AccountBootstrapSnapshot::from_cbor(bytes.as_bytes()).expect("snapshot");
    store.pool().close().await;
    let reopened = PostgresStore::connect(&postgres_url(&schema)).await.expect("new instance");
    let mut tx = reopened.pool().begin().await.expect("reopened transaction");
    let current =
        read_postgres_password_bootstrap_in_transaction(&mut tx, ORIGIN, snapshot.account_id)
            .await
            .expect("durable complete state");
    assert_eq!(current, bytes);
    tx.commit().await.expect("read committed");
    cleanup_postgres(reopened, admin, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_outer_audit_failure_rolls_back_every_row_and_lifetime_slot() {
    let (store, admin, schema) = postgres_fixture().await;
    store.initialize_account_id_retention(1).await.expect("guard initialized before fault");
    sqlx::raw_sql("CREATE FUNCTION fail_bootstrap_audit() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''audit unavailable''; END'; CREATE TRIGGER fail_bootstrap_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION fail_bootstrap_audit()").execute(store.pool()).await.expect("owned audit fault");
    let retry = rollback!(
        store,
        create_postgres_password_account_in_transaction,
        append_deployment_audit_event_in_postgres_transaction,
        true
    );
    sqlx::raw_sql("DROP TRIGGER fail_bootstrap_audit ON deployment_audit_events; DROP FUNCTION fail_bootstrap_audit()").execute(store.pool()).await.expect("remove owned audit fault");
    retry_and_capacity!(
        store,
        &retry.payload,
        create_postgres_password_account_in_transaction,
        append_deployment_audit_event_in_postgres_transaction
    );
    cleanup_postgres(store, admin, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_registration_namespace_and_validation_failures_leave_no_partial_aggregate() {
    let (store, admin, schema) = postgres_fixture().await;
    conflicts!(store, create_postgres_password_account_in_transaction, true);
    cleanup_postgres(store, admin, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_complete_bootstrap_rejects_corrupt_missing_and_unsupported_state() {
    let (store, admin, schema) = postgres_fixture().await;
    corruption!(
        store,
        create_postgres_password_account_in_transaction,
        read_postgres_password_bootstrap_in_transaction,
        true
    );
    cleanup_postgres(store, admin, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_account_writers_preserve_current_bootstrap_and_exact_replay() {
    let (store, admin, schema) = postgres_fixture().await;
    writers!(
        store,
        create_postgres_password_account_in_transaction,
        read_postgres_password_bootstrap_in_transaction,
        true
    );
    cleanup_postgres(store, admin, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_legacy_accounts_keep_existing_key_behavior_without_password_conversion() {
    let (store, admin, schema) = postgres_fixture().await;
    legacy!(
        store,
        read_postgres_password_bootstrap_in_transaction,
        legacy_identity::seed_postgres,
        true
    );
    cleanup_postgres(store, admin, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_bootstrap_waits_for_writer_and_rejects_stale_strong_isolation_snapshots() {
    let (store, admin, schema) = postgres_fixture().await;
    let second = PostgresStore::connect(&postgres_url(&schema)).await.expect("second instance");
    store.initialize_account_id_retention(CEILING).await.expect("guard");
    let fixture = fixture("bootstrap-snapshot");
    let payload = &fixture.payload;
    let mut tx = store.pool().begin().await.expect("initial transaction");
    create_postgres_password_account_in_transaction(&mut tx, ORIGIN, CEILING, payload, 1)
        .await
        .expect("initial aggregate");
    tx.commit().await.expect("fixture commit");
    let mut writer = store.pool().begin().await.expect("writer");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
        .bind(payload.account_id.as_bytes().as_slice())
        .execute(&mut *writer)
        .await
        .expect("account writer lock");
    sqlx::query(
        "UPDATE account_password_bootstrap SET credential_generation=credential_generation",
    )
    .execute(&mut *writer)
    .await
    .expect("writer version fence");
    sqlx::query("UPDATE sync_vaults SET rotation_pending=TRUE")
        .execute(&mut *writer)
        .await
        .expect("writer pending state");
    let mut reader = second.pool().begin().await.expect("reader");
    let mut read = Box::pin(read_postgres_password_bootstrap_in_transaction(
        &mut reader,
        ORIGIN,
        payload.account_id,
    ));
    assert!(tokio::time::timeout(std::time::Duration::from_millis(50), &mut read).await.is_err());
    writer.commit().await.expect("writer committed");
    assert!(matches!(read.await, Err(AccountBootstrapError::UnsupportedState)));
    reader.rollback().await.expect("failed reader rollback");
    sqlx::query("UPDATE sync_vaults SET rotation_pending=FALSE")
        .execute(store.pool())
        .await
        .expect("restore pending state");
    let principal = store
        .current_device_principal(payload.device_id.into_bytes())
        .await
        .expect("principal")
        .expect("active Device");
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
        + scoplen_api::auth::ACCESS_TOKEN_EXPIRES_IN;
    let mut bundle =
        SyncAccountKeyBundleUpdate::from_cbor(&payload.key_bundle).expect("initial PUT");
    for isolation in ["REPEATABLE READ", "SERIALIZABLE"] {
        let mut stale = second.pool().begin().await.expect("stale reader transaction");
        sqlx::query(&format!("SET TRANSACTION ISOLATION LEVEL {isolation}"))
            .execute(&mut *stale)
            .await
            .expect("strong isolation");
        let _: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_password_bootstrap")
            .fetch_one(&mut *stale)
            .await
            .expect("establish old snapshot");
        bundle.revision += 1;
        sign(&mut bundle);
        store
            .publish_account_key_bundle(&principal, expiry, &bundle)
            .await
            .expect("competing real publication");
        let error =
            read_postgres_password_bootstrap_in_transaction(&mut stale, ORIGIN, payload.account_id)
                .await
                .expect_err("old snapshot must fail");
        assert!(
            matches!(error, AccountBootstrapError::Storage(ref error) if error.as_database_error().and_then(sqlx::error::DatabaseError::code).is_some_and(|code| code == "40001")),
            "strong-isolation snapshot fence"
        );
        stale.rollback().await.expect("stale transaction rollback");
    }
    second.pool().close().await;
    cleanup_postgres(store, admin, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_initial_aggregate_rejects_a_silently_skipped_device_insert() {
    let (store, admin, schema) = postgres_fixture().await;
    store.initialize_account_id_retention(CEILING).await.expect("guard");
    sqlx::raw_sql("CREATE FUNCTION skip_bootstrap_device() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NULL; END'; CREATE TRIGGER skip_bootstrap_device BEFORE INSERT ON identity_devices FOR EACH ROW EXECUTE FUNCTION skip_bootstrap_device()").execute(store.pool()).await.expect("owned skipped-insert fault");
    skipped_device!(store, create_postgres_password_account_in_transaction);
    cleanup_postgres(store, admin, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_ownership_survives_missing_credentials_and_requires_parent_deletion() {
    let (store, admin, schema) = postgres_fixture().await;
    ownership!(
        store,
        create_postgres_password_account_in_transaction,
        read_postgres_password_bootstrap_in_transaction,
        true
    );
    cleanup_postgres(store, admin, schema).await;
}
