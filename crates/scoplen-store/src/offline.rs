// SPDX-License-Identifier: AGPL-3.0-only
//! Existing-only SQLite snapshots and verification for offline deployment archives.

use std::{fs::File, path::Path, sync::Arc};

use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::TryStreamExt;
use scoplen_audit::{checkpoint_payload, deployment_checkpoint_payload, event_hash};
use scoplen_ca::LocalUserCa;
use sqlx::{
    Connection, Row, SqliteConnection,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    SQLITE_MIGRATIONS, SqliteStore,
    kms::{AuditCheckpointSigner, KeyManagementService},
};

/// The complete successful migration history and durable public-origin binding.
#[derive(Debug, Eq, PartialEq)]
pub struct Metadata {
    /// Canonical origin retained by first-Operator setup.
    pub origin: String,
    /// Ordered migration versions and the existing `SQLx` checksums.
    pub migrations: Vec<(i64, Vec<u8>)>,
}

/// Offline inspection failures deliberately omit database contents and paths.
#[derive(Debug, Error)]
#[error(
    "offline database verification failed; check the matching build, database, keys and audit state"
)]
pub struct OfflineError;

/// Create a standalone WAL-complete image without creating or migrating the source.
///
/// # Errors
/// Fails on an unavailable source, snapshot failure or incomplete connection shutdown.
pub async fn snapshot(
    source: &Path,
    destination: &Path,
    lease: Arc<File>,
) -> Result<(), OfflineError> {
    let source = source.to_path_buf();
    let destination = destination.to_path_buf();
    tokio::spawn(async move {
        let _lease = lease;
        let mut connection = SqliteConnection::connect_with(
            &SqliteConnectOptions::new().filename(source).read_only(true).create_if_missing(false),
        )
        .await
        .map_err(|_| OfflineError)?;
        let result = async {
            sqlx::query("VACUUM INTO ?")
                .bind(destination.to_str().ok_or(OfflineError)?)
                .execute(&mut connection)
                .await
                .map_err(|_| OfflineError)?;
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&destination)
                .and_then(|file| file.sync_all())
                .map_err(|_| OfflineError)?;
            crate::pre_migration::verify_snapshot(&destination).await.map_err(|_| OfflineError)
        }
        .await;
        let closed = connection.close().await.map_err(|_| OfflineError);
        result.and(closed)
    })
    .await
    .map_err(|_| OfflineError)?
}

/// Verify a standalone image and its existing local-key relationships without initialization.
///
/// # Errors
/// Rejects integrity, migration, origin, KMS, CA or available audit-proof failures.
pub async fn verify(
    database: &Path,
    kms: &dyn KeyManagementService,
    audit_signer: &dyn AuditCheckpointSigner,
) -> Result<Metadata, OfflineError> {
    crate::pre_migration::verify_snapshot(database).await.map_err(|_| OfflineError)?;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(database)
                .read_only(true)
                .immutable(true)
                .create_if_missing(false),
        )
        .await
        .map_err(|_| OfflineError)?;
    let store = SqliteStore {
        pool,
        sync_cardinality_limits: crate::sync::SyncCardinalityLimits::default(),
        sync_write_limits: scoplen_api::sync::SyncWriteLimits::default(),
        _deployment_lease: None,
    };
    let result = inspect(&store, kms, audit_signer).await;
    store.pool.close().await;
    result
}

async fn inspect(
    store: &SqliteStore,
    kms: &dyn KeyManagementService,
    audit_signer: &dyn AuditCheckpointSigner,
) -> Result<Metadata, OfflineError> {
    let expected = SQLITE_MIGRATIONS
        .iter()
        .filter(|migration| !migration.migration_type.is_down_migration())
        .collect::<Vec<_>>();
    let rows = sqlx::query(
        "SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version LIMIT ?",
    )
    .bind(i64::try_from(expected.len() + 1).map_err(|_| OfflineError)?)
    .fetch_all(&store.pool)
    .await
    .map_err(|_| OfflineError)?;
    if rows.len() != expected.len() {
        return Err(OfflineError);
    }
    let mut migrations = Vec::with_capacity(rows.len());
    for (row, expected) in rows.iter().zip(expected) {
        let version: i64 = row.try_get("version").map_err(|_| OfflineError)?;
        let checksum: Vec<u8> = row.try_get("checksum").map_err(|_| OfflineError)?;
        if version != expected.version
            || checksum.as_slice() != expected.checksum.as_ref()
            || !row.try_get::<bool, _>("success").map_err(|_| OfflineError)?
        {
            return Err(OfflineError);
        }
        migrations.push((version, checksum));
    }
    let origin: String =
        sqlx::query_scalar("SELECT trusted_origin FROM operator_setup WHERE singleton = 1")
            .fetch_one(&store.pool)
            .await
            .map_err(|_| OfflineError)?;
    crate::device_token_keys::verify_offline(store, kms).await.map_err(|_| OfflineError)?;
    crate::operator_token_keys::verify_offline(store, kms).await.map_err(|_| OfflineError)?;
    let probe: bool = sqlx::query_scalar(
        "SELECT encrypted_key IS NOT NULL FROM account_password_probe_key WHERE singleton = 1",
    )
    .fetch_one(&store.pool)
    .await
    .map_err(|_| OfflineError)?;
    if probe {
        store.read_account_probe_key(kms).await.map_err(|_| OfflineError)?;
    } else if sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM identity_accounts)")
        .fetch_one(&store.pool)
        .await
        .map_err(|_| OfflineError)?
    {
        return Err(OfflineError);
    }
    let mut authorities = sqlx::query(
        "SELECT organization_id, id, encrypted_seed, response_json FROM organization_user_cas",
    )
    .fetch(&store.pool);
    while let Some(row) = authorities.try_next().await.map_err(|_| OfflineError)? {
        let org: Vec<u8> = row.try_get("organization_id").map_err(|_| OfflineError)?;
        let id: Vec<u8> = row.try_get("id").map_err(|_| OfflineError)?;
        let encrypted: Vec<u8> = row.try_get("encrypted_seed").map_err(|_| OfflineError)?;
        let response: Vec<u8> = row.try_get("response_json").map_err(|_| OfflineError)?;
        let org = Uuid::from_slice(&org).map_err(|_| OfflineError)?;
        let id = Uuid::from_slice(&id).map_err(|_| OfflineError)?;
        let ca = LocalUserCa::open(&encrypted, kms.key_encryption_key(), org, id)
            .map_err(|_| OfflineError)?;
        let resource =
            scoplen_api::user_ca::UserCaResource::from_json(&response).map_err(|_| OfflineError)?;
        resource.validate_for_id(id).map_err(|_| OfflineError)?;
        if ca.public_key().map_err(|_| OfflineError)? != resource.public_key {
            return Err(OfflineError);
        }
    }
    drop(authorities);
    verify_audit(store, audit_signer, false).await?;
    verify_audit(store, audit_signer, true).await?;
    Ok(Metadata { origin, migrations })
}

async fn verify_audit(
    store: &SqliteStore,
    signer: &dyn AuditCheckpointSigner,
    deployment: bool,
) -> Result<(), OfflineError> {
    let key = VerifyingKey::from_bytes(&signer.verification_key()).map_err(|_| OfflineError)?;
    let (events, checkpoints, organization, join) = if deployment {
        ("deployment_audit_events", "deployment_audit_checkpoints", "NULL", "c.sequence=e.sequence")
    } else {
        (
            "audit_events",
            "audit_checkpoints",
            "e.organization_id",
            "c.organization_id=e.organization_id AND c.sequence=e.sequence",
        )
    };
    let query = format!(
        "SELECT {organization} AS organization_id, e.sequence, e.previous_hash, CASE WHEN length(e.event_bytes) BETWEEN 1 AND 1048576 THEN e.event_bytes END AS event_bytes, e.event_hash, e.created_at_ms, c.sequence AS checkpoint_sequence, c.head_hash, c.signature, c.signed_at_ms FROM {events} e LEFT JOIN {checkpoints} c ON {join} ORDER BY organization_id, e.sequence"
    );
    let mut rows = sqlx::query(&query).fetch(&store.pool);
    let mut organization = None;
    let mut sequence = 0_u64;
    let mut hash = [0_u8; 32];
    while let Some(row) = rows.try_next().await.map_err(|_| OfflineError)? {
        let org: Option<Vec<u8>> = row.try_get("organization_id").map_err(|_| OfflineError)?;
        let org =
            org.map(|bytes| <[u8; 16]>::try_from(bytes).map_err(|_| OfflineError)).transpose()?;
        if org != organization {
            organization = org;
            sequence = 0;
            hash = [0; 32];
        }
        let actual = u64::try_from(row.try_get::<i64, _>("sequence").map_err(|_| OfflineError)?)
            .map_err(|_| OfflineError)?;
        let previous: Vec<u8> = row.try_get("previous_hash").map_err(|_| OfflineError)?;
        let event: Vec<u8> = row.try_get("event_bytes").map_err(|_| OfflineError)?;
        let stored: Vec<u8> = row.try_get("event_hash").map_err(|_| OfflineError)?;
        if actual != sequence.checked_add(1).ok_or(OfflineError)?
            || previous.as_slice() != hash
            || row.try_get::<i64, _>("created_at_ms").map_err(|_| OfflineError)? <= 0
        {
            return Err(OfflineError);
        }
        hash = event_hash(&hash, &event).map_err(|_| OfflineError)?;
        if stored.as_slice() != hash {
            return Err(OfflineError);
        }
        sequence = actual;
        if row.try_get::<Option<i64>, _>("checkpoint_sequence").map_err(|_| OfflineError)?.is_some()
        {
            let head: Vec<u8> = row.try_get("head_hash").map_err(|_| OfflineError)?;
            let signature: Vec<u8> = row.try_get("signature").map_err(|_| OfflineError)?;
            let at =
                u64::try_from(row.try_get::<i64, _>("signed_at_ms").map_err(|_| OfflineError)?)
                    .map_err(|_| OfflineError)?;
            if head.as_slice() != hash {
                return Err(OfflineError);
            }
            let payload = if let Some(org) = organization {
                checkpoint_payload(&org, sequence, &hash, at)
            } else {
                deployment_checkpoint_payload(sequence, &hash, at)
            }
            .map_err(|_| OfflineError)?;
            let signature = Signature::from_slice(&signature).map_err(|_| OfflineError)?;
            key.verify_strict(&payload, &signature).map_err(|_| OfflineError)?;
        }
    }
    drop(rows);
    let orphan = format!(
        "SELECT EXISTS(SELECT 1 FROM {checkpoints} c LEFT JOIN {events} e ON {join} WHERE e.sequence IS NULL)"
    );
    if sqlx::query_scalar::<_, bool>(&orphan)
        .fetch_one(&store.pool)
        .await
        .map_err(|_| OfflineError)?
    {
        return Err(OfflineError);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeploymentAuditCheckpoint;
    use ed25519_dalek::{Signer, SigningKey};

    struct Kms([u8; 32]);
    impl KeyManagementService for Kms {
        fn key_encryption_key(&self) -> &[u8; 32] {
            &self.0
        }
        fn backend_name(&self) -> &'static str {
            "offline-test"
        }
    }

    struct Audit(SigningKey);
    impl AuditCheckpointSigner for Audit {
        fn sign_checkpoint(&self, payload: &[u8]) -> [u8; 64] {
            self.0.sign(payload).to_bytes()
        }
        fn verification_key(&self) -> [u8; 32] {
            self.0.verifying_key().to_bytes()
        }
    }

    #[tokio::test]
    async fn wal_snapshot_checks_migrations_retained_keys_and_signed_audit_without_initializing() {
        let root = std::env::temp_dir().join(format!("scoplen-offline-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).expect("owned test directory");
        let database = root.join("source.sqlite");
        let store = SqliteStore::open(&database).await.expect("source schema");
        store
            .initialize_operator_setup("https://backup.example.com", false)
            .await
            .expect("durable origin");
        let kms = Kms([7; 32]);
        let signer = Audit(SigningKey::from_bytes(&[8; 32]));
        let lease = Arc::new(File::create(root.join("lease")).expect("test lease handle"));
        let uninitialized = root.join("uninitialized.sqlite");
        snapshot(&database, &uninitialized, lease.clone()).await.expect("existing-only snapshot");
        verify(&uninitialized, &kms, &signer).await.expect("uninitialized bootstrap key is valid");
        store.ensure_device_token_keyring(&kms).await.expect("existing token key");
        store.ensure_operator_token_keyring(&kms).await.expect("existing operator key");
        store.ensure_account_probe_key(&kms).await.expect("existing probe key");
        let head = store.deployment_audit_head().await.expect("audit head").expect("setup audit");
        let payload = deployment_checkpoint_payload(head.sequence, &head.head_hash, 1)
            .expect("checkpoint payload");
        store
            .write_deployment_audit_checkpoint(&DeploymentAuditCheckpoint {
                sequence: head.sequence,
                head_hash: head.head_hash,
                signature: signer.sign_checkpoint(&payload),
                signed_at_ms: 1,
            })
            .await
            .expect("available signed proof");
        let image = root.join("image.sqlite");
        snapshot(&database, &image, lease).await.expect("WAL-complete snapshot");
        let metadata = verify(&image, &kms, &signer).await.expect("complete retained state");
        assert_eq!(metadata.origin, "https://backup.example.com");
        assert_ne!(metadata.migrations, []);
        assert!(verify(&image, &Kms([9; 32]), &signer).await.is_err());
        assert!(verify(&image, &kms, &Audit(SigningKey::from_bytes(&[10; 32]))).await.is_err());
        for (name, mutation) in [
            (
                "migration",
                "UPDATE _sqlx_migrations SET checksum = zeroblob(48) WHERE version = (SELECT MIN(version) FROM _sqlx_migrations)",
            ),
            ("audit", "UPDATE deployment_audit_events SET event_bytes = X'01' WHERE sequence = 1"),
            ("proof", "UPDATE deployment_audit_checkpoints SET signature = zeroblob(64)"),
        ] {
            let changed = root.join(format!("{name}.sqlite"));
            std::fs::copy(&image, &changed).expect("owned corrupt image");
            let mut connection = SqliteConnection::connect_with(
                &SqliteConnectOptions::new().filename(&changed).create_if_missing(false),
            )
            .await
            .expect("open owned corruption fixture");
            sqlx::query(mutation).execute(&mut connection).await.expect("mutate owned fixture");
            connection.close().await.expect("close corruption fixture");
            assert!(
                verify(&changed, &kms, &signer).await.is_err(),
                "{name} corruption must fail closed"
            );
        }
        store.pool.close().await;
        std::fs::remove_dir_all(root).expect("remove owned fixtures");
    }
}
