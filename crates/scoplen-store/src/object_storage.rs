// SPDX-License-Identifier: AGPL-3.0-only
//! Object storage boundary for recordings, exports, large envelopes, and backups.
//!
//! The server keeps object-store details behind this module. The implementation uses the
//! maintained `object_store` interface, which provides the same operations for a local filesystem
//! and S3-compatible services. Object keys are parsed before they reach either backend so a key
//! cannot escape a filesystem prefix or address an ambiguous object name.

#![forbid(unsafe_code)]

use std::{fmt, path::PathBuf, sync::Arc};

use bytes::Bytes;
use futures_util::StreamExt;
use object_store::{
    GetResult, MultipartUpload, ObjectStore, ObjectStoreExt, PutResult,
    aws::AmazonS3Builder,
    local::LocalFileSystem,
    path::{self, Path as ObjectPath},
};
use thiserror::Error;

/// Maximum UTF-8 encoded object-key length accepted by the server boundary.
pub const MAX_OBJECT_KEY_BYTES: usize = 1024;

/// Shared object storage handle used by server services.
#[derive(Clone)]
pub struct ObjectStorage {
    backend: Arc<dyn ObjectStore>,
    filesystem_root: Option<PathBuf>,
}

impl fmt::Debug for ObjectStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObjectStorage(<backend redacted>)")
    }
}

/// Configuration for a concrete object-storage backend.
#[derive(Clone)]
pub enum ObjectStorageConfig {
    /// Store objects below a local filesystem directory.
    Filesystem {
        /// Root directory owned by the deployment.
        root: PathBuf,
    },
    /// Store objects in an S3-compatible bucket.
    S3(S3ObjectStorageConfig),
}

impl fmt::Debug for ObjectStorageConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Filesystem { root } => {
                formatter.debug_struct("Filesystem").field("root", root).finish()
            }
            Self::S3(config) => formatter.debug_tuple("S3").field(config).finish(),
        }
    }
}

/// S3-compatible object storage settings.
///
/// Credentials are optional so the backend can use its normal environment, workload-identity,
/// or instance-role provider. If one static credential is supplied, the other must be supplied as
/// well. `allow_http` is intended for explicitly configured local emulators and is disabled by
/// default.
#[derive(Clone)]
pub struct S3ObjectStorageConfig {
    /// Bucket name.
    pub bucket: String,
    /// Signing region. `us-east-1` is suitable for many S3-compatible services.
    pub region: String,
    /// Optional endpoint for an S3-compatible service such as `MinIO` or `R2`.
    pub endpoint: Option<String>,
    /// Optional static access key. Prefer workload credentials in deployments.
    pub access_key_id: Option<String>,
    /// Optional static secret key. Never log this value.
    pub secret_access_key: Option<String>,
    /// Permit an explicitly configured HTTP endpoint (disabled by default).
    pub allow_http: bool,
}

impl fmt::Debug for S3ObjectStorageConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S3ObjectStorageConfig")
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("endpoint", &self.endpoint)
            .field("access_key_id", &self.access_key_id.as_ref().map(|_| "<redacted>"))
            .field("secret_access_key", &self.secret_access_key.as_ref().map(|_| "<redacted>"))
            .field("allow_http", &self.allow_http)
            .finish()
    }
}

impl ObjectStorage {
    /// Build an object store from the configured backend.
    ///
    /// # Errors
    ///
    /// Returns an error when a filesystem root cannot be initialized, S3 settings are incomplete,
    /// or the selected backend rejects its configuration.
    pub fn from_config(config: &ObjectStorageConfig) -> Result<Self, ObjectStorageError> {
        let (backend, filesystem_root): (Arc<dyn ObjectStore>, Option<PathBuf>) = match config {
            ObjectStorageConfig::Filesystem { root } => {
                std::fs::create_dir_all(root).map_err(ObjectStorageError::CreateDirectory)?;
                (
                    Arc::new(
                        LocalFileSystem::new_with_prefix(root)
                            .map_err(ObjectStorageError::Backend)?,
                    ),
                    Some(root.clone()),
                )
            }
            ObjectStorageConfig::S3(config) => (Arc::new(build_s3(config)?), None),
        };
        Ok(Self { backend, filesystem_root })
    }

    /// Wrap an already constructed object-store backend.
    #[must_use]
    pub fn from_backend(backend: Arc<dyn ObjectStore>) -> Self {
        Self { backend, filesystem_root: None }
    }

    /// Save an object atomically at `key`.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is invalid or the backend cannot complete the write.
    pub async fn put(&self, key: &str, contents: Vec<u8>) -> Result<PutResult, ObjectStorageError> {
        let path = object_path(key)?;
        self.backend.put(&path, contents.into()).await.map_err(ObjectStorageError::Backend)
    }

    /// Start an atomic multipart upload for a large object.
    ///
    /// The caller must complete or abort the returned upload. S3 deployments should also expire
    /// abandoned multipart uploads with a bucket lifecycle rule.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is invalid or the backend cannot start the upload.
    pub async fn put_multipart(
        &self,
        key: &str,
    ) -> Result<Box<dyn MultipartUpload>, ObjectStorageError> {
        let path = object_path(key)?;
        self.backend.put_multipart(&path).await.map_err(ObjectStorageError::Backend)
    }

    /// Read an object fully into memory.
    ///
    /// Callers use this only for bounded payloads. Use [`Self::get_stream`] for large objects.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is invalid, the object is missing, or the backend cannot
    /// read it.
    pub async fn get(&self, key: &str) -> Result<Bytes, ObjectStorageError> {
        self.get_stream(key).await?.bytes().await.map_err(ObjectStorageError::Backend)
    }

    /// Fetch an object as a stream without buffering it in memory.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is invalid, the object is missing, or the backend cannot
    /// start the read.
    pub async fn get_stream(&self, key: &str) -> Result<GetResult, ObjectStorageError> {
        let path = object_path(key)?;
        self.backend.get(&path).await.map_err(ObjectStorageError::Backend)
    }

    /// Return metadata for an object without downloading its contents.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is invalid or the backend cannot read metadata.
    pub async fn head(&self, key: &str) -> Result<object_store::ObjectMeta, ObjectStorageError> {
        let path = object_path(key)?;
        self.backend.head(&path).await.map_err(ObjectStorageError::Backend)
    }

    /// Delete an object.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is invalid or the backend cannot complete the deletion.
    pub async fn delete(&self, key: &str) -> Result<(), ObjectStorageError> {
        let path = object_path(key)?;
        self.backend.delete(&path).await.map_err(ObjectStorageError::Backend)
    }

    /// Check backend reachability without creating or deleting an object.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot enumerate its root prefix.
    pub async fn check(&self) -> Result<(), ObjectStorageError> {
        if let Some(root) = &self.filesystem_root {
            let metadata =
                std::fs::metadata(root).map_err(ObjectStorageError::FilesystemUnavailable)?;
            if !metadata.is_dir() {
                return Err(ObjectStorageError::InvalidConfiguration(
                    "filesystem object storage root is not a directory".into(),
                ));
            }
        }
        let mut objects = self.backend.list(None);
        if let Some(result) = objects.next().await {
            result.map_err(ObjectStorageError::Backend)?;
        }
        Ok(())
    }
}

fn build_s3(
    config: &S3ObjectStorageConfig,
) -> Result<object_store::aws::AmazonS3, ObjectStorageError> {
    if config.bucket.trim().is_empty() {
        return Err(ObjectStorageError::InvalidConfiguration("S3 bucket must not be empty".into()));
    }
    if config.region.trim().is_empty() {
        return Err(ObjectStorageError::InvalidConfiguration("S3 region must not be empty".into()));
    }
    if config.access_key_id.is_some() != config.secret_access_key.is_some() {
        return Err(ObjectStorageError::InvalidConfiguration(
            "S3 access_key_id and secret_access_key must be supplied together".into(),
        ));
    }
    if config.access_key_id.as_ref().is_some_and(String::is_empty)
        || config.secret_access_key.as_ref().is_some_and(String::is_empty)
    {
        return Err(ObjectStorageError::InvalidConfiguration(
            "S3 static credentials must not be empty".into(),
        ));
    }

    let mut builder =
        AmazonS3Builder::new().with_bucket_name(&config.bucket).with_region(&config.region);
    if let Some(endpoint) = &config.endpoint {
        if endpoint.trim().is_empty() {
            return Err(ObjectStorageError::InvalidConfiguration(
                "S3 endpoint must not be empty when configured".into(),
            ));
        }
        builder = builder.with_endpoint(endpoint);
    }
    if let (Some(access_key_id), Some(secret_access_key)) =
        (&config.access_key_id, &config.secret_access_key)
    {
        builder =
            builder.with_access_key_id(access_key_id).with_secret_access_key(secret_access_key);
    }
    if config.allow_http {
        builder = builder.with_allow_http(true);
    }
    builder.build().map_err(ObjectStorageError::Backend)
}

/// Validate a logical object key without constructing or initializing an object store.
///
/// # Errors
/// Rejects keys outside the existing filesystem/object-store path contract.
pub fn validate_object_key(key: &str) -> Result<(), ObjectStorageError> {
    object_path(key).map(|_| ())
}

fn object_path(key: &str) -> Result<ObjectPath, ObjectStorageError> {
    if key.is_empty()
        || key.len() > MAX_OBJECT_KEY_BYTES
        || key.starts_with('/')
        || key.ends_with('/')
        || key.contains('\\')
    {
        return Err(ObjectStorageError::InvalidKey(key.to_owned()));
    }
    path::Path::parse(key)
        .map_err(|error| ObjectStorageError::InvalidKey(format!("{key}: {error}")))
}

/// Errors returned by the object-storage boundary.
#[derive(Debug, Error)]
pub enum ObjectStorageError {
    /// A key violates the object naming or size rules.
    #[error("invalid object key: {0}")]
    InvalidKey(String),
    /// Backend settings are incomplete or unsafe.
    #[error("invalid object storage configuration: {0}")]
    InvalidConfiguration(String),
    /// The filesystem root could not be created.
    #[error("could not create object storage directory: {0}")]
    CreateDirectory(std::io::Error),
    /// The configured filesystem root disappeared or became inaccessible.
    #[error("object storage filesystem root is unavailable: {0}")]
    FilesystemUnavailable(#[source] std::io::Error),
    /// The selected backend rejected an operation or could not complete it.
    #[error("object storage backend error: {0}")]
    Backend(#[source] object_store::Error),
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn temporary_directory() -> PathBuf {
        std::env::temp_dir().join(format!("scoplen-object-store-{}", uuid::Uuid::new_v4()))
    }

    #[tokio::test]
    async fn filesystem_backend_round_trips_and_deletes_objects() {
        let root = temporary_directory();
        let store =
            ObjectStorage::from_config(&ObjectStorageConfig::Filesystem { root: root.clone() })
                .expect("filesystem backend builds");

        let result = store.put("recordings/session-1", b"terminal bytes".to_vec()).await;
        assert!(result.is_ok(), "put succeeds: {result:?}");
        assert_eq!(
            store.get("recordings/session-1").await.expect("get succeeds"),
            "terminal bytes"
        );
        assert_eq!(store.head("recordings/session-1").await.expect("head succeeds").size, 14);
        store.delete("recordings/session-1").await.expect("delete succeeds");
        assert!(matches!(
            store.get("recordings/session-1").await,
            Err(ObjectStorageError::Backend(_))
        ));
        fs::remove_dir_all(root).expect("temporary object store is removable");
    }

    #[tokio::test]
    async fn filesystem_root_is_created_and_invalid_keys_fail_closed() {
        let root = temporary_directory();
        let store =
            ObjectStorage::from_config(&ObjectStorageConfig::Filesystem { root: root.clone() })
                .expect("filesystem backend builds");
        assert!(root.is_dir());

        for key in
            ["", "/leading", "trailing/", "../outside", "nested/../outside", "nested\\outside"]
        {
            assert!(
                matches!(store.put(key, Vec::new()).await, Err(ObjectStorageError::InvalidKey(_))),
                "{key:?} must be rejected"
            );
        }
        let oversized = "x".repeat(MAX_OBJECT_KEY_BYTES + 1);
        assert!(matches!(
            store.put(&oversized, Vec::new()).await,
            Err(ObjectStorageError::InvalidKey(_))
        ));
        fs::remove_dir_all(root).expect("temporary object store is removable");
    }

    #[tokio::test]
    async fn filesystem_multipart_upload_and_stream_read_round_trip() {
        let root = temporary_directory();
        let store =
            ObjectStorage::from_config(&ObjectStorageConfig::Filesystem { root: root.clone() })
                .expect("filesystem backend builds");
        let mut upload = store.put_multipart("recordings/large").await.expect("start upload");
        upload.put_part(b"chunk one".to_vec().into()).await.expect("upload part");
        upload.put_part(b"chunk two".to_vec().into()).await.expect("upload part");
        upload.complete().await.expect("complete upload");
        let result = store.get_stream("recordings/large").await.expect("start stream read");
        assert_eq!(result.bytes().await.expect("read stream"), "chunk onechunk two");
        assert!(matches!(
            store.put_multipart("../outside").await,
            Err(ObjectStorageError::InvalidKey(_))
        ));
        fs::remove_dir_all(root).expect("temporary object store is removable");
    }

    #[tokio::test]
    async fn filesystem_health_check_succeeds_without_mutating_objects() {
        let root = temporary_directory();
        let store =
            ObjectStorage::from_config(&ObjectStorageConfig::Filesystem { root: root.clone() })
                .expect("filesystem backend builds");
        store.check().await.expect("filesystem backend is reachable");
        store.check().await.expect("second health check");
        fs::remove_dir_all(root).expect("temporary object store is removable");
    }

    #[test]
    fn s3_config_builds_without_network_and_redacts_credentials() {
        let config = S3ObjectStorageConfig {
            bucket: "scoplen-test".into(),
            region: "us-east-1".into(),
            endpoint: Some("http://127.0.0.1:9000".into()),
            access_key_id: Some("test-access-value".into()),
            secret_access_key: Some("test-secret-value".into()),
            allow_http: true,
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("test-access-value"));
        assert!(!debug.contains("test-secret-value"));
        assert!(ObjectStorage::from_config(&ObjectStorageConfig::S3(config)).is_ok());
    }

    #[test]
    fn s3_config_rejects_partial_credentials_and_empty_fields() {
        let partial = S3ObjectStorageConfig {
            bucket: "bucket".into(),
            region: "us-east-1".into(),
            endpoint: None,
            access_key_id: Some("access".into()),
            secret_access_key: None,
            allow_http: false,
        };
        assert!(matches!(
            ObjectStorage::from_config(&ObjectStorageConfig::S3(partial)),
            Err(ObjectStorageError::InvalidConfiguration(_))
        ));

        let empty_bucket = S3ObjectStorageConfig {
            bucket: " ".into(),
            region: "us-east-1".into(),
            endpoint: None,
            access_key_id: None,
            secret_access_key: None,
            allow_http: false,
        };
        assert!(matches!(
            ObjectStorage::from_config(&ObjectStorageConfig::S3(empty_bucket)),
            Err(ObjectStorageError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn object_storage_debug_does_not_include_backend_credentials() {
        let config = ObjectStorageConfig::S3(S3ObjectStorageConfig {
            bucket: "bucket".into(),
            region: "us-east-1".into(),
            endpoint: None,
            access_key_id: Some("test-access-value".into()),
            secret_access_key: Some("test-secret-value".into()),
            allow_http: false,
        });
        let debug = format!("{config:?}");
        assert!(!debug.contains("test-secret-value"));
        assert!(!debug.contains("test-access-value"));
    }
}
