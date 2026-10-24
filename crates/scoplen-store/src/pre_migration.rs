// SPDX-License-Identifier: AGPL-3.0-only
//! Consistent, private SQLite recovery points before forward migrations.

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions, TryLockError},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use sqlx::{
    Connection, SqliteConnection, SqlitePool, migrate::Migrate, sqlite::SqliteConnectOptions,
};
use uuid::Uuid;

use crate::{SQLITE_MIGRATIONS, StoreError};

const KEEP_SNAPSHOTS: usize = 3;

pub(super) async fn migrate(
    pool: &SqlitePool,
    path: &Path,
    deployment_lease: Option<Arc<File>>,
) -> Result<(), StoreError> {
    let pool = pool.clone();
    let path = path.to_path_buf();
    // Keep the file lock and SQLite worker alive until migration finishes, even if the
    // startup caller is cancelled while SQLite is executing a statement.
    tokio::spawn(async move {
        let _deployment_lease = deployment_lease;
        let path = fs::canonicalize(path).map_err(|_| failed("database path"))?;
        let _lock = migration_lock(&path).await?;
        let mut connection = pool.acquire().await?;
        let result: Result<(), StoreError> = async {
            if needs_snapshot(&mut connection).await? {
                create_snapshot(&mut connection, &path).await?;
            }
            SQLITE_MIGRATIONS.run_direct(&mut *connection).await?;
            Ok(())
        }
        .await;
        // Wait for the worker and any queued rollback instead of asynchronously returning
        // this startup-only connection to the pool after releasing the migration lock.
        let closed = connection.close().await.map_err(|_| failed("migration connection close"));
        result.and(closed)
    })
    .await
    .map_err(|_| failed("migration task"))?
}

fn sibling(path: &Path, suffix: &str) -> Result<PathBuf, StoreError> {
    let mut name = path.file_name().ok_or_else(|| failed("database name"))?.to_os_string();
    name.push(suffix);
    Ok(path.with_file_name(name))
}

async fn migration_lock(path: &Path) -> Result<File, StoreError> {
    let path = sibling(path, ".migration.lock")?;
    let file = match private_file(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            check_private(&path, false)?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|_| failed("migration lock"))?
        }
        Err(_) => return Err(failed("migration lock")),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(_) => return Err(failed("migration lock; another startup may be active")),
        }
    }
}

async fn needs_snapshot(connection: &mut SqliteConnection) -> Result<bool, StoreError> {
    let has_history: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = '_sqlx_migrations')",
    )
    .fetch_one(&mut *connection)
    .await?;
    let applied = if has_history {
        if let Some(version) = connection.dirty_version().await? {
            return Err(sqlx::migrate::MigrateError::Dirty(version).into());
        }
        connection.list_applied_migrations().await?
    } else {
        Vec::new()
    };
    let known: HashMap<_, _> = SQLITE_MIGRATIONS.iter().map(|item| (item.version, item)).collect();
    for item in &applied {
        let migration = known
            .get(&item.version)
            .ok_or(sqlx::migrate::MigrateError::VersionMissing(item.version))?;
        if migration.checksum != item.checksum {
            return Err(sqlx::migrate::MigrateError::VersionMismatch(item.version).into());
        }
    }
    let pending = SQLITE_MIGRATIONS.iter().any(|item| {
        !item.migration_type.is_down_migration()
            && !applied.iter().any(|entry| entry.version == item.version)
    });
    if !pending {
        return Ok(false);
    }
    let populated: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*')",
    )
    .fetch_one(connection)
    .await?;
    Ok(populated)
}

fn private_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn check_private(path: &Path, directory: bool) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| failed("snapshot metadata"))?;
    if metadata.file_type().is_symlink()
        || if directory { !metadata.is_dir() } else { !metadata.is_file() }
    {
        return Err(failed("snapshot path must be an ordinary private file or directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || (!directory && metadata.nlink() != 1) {
            return Err(failed("snapshot permissions"));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(failed("snapshot reparse point"));
        }
    }
    Ok(())
}

fn snapshot_directory(path: &Path) -> Result<PathBuf, StoreError> {
    let directory = sibling(path, ".migration-snapshots")?;
    #[cfg(unix)]
    let created = {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&directory)
    };
    #[cfg(not(unix))]
    let created = fs::create_dir(&directory);
    match created {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(failed("snapshot directory")),
    }
    check_private(&directory, true)?;
    Ok(directory)
}

async fn create_snapshot(connection: &mut SqliteConnection, path: &Path) -> Result<(), StoreError> {
    let directory = snapshot_directory(path)?;
    // Refuse unsafe matching entries before writing or pruning any recovery point.
    let previous = completed_snapshots(&directory)?;
    let mut id = Uuid::now_v7();
    if let Some((last, _)) = previous.last()
        && id <= *last
    {
        // A clock adjustment across restarts must not prune this upgrade's recovery point.
        let (seconds, nanos) =
            last.get_timestamp().ok_or_else(|| failed("snapshot ordering"))?.to_unix();
        let next = Duration::new(seconds, nanos) + Duration::from_millis(1);
        id = Uuid::new_v7(uuid::Timestamp::from_unix(
            uuid::NoContext,
            next.as_secs(),
            next.subsec_nanos(),
        ));
        if id <= *last {
            return Err(failed("snapshot ordering"));
        }
    }
    let name = format!("pre-migration-{id}.sqlite");
    let completed = directory.join(&name);
    let partial = directory.join(format!("{name}.partial"));
    let file = private_file(&partial).map_err(|_| failed("snapshot creation"))?;
    let result = write_snapshot(connection, &partial, &completed, &file).await;
    drop(file);
    // Only this attempt's private, unpublished staging name is eligible for cleanup.
    // A published snapshot is retained even if directory sync or retention later fails.
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result?;
    sync_directory(&directory)?;
    sync_directory(directory.parent().ok_or_else(|| failed("snapshot parent"))?)?;
    let snapshots = completed_snapshots(&directory)?;
    for (_, path) in snapshots.iter().take(snapshots.len().saturating_sub(KEEP_SNAPSHOTS)) {
        fs::remove_file(path).map_err(|_| failed("snapshot retention"))?;
    }
    sync_directory(&directory)
}

async fn write_snapshot(
    connection: &mut SqliteConnection,
    partial: &Path,
    completed: &Path,
    file: &File,
) -> Result<(), StoreError> {
    let destination = partial.to_str().ok_or_else(|| failed("snapshot path encoding"))?;
    // SQLite incorporates committed WAL pages into a standalone consistent database.
    sqlx::query("VACUUM INTO ?")
        .bind(destination)
        .execute(connection)
        .await
        .map_err(|_| failed("consistent snapshot"))?;
    file.sync_all().map_err(|_| failed("snapshot data sync"))?;
    verify_snapshot(partial).await?;
    // A hard link publishes the already verified bytes without replacing another file.
    fs::hard_link(partial, completed).map_err(|_| failed("snapshot publication"))?;
    fs::remove_file(partial).map_err(|_| failed("snapshot staging removal"))
}

async fn verify_snapshot(path: &Path) -> Result<(), StoreError> {
    let options = SqliteConnectOptions::new().filename(path).read_only(true).immutable(true);
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|_| failed("snapshot verification"))?;
    let result = async {
        let checks: Vec<String> = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_all(&mut connection)
            .await
            .map_err(|_| failed("snapshot integrity"))?;
        let foreign_keys = sqlx::query("PRAGMA foreign_key_check")
            .fetch_optional(&mut connection)
            .await
            .map_err(|_| failed("snapshot foreign keys"))?;
        if checks != ["ok"] || foreign_keys.is_some() {
            return Err(failed("snapshot integrity"));
        }
        Ok(())
    }
    .await;
    connection.close().await.map_err(|_| failed("snapshot verification close"))?;
    result
}

fn completed_snapshots(directory: &Path) -> Result<Vec<(Uuid, PathBuf)>, StoreError> {
    let mut snapshots = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| failed("snapshot listing"))? {
        let entry = entry.map_err(|_| failed("snapshot listing"))?;
        let name = entry.file_name();
        let Some(id) = name
            .to_str()
            .and_then(|name| name.strip_prefix("pre-migration-"))
            .and_then(|name| name.strip_suffix(".sqlite"))
        else {
            continue;
        };
        let Ok(uuid) = Uuid::parse_str(id) else { continue };
        if uuid.get_version_num() != 7
            || uuid.get_variant() != uuid::Variant::RFC4122
            || uuid.to_string() != id
        {
            continue;
        }
        check_private(&entry.path(), false)?;
        snapshots.push((uuid, entry.path()));
    }
    snapshots.sort_unstable_by_key(|(id, _)| *id);
    Ok(snapshots)
}

fn sync_directory(directory: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| failed("snapshot directory sync"))?;
    #[cfg(not(unix))]
    // Portable directory flushing is unavailable here; recheck the path after syncing file data.
    check_private(directory, true)?;
    Ok(())
}

fn failed(phase: &'static str) -> StoreError {
    StoreError::MigrationSnapshot(phase)
}
