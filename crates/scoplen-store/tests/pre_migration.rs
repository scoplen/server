// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use std::{
    fs,
    path::{Path, PathBuf},
};

use scoplen_store::{RelationalStore, SqliteStore, StoreError};
use sqlx::{
    Connection, SqliteConnection, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use uuid::Uuid;

struct Fixture {
    directory: PathBuf,
    database: PathBuf,
    snapshots: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("scoplen-migration-snapshot-{}", Uuid::new_v4()));
        fs::create_dir(&directory).expect("owned test directory");
        Self {
            database: directory.join("scoplen.sqlite"),
            snapshots: directory.join("scoplen.sqlite.migration-snapshots"),
            directory,
        }
    }

    async fn historical(&self) -> SqlitePool {
        self.historical_before(1).await
    }

    async fn historical_before(&self, pending: usize) -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(&self.database)
                    .create_if_missing(true)
                    .journal_mode(SqliteJournalMode::Wal)
                    .foreign_keys(true),
            )
            .await
            .expect("historical database");
        let mut old = sqlx::migrate!("./migrations/sqlite");
        let retained = old.migrations.len() - pending;
        old.migrations.to_mut().truncate(retained);
        old.run(&pool).await.expect("historical schema");
        sqlx::query("PRAGMA wal_autocheckpoint = 0")
            .execute(&pool)
            .await
            .expect("retain WAL pages");
        sqlx::query("INSERT INTO organizations (id, name, created_at_ms) VALUES (?, 'Retained organization', 123)")
            .bind([7_u8;16].as_slice()).execute(&pool).await.expect("committed fixture data");
        pool
    }

    fn completed(&self) -> Vec<PathBuf> {
        let mut paths: Vec<_> = fs::read_dir(&self.snapshots)
            .expect("snapshot directory")
            .map(|entry| entry.expect("snapshot entry").path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.strip_prefix("pre-migration-"))
                    .and_then(|name| name.strip_suffix(".sqlite"))
                    .is_some_and(|id| {
                        Uuid::parse_str(id).is_ok_and(|uuid| {
                            uuid.get_version_num() == 7
                                && uuid.get_variant() == uuid::Variant::RFC4122
                                && uuid.to_string() == id
                        })
                    })
            })
            .collect();
        paths.sort();
        paths
    }

    async fn remove(self) {
        support::remove_test_directory(self.directory).await;
    }
}

async fn readonly(path: &Path) -> SqliteConnection {
    SqliteConnection::connect_with(
        &SqliteConnectOptions::new().filename(path).read_only(true).immutable(true),
    )
    .await
    .expect("standalone read-only snapshot")
}

async fn migration_count(connection: &mut SqliteConnection) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(connection)
        .await
        .expect("migration history")
}

async fn assert_retained(connection: &mut SqliteConnection) {
    let name: String = sqlx::query_scalar("SELECT name FROM organizations WHERE id = ?")
        .bind([7_u8; 16].as_slice())
        .fetch_one(&mut *connection)
        .await
        .expect("retained organization");
    assert_eq!(name, "Retained organization");
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(connection)
        .await
        .expect("snapshot integrity");
    assert_eq!(integrity, "ok");
}

#[tokio::test]
async fn first_empty_database_and_current_reopen_create_no_snapshots() {
    let fixture = Fixture::new();
    for _ in 0..2 {
        let store = SqliteStore::open(&fixture.database).await.expect("ordinary startup");
        assert!(!fixture.snapshots.exists());
        store.pool().close().await;
    }
    fixture.remove().await;
}

#[tokio::test]
async fn an_existing_unmanaged_schema_is_preserved_before_first_managed_migration() {
    let fixture = Fixture::new();
    let mut old = SqliteConnection::connect_with(
        &SqliteConnectOptions::new().filename(&fixture.database).create_if_missing(true),
    )
    .await
    .expect("existing unmanaged database");
    sqlx::query("CREATE TABLE sqlitex (retained TEXT)")
        .execute(&mut old)
        .await
        .expect("ordinary user table with a SQLite-like name");
    sqlx::query("INSERT INTO sqlitex VALUES ('retained')")
        .execute(&mut old)
        .await
        .expect("unmanaged row");
    old.close().await.expect("close old database");
    let store = SqliteStore::open(&fixture.database).await.expect("first managed upgrade");
    store.pool().close().await;
    let paths = fixture.completed();
    assert_eq!(paths.len(), 1);
    let mut snapshot = readonly(&paths[0]).await;
    let retained: String = sqlx::query_scalar("SELECT retained FROM sqlitex")
        .fetch_one(&mut snapshot)
        .await
        .expect("original unmanaged row");
    assert_eq!(retained, "retained");
    let managed: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_schema WHERE name = '_sqlx_migrations'")
            .fetch_one(&mut snapshot)
            .await
            .expect("original unmodified schema");
    assert_eq!(managed, 0);
    snapshot.close().await.expect("close snapshot");
    fixture.remove().await;
}

#[tokio::test]
async fn a_later_failed_migration_keeps_the_snapshot_before_any_upgrade_step() {
    let fixture = Fixture::new();
    let historical = fixture.historical_before(2).await;
    sqlx::query("CREATE TABLE sync_objects_configurable (retained TEXT)")
        .execute(&historical)
        .await
        .expect("owned later migration conflict");
    let previous: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&historical)
        .await
        .expect("original migration history");
    assert!(matches!(SqliteStore::open(&fixture.database).await, Err(StoreError::Migration(_))));
    let partial_upgrade: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&historical)
        .await
        .expect("earlier committed migration survives the later failure");
    assert_eq!(partial_upgrade, previous + 1);
    let snapshots = fixture.completed();
    assert_eq!(snapshots.len(), 1);
    let restored = fixture.directory.join("old-version-recovery.sqlite");
    fs::copy(&snapshots[0], &restored).expect("retain and restore original recovery point");
    let mut recovery = readonly(&restored).await;
    assert_eq!(migration_count(&mut recovery).await, previous);
    assert_retained(&mut recovery).await;
    recovery.close().await.expect("close original-schema recovery");
    historical.close().await;
    fixture.remove().await;
}

#[tokio::test]
async fn upgrade_snapshot_includes_committed_wal_and_restores_on_a_fresh_path() {
    let fixture = Fixture::new();
    let historical = fixture.historical().await;
    let previous: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&historical)
        .await
        .expect("old migration count");
    let wal = fixture.directory.join("scoplen.sqlite-wal");
    assert!(fs::metadata(&wal).expect("live WAL").len() > 0);
    let store = SqliteStore::open(&fixture.database).await.expect("protected upgrade");
    let snapshots = fixture.completed();
    assert_eq!(snapshots.len(), 1);
    let mut snapshot = readonly(&snapshots[0]).await;
    assert_eq!(migration_count(&mut snapshot).await, previous);
    assert_retained(&mut snapshot).await;
    snapshot.close().await.expect("close snapshot");
    let current: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(store.pool())
        .await
        .expect("new migration count");
    assert_eq!(current, previous + 1);
    store.pool().close().await;
    historical.close().await;

    let restored = fixture.directory.join("restored.sqlite");
    fs::copy(&snapshots[0], &restored).expect("copy complete standalone recovery point");
    let mut old = readonly(&restored).await;
    assert_eq!(migration_count(&mut old).await, previous);
    assert_retained(&mut old).await;
    old.close().await.expect("close restored old schema");
    let upgraded = SqliteStore::open(&restored).await.expect("restored database can upgrade again");
    let mut connection = upgraded.pool().acquire().await.expect("restored database");
    assert_retained(&mut connection).await;
    drop(connection);
    upgraded.pool().close().await;
    let current = SqliteStore::open(&fixture.database).await.expect("current original database");
    current.pool().close().await;
    assert_eq!(fixture.completed(), snapshots, "unchanged current startup creates no new snapshot");
    fixture.remove().await;
}

#[tokio::test]
async fn snapshot_failure_blocks_migration_and_preserves_database_and_keys() {
    let fixture = Fixture::new();
    let historical = fixture.historical().await;
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&historical)
        .await
        .expect("old history");
    fs::write(&fixture.snapshots, b"operator-owned sentinel").expect("occupied destination");
    let key = fixture.directory.join("deployment.key");
    fs::write(&key, b"synthetic retained material").expect("synthetic key");
    let error =
        SqliteStore::open(&fixture.database).await.err().expect("snapshot must fail closed");
    assert!(matches!(error, StoreError::MigrationSnapshot(_)));
    assert!(!error.to_string().contains(fixture.directory.to_str().expect("fixture path")));
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&historical)
        .await
        .expect("unchanged history");
    assert_eq!(before, after);
    assert_eq!(
        fs::read(&fixture.snapshots).expect("retained sentinel"),
        b"operator-owned sentinel"
    );
    assert_eq!(fs::read(&key).expect("retained material"), b"synthetic retained material");
    let mut connection = historical.acquire().await.expect("old database");
    assert_retained(&mut connection).await;
    drop(connection);
    historical.close().await;
    fixture.remove().await;
}

#[tokio::test]
async fn failed_migrations_keep_the_three_latest_verified_recovery_points_only() {
    let fixture = Fixture::new();
    let historical = fixture.historical().await;
    sqlx::query("CREATE TABLE sync_objects_configurable (retained TEXT)")
        .execute(&historical)
        .await
        .expect("owned migration conflict");
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&historical)
        .await
        .expect("old history");
    let mut produced = Vec::new();
    for attempt in 0..5 {
        let error = SqliteStore::open(&fixture.database).await.err().expect("migration conflict");
        assert!(matches!(error, StoreError::Migration(_)));
        let retained = fixture.completed();
        assert_eq!(retained.len(), (attempt + 1).min(3));
        produced.push(retained.last().expect("latest verified snapshot").clone());
        assert_eq!(retained, produced[produced.len().saturating_sub(3)..]);
        let mut snapshot = readonly(retained.last().expect("latest snapshot")).await;
        assert_eq!(migration_count(&mut snapshot).await, before);
        assert_retained(&mut snapshot).await;
        snapshot.close().await.expect("close recovery point");
        let current: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(&historical)
            .await
            .expect("unchanged failed migration history");
        assert_eq!(current, before);
        if attempt == 0 {
            fs::write(fixture.snapshots.join("operator-notes.txt"), b"retain notes")
                .expect("unmanaged note");
            fs::write(
                fixture.snapshots.join("pre-migration-invalid.sqlite"),
                b"retain unknown file",
            )
            .expect("unmanaged name");
            fs::write(
                fixture.snapshots.join("interrupted.sqlite.partial"),
                b"retain interrupted evidence",
            )
            .expect("unmanaged partial");
            fs::write(
                fixture.snapshots.join("pre-migration-00000000-0000-7000-0000-000000000000.sqlite"),
                b"retain non-RFC identifier",
            )
            .expect("unmanaged UUID variant");
        }
    }
    assert_eq!(
        fs::read(fixture.snapshots.join("operator-notes.txt")).expect("notes retained"),
        b"retain notes"
    );
    assert_eq!(
        fs::read(fixture.snapshots.join("pre-migration-invalid.sqlite"))
            .expect("unknown file retained"),
        b"retain unknown file"
    );
    assert_eq!(
        fs::read(fixture.snapshots.join("interrupted.sqlite.partial"))
            .expect("interrupted evidence retained"),
        b"retain interrupted evidence"
    );
    assert_eq!(
        fs::read(
            fixture.snapshots.join("pre-migration-00000000-0000-7000-0000-000000000000.sqlite")
        )
        .expect("non-RFC identifier retained"),
        b"retain non-RFC identifier"
    );
    historical.close().await;
    fixture.remove().await;
}

#[tokio::test]
async fn simultaneous_startups_publish_one_recovery_point() {
    let fixture = Fixture::new();
    fixture.historical().await.close().await;
    let (first, second) =
        tokio::join!(SqliteStore::open(&fixture.database), SqliteStore::open(&fixture.database));
    let first = first.expect("first serialized startup");
    let second = second.expect("second serialized startup");
    assert_eq!(fixture.completed().len(), 1);
    first.pool().close().await;
    second.pool().close().await;
    fixture.remove().await;
}

#[tokio::test]
async fn cancelling_the_startup_caller_does_not_release_the_migration_lock_early() {
    use std::{fs::TryLockError, time::Duration};

    let fixture = Fixture::new();
    let historical = fixture.historical().await;
    let mut writer = historical.acquire().await.expect("owned concurrent writer");
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *writer)
        .await
        .expect("hold migration write admission");
    let path = fixture.database.clone();
    let startup = tokio::spawn(async move { SqliteStore::open(&path).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if fixture.snapshots.exists() && !fixture.completed().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("read-only WAL snapshot finishes while the writer blocks migration");
    startup.abort();
    assert!(startup.await.err().expect("outer startup cancelled").is_cancelled());
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.directory.join("scoplen.sqlite.migration.lock"))
        .expect("existing migration lock");
    assert!(
        matches!(lock.try_lock(), Err(TryLockError::WouldBlock)),
        "detached migration still owns its lock"
    );
    sqlx::query("ROLLBACK").execute(&mut *writer).await.expect("release fixture writer");
    drop(writer);
    let store =
        SqliteStore::open(&fixture.database).await.expect("earlier protected upgrade finishes");
    assert_eq!(fixture.completed().len(), 1, "cancelled caller did not permit a duplicate upgrade");
    store.pool().close().await;
    historical.close().await;
    drop(lock);
    fixture.remove().await;
}

#[tokio::test]
async fn a_future_dated_recovery_point_cannot_cause_the_current_snapshot_to_be_pruned() {
    let fixture = Fixture::new();
    let historical = fixture.historical().await;
    sqlx::query("CREATE TABLE sync_objects_configurable (retained TEXT)")
        .execute(&historical)
        .await
        .expect("owned migration conflict");
    assert!(matches!(SqliteStore::open(&fixture.database).await, Err(StoreError::Migration(_))));
    let future = Uuid::new_v7(uuid::Timestamp::from_unix(uuid::NoContext, 4_102_444_800, 0));
    fs::rename(
        &fixture.completed()[0],
        fixture.snapshots.join(format!("pre-migration-{future}.sqlite")),
    )
    .expect("simulate retained snapshot before a backwards clock adjustment");
    for _ in 0..4 {
        assert!(matches!(
            SqliteStore::open(&fixture.database).await,
            Err(StoreError::Migration(_))
        ));
        let retained = fixture.completed();
        let latest = retained
            .last()
            .expect("newest recovery point")
            .file_stem()
            .expect("snapshot name")
            .to_str()
            .expect("canonical name");
        let id = Uuid::parse_str(latest.strip_prefix("pre-migration-").expect("owned name"))
            .expect("canonical UUIDv7");
        assert!(id > future, "new recovery point remains after the retained ordering boundary");
        assert!(retained.len() <= 3);
    }
    historical.close().await;
    fixture.remove().await;
}

#[tokio::test]
async fn incompatible_migration_history_does_not_create_a_snapshot_or_apply_migrations() {
    let fixture = Fixture::new();
    let historical = fixture.historical().await;
    sqlx::query("UPDATE _sqlx_migrations SET checksum = X'00' WHERE version = (SELECT MIN(version) FROM _sqlx_migrations)")
        .execute(&historical).await.expect("owned invalid history");
    assert!(matches!(
        SqliteStore::open(&fixture.database).await,
        Err(StoreError::Migration(sqlx::migrate::MigrateError::VersionMismatch(_)))
    ));
    assert!(!fixture.snapshots.exists());
    historical.close().await;
    fixture.remove().await;
}

#[tokio::test]
async fn invalid_foreign_keys_refuse_snapshot_publication_and_leave_no_partial_file() {
    let fixture = Fixture::new();
    let historical = fixture.historical().await;
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&historical)
        .await
        .expect("owned historical corruption");
    sqlx::query("INSERT INTO sync_objects (vault_id, object_id, sequence, envelope, tombstone, written_at_ms) VALUES (?, ?, 1, X'01', 0, 1)")
        .bind([1_u8;16].as_slice()).bind([2_u8;16].as_slice()).execute(&historical).await.expect("orphan retained source row");
    let error = SqliteStore::open(&fixture.database)
        .await
        .err()
        .expect("invalid backup must not authorize upgrade");
    assert!(matches!(error, StoreError::MigrationSnapshot("snapshot integrity")));
    assert_eq!(fs::read_dir(&fixture.snapshots).expect("snapshot directory").count(), 0);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sync_objects")
        .fetch_one(&historical)
        .await
        .expect("source left untouched");
    assert_eq!(count, 1);
    historical.close().await;
    fixture.remove().await;
}

#[cfg(windows)]
#[tokio::test]
async fn retention_failure_keeps_published_snapshots_and_blocks_the_pending_migration() {
    use std::os::windows::fs::OpenOptionsExt;

    let fixture = Fixture::new();
    let historical = fixture.historical().await;
    sqlx::query("CREATE TABLE sync_objects_configurable (retained TEXT)")
        .execute(&historical)
        .await
        .expect("owned migration conflict");
    for _ in 0..3 {
        assert!(matches!(
            SqliteStore::open(&fixture.database).await,
            Err(StoreError::Migration(_))
        ));
    }
    let original = fixture.completed();
    let retained_bytes: Vec<_> =
        original.iter().map(|path| fs::read(path).expect("original bytes")).collect();
    let oldest = fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&original[0])
        .expect("hold the owned oldest snapshot without delete sharing");
    sqlx::query("DROP TABLE sync_objects_configurable")
        .execute(&historical)
        .await
        .expect("remove owned failure fixture");
    let previous: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&historical)
        .await
        .expect("pending migration history");
    assert!(matches!(
        SqliteStore::open(&fixture.database).await,
        Err(StoreError::MigrationSnapshot("snapshot retention"))
    ));
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&historical)
        .await
        .expect("unchanged migration history");
    assert_eq!(after, previous);
    assert_eq!(
        fixture.completed().len(),
        4,
        "newly published recovery point is kept after retention failure"
    );
    for (path, bytes) in original.iter().zip(retained_bytes) {
        assert_eq!(fs::read(path).expect("prior recovery point remains"), bytes);
    }
    drop(oldest);
    let store = SqliteStore::open(&fixture.database)
        .await
        .expect("upgrade after the operator releases the snapshot reader");
    assert_eq!(fixture.completed().len(), 3);
    store.pool().close().await;
    historical.close().await;
    fixture.remove().await;
}

#[cfg(unix)]
#[tokio::test]
async fn snapshots_and_lock_are_private_and_unsafe_snapshot_directories_are_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    fixture.historical().await.close().await;
    let store = SqliteStore::open(&fixture.database).await.expect("private snapshot");
    store.pool().close().await;
    for (path, mode) in [
        (fixture.snapshots.clone(), 0o700),
        (fixture.completed()[0].clone(), 0o600),
        (fixture.directory.join("scoplen.sqlite.migration.lock"), 0o600),
    ] {
        assert_eq!(
            fs::metadata(path).expect("private metadata").permissions().mode() & 0o777,
            mode
        );
    }
    fixture.remove().await;

    let fixture = Fixture::new();
    fixture.historical().await.close().await;
    fs::create_dir(&fixture.snapshots).expect("owned unsafe snapshot directory");
    fs::set_permissions(&fixture.snapshots, fs::Permissions::from_mode(0o755))
        .expect("unsafe permissions");
    assert!(matches!(
        SqliteStore::open(&fixture.database).await,
        Err(StoreError::MigrationSnapshot("snapshot permissions"))
    ));
    assert_eq!(fs::read_dir(&fixture.snapshots).expect("untouched directory").count(), 0);
    fixture.remove().await;
}

#[cfg(unix)]
#[tokio::test]
async fn retention_never_follows_a_matching_symlink() {
    use std::os::unix::fs::{DirBuilderExt, symlink};
    let fixture = Fixture::new();
    fixture.historical().await.close().await;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&fixture.snapshots)
        .expect("private snapshot directory");
    let retained = fixture.directory.join("operator-owned.txt");
    fs::write(&retained, b"retain external file").expect("external sentinel");
    let link = fixture.snapshots.join(format!("pre-migration-{}.sqlite", Uuid::now_v7()));
    symlink(&retained, &link).expect("owned unsafe snapshot entry");
    assert!(matches!(
        SqliteStore::open(&fixture.database).await,
        Err(StoreError::MigrationSnapshot(_))
    ));
    assert_eq!(fs::read(&retained).expect("external file retained"), b"retain external file");
    assert!(fs::symlink_metadata(&link).expect("link retained").file_type().is_symlink());
    assert_eq!(fs::read_dir(&fixture.snapshots).expect("no new snapshot").count(), 1);
    fixture.remove().await;
}
