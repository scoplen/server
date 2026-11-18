// SPDX-License-Identifier: AGPL-3.0-only
//! Current-day local archive scheduling, backed by the ordinary SQLite job queue.

use std::{sync::Arc, time::Duration};

use scoplen_store::{
    JobQueueError, SqliteStore,
    jobs::{Job, JobId},
};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::{BackupSettings, Config, ServerError, backup, deployment_lease::DeploymentLease};

const KIND: &str = "backup.daily";
const MAX_ATTEMPTS: u32 = 3;
const RETRY_MS: i64 = 5 * 60 * 1_000;
const LEASE_MS: i64 = 60_000;
const RENEW_INTERVAL: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_secs(30);
const DAY_MS: i64 = 86_400_000;

struct Slot {
    id: JobId,
    date: String,
    basename: String,
    due_at_ms: i64,
}

impl Slot {
    fn at(settings: &BackupSettings, now_ms: i64) -> Result<Self, JobQueueError> {
        if now_ms < 0 {
            return Err(JobQueueError::Clock);
        }
        let instant = time::OffsetDateTime::from_unix_timestamp(now_ms / 1_000)
            .map_err(|_| JobQueueError::Clock)?;
        let day = now_ms / DAY_MS;
        let mut hash = Sha256::new();
        hash.update(b"scoplen.backup.daily.v1\0");
        hash.update(day.to_be_bytes());
        let digest = hash.finalize();
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        let date = instant.date().to_string();
        let due_at_ms =
            day * DAY_MS + settings.minute_of_day().map_err(|_| JobQueueError::Clock)? * 60_000;
        Ok(Self { id, basename: format!("scoplen-{date}.age"), date, due_at_ms })
    }
}

enum Due {
    Idle,
    Exhausted(Slot),
    Claimed(Slot, Job),
}

async fn claim_due(
    store: &SqliteStore,
    settings: &BackupSettings,
    owner: &str,
    now_ms: i64,
) -> Result<Due, JobQueueError> {
    if !settings.enabled {
        return Ok(Due::Idle);
    }
    let slot = Slot::at(settings, now_ms)?;
    let job = match store.get_job(slot.id).await {
        Ok(job) => job,
        Err(JobQueueError::NotFound) => {
            if now_ms < slot.due_at_ms && store.has_job_kind(KIND).await? {
                return Ok(Due::Idle);
            }
            match store.enqueue_job(slot.id, KIND, slot.date.as_bytes(), now_ms).await {
                Ok(()) | Err(JobQueueError::Constraint(_)) => {}
                Err(error) => return Err(error),
            }
            store.get_job(slot.id).await?
        }
        Err(error) => return Err(error),
    };
    if job.kind != KIND || job.payload != slot.date.as_bytes() {
        return Err(JobQueueError::CorruptRow("daily backup slot"));
    }
    if job.finished_at_ms.is_some() {
        return Ok(Due::Idle);
    }
    if job.attempts >= u64::from(MAX_ATTEMPTS) {
        return Ok(if job.lease_until_ms.is_some_and(|until| until > now_ms) {
            Due::Idle
        } else {
            Due::Exhausted(slot)
        });
    }
    Ok(match store.claim_job_id(slot.id, owner, now_ms, LEASE_MS, MAX_ATTEMPTS).await? {
        Some(job) => Due::Claimed(slot, job),
        None => Due::Idle,
    })
}

fn now_ms() -> Result<i64, JobQueueError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| JobQueueError::Clock)?
        .as_millis()
        .try_into()
        .map_err(|_| JobQueueError::Clock)
}

async fn failed(store: &SqliteStore, owner: &str, slot: &Slot, job: &Job, reason: &'static str) {
    let Ok(now) = now_ms() else {
        warn!(target: "backup.daily", event = "unconfirmed", slot = %slot.date,
            attempt = job.attempts, archive = %slot.basename, reason = "clock_unavailable",
            "scheduled backup status");
        return;
    };
    let retry_at_ms = now.saturating_add(RETRY_MS);
    if store.fail_job(slot.id, owner, now, retry_at_ms, reason).await.is_err() {
        warn!(target: "backup.daily", event = "unconfirmed", slot = %slot.date,
            attempt = job.attempts, archive = %slot.basename, reason = "job_update_unconfirmed",
            "scheduled backup status");
    } else if job.attempts >= u64::from(MAX_ATTEMPTS) {
        warn!(target: "backup.daily", event = "exhausted", slot = %slot.date,
            attempt = job.attempts, archive = %slot.basename, reason,
            "scheduled backup status");
    } else {
        warn!(target: "backup.daily", event = "retry_scheduled", slot = %slot.date,
            attempt = job.attempts, archive = %slot.basename, retry_at_ms, reason,
            "scheduled backup status");
    }
}

async fn capture(
    config: &Config,
    store: &SqliteStore,
    lease: &DeploymentLease,
    owner: &str,
    slot: &Slot,
    job: &Job,
) {
    let output =
        config.backup.directory.as_ref().expect("validated backup directory").join(&slot.basename);
    let passphrase = config.backup.passphrase_file.as_deref().expect("validated passphrase file");
    info!(target: "backup.daily", event = "started", slot = %slot.date,
        attempt = job.attempts, archive = %slot.basename, "scheduled backup status");
    let operation = backup::create_online(config, &output, passphrase, lease);
    tokio::pin!(operation);
    let mut renewal = tokio::time::interval(RENEW_INTERVAL);
    renewal.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    renewal.tick().await;
    let result = loop {
        tokio::select! {
            result = &mut operation => break result,
            _ = renewal.tick() => {
                let renewed = match now_ms() {
                    Ok(now) => store.renew_job(slot.id, owner, now, LEASE_MS).await,
                    Err(error) => Err(error),
                };
                if renewed.is_err() {
                    warn!(target: "backup.daily", event = "unconfirmed", slot = %slot.date,
                        attempt = job.attempts, archive = %slot.basename,
                        reason = "lease_update_unconfirmed", "scheduled backup status");
                }
            }
        }
    };
    if result.is_err() {
        let reason = if std::fs::symlink_metadata(&output).is_ok() {
            warn!(target: "backup.daily", event = "unconfirmed", slot = %slot.date,
                attempt = job.attempts, archive = %slot.basename, reason = "output_exists",
                "scheduled backup status");
            "output_exists"
        } else {
            "capture_failed"
        };
        failed(store, owner, slot, job, reason).await;
        return;
    }
    let completed = match now_ms() {
        Ok(now) => store.complete_job(slot.id, owner, now).await.map(|()| now),
        Err(error) => Err(error),
    };
    if let Ok(completed_at_ms) = completed {
        info!(target: "backup.daily", event = "succeeded",
            slot = %slot.date, attempt = job.attempts, archive = %slot.basename,
            completed_at_ms, "scheduled backup status");
    } else {
        warn!(target: "backup.daily", event = "unconfirmed", slot = %slot.date,
            attempt = job.attempts, archive = %slot.basename,
            reason = "completion_unconfirmed", "scheduled backup status");
        failed(store, owner, slot, job, "completion_unconfirmed").await;
    }
}

pub(crate) async fn run(
    config: Config,
    store: Arc<SqliteStore>,
    lease: DeploymentLease,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServerError> {
    let owner = format!("backup-{}", uuid::Uuid::new_v4());
    let mut poll = tokio::time::interval(POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut exhausted = None;
    loop {
        tokio::select! {
            biased;
            () = crate::runtime::shutdown_requested(&mut shutdown) => return Ok(()),
            _ = poll.tick() => {}
        }
        let due = tokio::select! {
            biased;
            () = crate::runtime::shutdown_requested(&mut shutdown) => return Ok(()),
            result = async {
                claim_due(store.as_ref(), &config.backup, &owner, now_ms()?).await
            } => result,
        };
        if *shutdown.borrow() {
            return Ok(());
        }
        match due {
            Ok(Due::Claimed(slot, job)) => {
                capture(&config, store.as_ref(), &lease, &owner, &slot, &job).await;
            }
            Ok(Due::Exhausted(slot)) if exhausted != Some(slot.id) => {
                warn!(target: "backup.daily", event = "exhausted", slot = %slot.date,
                    attempt = MAX_ATTEMPTS, archive = %slot.basename, reason = "attempt_limit",
                    "scheduled backup status");
                exhausted = Some(slot.id);
            }
            Ok(_) => {}
            Err(_) => warn!(target: "backup.daily", event = "unconfirmed",
                reason = "schedule_unavailable", "scheduled backup status"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scoplen_store::RelationalStore;
    use std::{fs, path::PathBuf};

    fn directory() -> PathBuf {
        #[cfg(unix)]
        let parent = fs::canonicalize(std::env::temp_dir()).expect("test temporary root");
        #[cfg(not(unix))]
        let parent = std::env::temp_dir();
        let path = parent.join(format!("scoplen-backup-schedule-{}", uuid::Uuid::new_v4()));
        #[cfg(windows)]
        crate::windows_private_directory::prepare_directory(&path, &[]).expect("private fixture");
        #[cfg(not(windows))]
        {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&path).expect("private fixture");
        }
        path
    }

    async fn close(directory: PathBuf, store: SqliteStore) {
        store.pool().close().await;
        drop(store);
        fs::remove_dir_all(directory).expect("remove owned schedule fixture");
    }

    fn settings() -> BackupSettings {
        BackupSettings { enabled: true, ..BackupSettings::default() }
    }

    fn claimed(due: Due) -> (Slot, Job) {
        let Due::Claimed(slot, job) = due else { panic!("expected current-day claim") };
        (slot, job)
    }

    #[test]
    fn utc_slots_have_stable_daily_identity_and_due_time() {
        let settings = settings();
        let first = Slot::at(&settings, 0).expect("epoch slot");
        let same = Slot::at(&settings, DAY_MS - 1).expect("same UTC day");
        let next = Slot::at(&settings, DAY_MS).expect("next UTC day");
        assert_eq!(first.date, "1970-01-01");
        assert_eq!(first.basename, "scoplen-1970-01-01.age");
        assert_eq!(first.due_at_ms, 3 * 60 * 60_000);
        assert_eq!(first.id, same.id);
        assert_ne!(first.id, next.id);
        assert_eq!(next.date, "1970-01-02");
        assert!(Slot::at(&settings, -1).is_err());
    }

    #[test]
    fn enabled_schedule_rejects_unsupported_profiles_cache_and_source_overlap() {
        let directory = directory();
        let password = directory.join("passphrase");
        crate::private_material::write_private(&password, "synthetic backup passphrase")
            .expect("passphrase file");
        let mut config = Config::default();
        config.server.data_dir = directory.join("source");
        config.backup = BackupSettings {
            enabled: true,
            directory: Some(directory.clone()),
            passphrase_file: Some(password),
            ..BackupSettings::default()
        };
        config.validate().expect("valid enabled configuration before source bootstrap");
        config.storage.backend = "postgres".into();
        assert!(backup::validate_schedule(&config).is_err());
        config.storage.backend = "sqlite".into();
        config.tls.mode = crate::TlsMode::Acme;
        assert!(backup::validate_schedule(&config).is_err());
        config.tls.mode = crate::TlsMode::Plain;
        fs::create_dir(&config.server.data_dir).expect("owned source");
        fs::create_dir(config.server.data_dir.join("acme-cache")).expect("empty managed cache");
        assert!(backup::validate_schedule(&config).is_err());
        fs::remove_dir(config.server.data_dir.join("acme-cache")).expect("remove owned cache");
        config.server.data_dir = directory.clone();
        assert!(backup::validate_schedule(&config).is_err());
        fs::remove_dir_all(directory).expect("remove owned config fixture");
    }

    #[tokio::test]
    async fn first_enable_is_immediate_but_later_days_wait_and_never_catch_up() {
        let directory = directory();
        let store = SqliteStore::open(&directory.join("jobs.sqlite")).await.expect("store");
        let settings = settings();
        let early = (now_ms().expect("clock") / DAY_MS + 1) * DAY_MS + 60 * 60_000;
        let (slot, first) =
            claimed(claim_due(&store, &settings, "first", early).await.expect("first enable"));
        assert_eq!(first.payload, slot.date.as_bytes());
        store.complete_job(slot.id, "first", early + 1).await.expect("success");
        assert!(matches!(
            claim_due(&store, &settings, "restart", early + 2).await.expect("today"),
            Due::Idle
        ));
        let later = early + 3 * DAY_MS;
        assert!(matches!(
            claim_due(&store, &settings, "restart", later).await.expect("before due"),
            Due::Idle
        ));
        let (today, _) = claimed(
            claim_due(&store, &settings, "restart", later + 2 * 60 * 60_000)
                .await
                .expect("due today"),
        );
        for missed in 1..3 {
            let missed = Slot::at(&settings, early + missed * DAY_MS).expect("missed date");
            assert!(matches!(store.get_job(missed.id).await, Err(JobQueueError::NotFound)));
        }
        assert_ne!(today.id, slot.id);
        close(directory, store).await;
    }

    #[tokio::test]
    async fn retries_survive_restart_and_exhaustion_does_not_complete_the_day() {
        let directory = directory();
        let store = SqliteStore::open(&directory.join("jobs.sqlite")).await.expect("store");
        let settings = settings();
        let now = 20_000 * DAY_MS;
        let (slot, _) = claimed(claim_due(&store, &settings, "first", now).await.expect("first"));
        store
            .fail_job(slot.id, "first", now + 1, now + RETRY_MS, "capture_failed")
            .await
            .expect("retry");
        store.pool().close().await;
        drop(store);
        let store =
            SqliteStore::open(&directory.join("jobs.sqlite")).await.expect("restarted store");
        assert!(matches!(
            claim_due(&store, &settings, "second", now + RETRY_MS - 1).await.expect("early"),
            Due::Idle
        ));
        let (_, second) = claimed(
            claim_due(&store, &settings, "second", now + RETRY_MS)
                .await
                .expect("retry due before daily time"),
        );
        assert_eq!(second.attempts, 2);
        let (_, third) = claimed(
            claim_due(&store, &settings, "third", now + RETRY_MS + LEASE_MS)
                .await
                .expect("abandoned claim"),
        );
        assert_eq!(third.attempts, 3);
        store
            .fail_job(
                slot.id,
                "third",
                now + RETRY_MS + LEASE_MS + 1,
                now + 2 * RETRY_MS,
                "capture_failed",
            )
            .await
            .expect("last failure");
        assert!(matches!(
            claim_due(&store, &settings, "fourth", now + 2 * RETRY_MS).await.expect("cap"),
            Due::Exhausted(_)
        ));
        assert!(store.get_job(slot.id).await.expect("failure retained").finished_at_ms.is_none());
        assert!(matches!(
            claim_due(&store, &settings, "tomorrow", now + DAY_MS)
                .await
                .expect("tomorrow before due"),
            Due::Idle
        ));
        let (tomorrow, _) = claimed(
            claim_due(&store, &settings, "tomorrow", now + DAY_MS + 3 * 60 * 60_000)
                .await
                .expect("tomorrow due"),
        );
        assert_ne!(tomorrow.id, slot.id);
        assert_eq!(store.get_job(slot.id).await.expect("old failure preserved").attempts, 3);
        close(directory, store).await;
    }

    #[tokio::test]
    async fn disabled_schedule_and_requested_shutdown_create_no_slot() {
        let directory = directory();
        let store = SqliteStore::open(&directory.join("jobs.sqlite")).await.expect("store");
        assert!(matches!(
            claim_due(&store, &BackupSettings::default(), "disabled", 0).await.expect("disabled"),
            Due::Idle
        ));
        let lease = DeploymentLease::try_shared(&directory).expect("shared admission");
        let (sender, receiver) = watch::channel(true);
        run(
            Config { backup: settings(), ..Config::default() },
            Arc::new(store.clone()),
            lease,
            receiver,
        )
        .await
        .expect("shutdown before scheduling");
        drop(sender);
        assert!(!store.has_job_kind(KIND).await.expect("no backup history"));
        close(directory, store).await;
    }

    #[tokio::test]
    async fn scheduled_capture_is_verified_and_existing_output_is_preserved() {
        let directory = directory();
        let mut config = Config::default();
        config.server.data_dir = directory.join("source");
        crate::reissue_operator_setup(&config).await.expect("initialized source");
        let password = directory.join("passphrase");
        crate::private_material::write_private(&password, "synthetic exact backup passphrase")
            .expect("passphrase");
        config.backup = BackupSettings {
            enabled: true,
            directory: Some(directory.clone()),
            passphrase_file: Some(password.clone()),
            ..BackupSettings::default()
        };
        config.validate().expect("scheduled local profile");
        let lease = DeploymentLease::try_shared(&config.server.data_dir).expect("shared admission");
        let store = SqliteStore::open(&config.server.data_dir.join("scoplen.sqlite"))
            .await
            .expect("source store");
        let (slot, job) = claimed(
            claim_due(&store, &config.backup, "capture", now_ms().expect("clock"))
                .await
                .expect("first claim"),
        );
        capture(&config, &store, &lease, "capture", &slot, &job).await;
        assert!(store.get_job(slot.id).await.expect("confirmed job").finished_at_ms.is_some());
        let archive = directory.join(&slot.basename);
        backup::verify(&archive, &password)
            .await
            .expect("ordinary verifier accepts scheduled archive");
        let original = fs::read(&archive).expect("published bytes");
        // An unconfirmed publication is never adopted or replaced by a later attempt.
        let next = Slot::at(&config.backup, now_ms().expect("clock") + DAY_MS).expect("next slot");
        fs::write(directory.join(&next.basename), &original).expect("existing output");
        store.enqueue_job(next.id, KIND, next.date.as_bytes(), 0).await.expect("unconfirmed slot");
        let next_job = store
            .claim_job_id(next.id, "collision", now_ms().expect("clock"), LEASE_MS, MAX_ATTEMPTS)
            .await
            .expect("claim collision")
            .expect("eligible collision");
        capture(&config, &store, &lease, "collision", &next, &next_job).await;
        let failed = store.get_job(next.id).await.expect("unconfirmed job");
        assert!(failed.finished_at_ms.is_none());
        assert_eq!(failed.last_error.as_deref(), Some("output_exists"));
        assert_eq!(fs::read(directory.join(next.basename)).expect("preserved bytes"), original);
        drop(lease);
        close(directory, store).await;
    }
}
