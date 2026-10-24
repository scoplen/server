// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use scoplen_store::sync::{
    ObjectWrite, PersonalMutation, SyncStoreError, TOMBSTONE_PURGE_AFTER_DAYS,
};

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("timestamp")
}

fn write(object: Uuid, device: Uuid, tombstone: bool) -> ObjectWrite {
    ObjectWrite {
        object_id: object.into_bytes(),
        base_sequence: tombstone.then_some(1),
        envelope: vec![1, 2, 3],
        key_epoch: 1,
        tombstone,
        signer_device_id: Some(device.into_bytes()),
    }
}

macro_rules! retention_tests {
    ($module:ident, $store:ty, $open:ident, $postgres:literal) => {
        mod $module {
            use super::*;

            fn sql(source: &str) -> String {
                if !$postgres { return source.to_owned(); }
                let mut n = 0;
                source.chars().map(|c| if c == '?' { n += 1; format!("${n}") } else { c.to_string() }).collect()
            }

            pub(super) async fn setup() -> ($store, Option<std::path::PathBuf>, PersonalEnrollmentRequest) {
                let (store, directory) = $open().await;
                let request = crate::$module::fixture(&store).await;
                history(&store, request.personal_vault_id, request.device_certificate.device_id).await;
                (store, directory, request)
            }

            async fn history(store: &$store, vault: Uuid, device: Uuid) {
                let object = Uuid::now_v7();
                store.write_sync_batch(vault.into_bytes(), &[write(object, device, false)]).await.expect("live object");
                store.write_sync_batch(vault.into_bytes(), &[write(object, device, true)]).await.expect("tombstone");
            }

            pub(super) async fn ack(store: &$store, request: &PersonalEnrollmentRequest, device: Uuid, cursor: u64) {
                let principal = store.current_device_principal(device.into_bytes()).await.expect("identity").expect("current device");
                let authorization = PersonalMutation { account_id: request.account_id.into_bytes(), device_id: device.into_bytes(), dpop_jkt: &principal.jkt, signers: &[] };
                store.ack_personal_sync_cursor(request.personal_vault_id.into_bytes(), &authorization, cursor).await.expect("authorized ACK");
            }

            async fn unchanged(store: &$store, vault: Uuid) {
                let row = sqlx::query(&sql("SELECT current_seq,purge_horizon FROM sync_vaults WHERE vault_id=?")).bind(vault.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("vault");
                assert_eq!(row.get::<i64,_>("current_seq"), 2);
                assert_eq!(row.get::<i64,_>("purge_horizon"), 0);
                let count: i64 = sqlx::query_scalar(&sql("SELECT COUNT(*) FROM sync_object_versions WHERE vault_id=?")).bind(vault.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("history");
                assert_eq!(count, 2);
                assert_eq!(store.sync_snapshot(vault.into_bytes(), 0, 10).await.expect("snapshot").objects.len(), 1);
            }

            async fn close(store: $store, directory: Option<std::path::PathBuf>) {
                store.pool().close().await;
                if let Some(directory) = directory { support::remove_test_directory(directory).await; }
            }

            #[tokio::test]
            async fn batched_identity_checks_cover_three_devices_and_all_revocations() {
                let (store, directory, mut request) = setup().await;
                let (second, _, second_complete) = crate::$module::ready(&store, &request).await;
                store.complete_pairing(ORIGIN, second.pairing_id, &principal(&request), &second_complete, source()).await.expect("second membership");
                request.key_bundle_update = SyncAccountKeyBundleUpdate::from_cbor(&second_complete.key_bundle_update).expect("current signed bundle");
                let (third, _, third_complete) = crate::$module::ready_with_key(&store, &request, 5).await;
                store.complete_pairing(ORIGIN, third.pairing_id, &principal(&request), &third_complete, source()).await.expect("third membership");
                let mut certificates = vec![request.device_certificate.encode().expect("own"), second_complete.device_certificate, third_complete.device_certificate];
                let mut revocations = Vec::new();
                for key in [7, 9] {
                    let retired = Uuid::now_v7();
                    certificates.push(certificate(request.account_id, retired, key).encode().expect("retired certificate"));
                    revocations.push(RevocationStatement::issue(&account_key(), retired, 2, "retired".into()).expect("revocation").encode().expect("signed revocation"));
                }
                store.replace_account_key_statements(request.account_id.into_bytes(), &certificates, &revocations).await.expect("complete signed snapshot");
                ack(&store, &request, request.device_certificate.device_id, 2).await;
                ack(&store, &request, second.responder_device_id, 1).await;
                ack(&store, &request, third.responder_device_id, 2).await;
                store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await.expect("three-device floor");
                unchanged(&store, request.personal_vault_id).await;
                ack(&store, &request, second.responder_device_id, 2).await;
                assert_eq!(store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await.expect("all current ACKs").purged_tombstones, 1);
                close(store, directory).await;
            }

            #[tokio::test]
            async fn personal_retention_uses_every_current_devices_minimum_ack() {
                let (store, directory, request) = setup().await;
                let (context, _, complete) = crate::$module::ready(&store, &request).await;
                store.complete_pairing(ORIGIN, context.pairing_id, &principal(&request), &complete, source()).await.expect("pair second device");
                ack(&store, &request, request.device_certificate.device_id, 2).await;
                ack(&store, &request, context.responder_device_id, 1).await;
                let report = store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await.expect("minimum ACK");
                assert_eq!(report.purged_tombstones, 0);
                unchanged(&store, request.personal_vault_id).await;
                ack(&store, &request, context.responder_device_id, 2).await;
                let report = store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await.expect("all devices ACK");
                assert_eq!(report.purged_tombstones, 1);
                assert_eq!(report.pruned_versions, 2);
                assert_eq!(report.purge_horizon, 2);
                assert!(matches!(store.sync_changes(request.personal_vault_id.into_bytes(), 0, 10).await, Err(SyncStoreError::CursorExpired { purge_horizon: 2 })));
                assert!(store.sync_snapshot(request.personal_vault_id.into_bytes(), 0, 10).await.expect("reconcile").objects.is_empty());
                close(store, directory).await;
            }

            #[tokio::test]
            async fn pairing_after_ack_and_unrelated_acks_cannot_hide_a_missing_ack() {
                let (store, directory, request) = setup().await;
                ack(&store, &request, request.device_certificate.device_id, 2).await;
                let (context, _, complete) = crate::$module::ready(&store, &request).await;
                store.complete_pairing(ORIGIN, context.pairing_id, &principal(&request), &complete, source()).await.expect("new membership after ACK");
                store.ack_sync_cursor(request.personal_vault_id.into_bytes(), Uuid::now_v7().into_bytes(), 2).await.expect("unrelated stored ACK");
                let outsider = crate::$module::fixture(&store).await;
                history(&store, outsider.personal_vault_id, outsider.device_certificate.device_id).await;
                store.ack_sync_cursor(outsider.personal_vault_id.into_bytes(), context.responder_device_id.into_bytes(), 2).await.expect("different vault ACK");
                store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await.expect("missing ACK is zero");
                unchanged(&store, request.personal_vault_id).await;
                ack(&store, &request, context.responder_device_id, 0).await;
                store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await.expect("explicit zero");
                unchanged(&store, request.personal_vault_id).await;
                close(store, directory).await;
            }

            #[tokio::test]
            async fn inactive_or_missing_unrevoked_identity_keeps_the_time_policy() {
                let (store, directory, request) = setup().await;
                let (context, _, complete) = crate::$module::ready(&store, &request).await;
                store.complete_pairing(ORIGIN, context.pairing_id, &principal(&request), &complete, source()).await.expect("pair");
                ack(&store, &request, request.device_certificate.device_id, 2).await;
                ack(&store, &request, context.responder_device_id, 2).await;
                sqlx::query(&sql("UPDATE identity_devices SET active=? WHERE device_id=?")).bind(false).bind(context.responder_device_id.as_bytes().as_slice()).execute(store.pool()).await.expect("inactive projection");
                store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await.expect("inactive peer");
                unchanged(&store, request.personal_vault_id).await;
                sqlx::query(&sql("DELETE FROM identity_devices WHERE device_id=?")).bind(context.responder_device_id.as_bytes().as_slice()).execute(store.pool()).await.expect("missing admission");
                store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await.expect("missing peer");
                unchanged(&store, request.personal_vault_id).await;
                let report = store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms() + TOMBSTONE_PURGE_AFTER_DAYS * 86_400_000).await.expect("time policy still runs");
                assert_eq!(report.purged_tombstones, 1);
                close(store, directory).await;
            }

            #[tokio::test]
            async fn signed_revocation_excludes_an_active_peer_without_an_ack() {
                let (store, directory, request) = setup().await;
                let (context, _, complete) = crate::$module::ready(&store, &request).await;
                store.complete_pairing(ORIGIN, context.pairing_id, &principal(&request), &complete, source()).await.expect("pair");
                ack(&store, &request, request.device_certificate.device_id, 2).await;
                let own = request.device_certificate.encode().expect("certificate");
                let revoked = RevocationStatement::issue(&account_key(), context.responder_device_id, 2, "retired".into()).expect("signed revocation").encode().expect("encoded");
                store.replace_account_key_statements(request.account_id.into_bytes(), &[own, complete.device_certificate], &[revoked]).await.expect("publish revocation");
                let report = store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await.expect("verified revocation");
                assert_eq!(report.purged_tombstones, 1);
                close(store, directory).await;
            }

            #[tokio::test]
            async fn empty_or_fully_revoked_sets_never_acknowledge_vacuously() {
                let (store, directory, request) = setup().await;
                ack(&store, &request, request.device_certificate.device_id, 2).await;
                let own = request.device_certificate.encode().expect("certificate");
                let revoked = RevocationStatement::issue(&account_key(), request.device_certificate.device_id, 2, "retired".into()).expect("signed revocation").encode().expect("encoded");
                store.replace_account_key_statements(request.account_id.into_bytes(), &[own], &[revoked]).await.expect("all revoked");
                store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await.expect("empty active set");
                unchanged(&store, request.personal_vault_id).await;
                store.replace_account_key_statements(request.account_id.into_bytes(), &[], &[]).await.expect("empty collection");
                store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await.expect("no certificates");
                unchanged(&store, request.personal_vault_id).await;
                close(store, directory).await;
            }

            #[tokio::test]
            async fn unsupported_and_bare_vaults_keep_180_day_cleanup() {
                let (store, directory) = $open().await;
                for kind in ["personal", "shared", "organization"] {
                    let vault = Uuid::now_v7();
                    sqlx::query(&sql("INSERT INTO sync_vaults(vault_id,kind) VALUES(?,?)"))
                        .bind(vault.as_bytes().as_slice()).bind(kind).execute(store.pool()).await.expect("unowned vault");
                    history(&store, vault, Uuid::now_v7()).await;
                    store.ack_sync_cursor(vault.into_bytes(), Uuid::now_v7().into_bytes(), 2).await.expect("ACK");
                    store.purge_sync_history_for_worker(vault.into_bytes(), now_ms()).await.expect("conservative policy");
                    unchanged(&store, vault).await;
                    let report = store.purge_sync_history_for_worker(vault.into_bytes(), now_ms() + TOMBSTONE_PURGE_AFTER_DAYS * 86_400_000).await.expect("expired");
                    assert_eq!(report.purged_tombstones, 1);
                }
                let vault = Uuid::now_v7();
                store.create_personal_sync_vault(vault.into_bytes(), Uuid::now_v7().into_bytes(), &[1]).await.expect("bare owner");
                history(&store, vault, Uuid::now_v7()).await;
                store.ack_sync_cursor(vault.into_bytes(), Uuid::now_v7().into_bytes(), 2).await.expect("ACK");
                store.purge_sync_history_for_worker(vault.into_bytes(), now_ms()).await.expect("owner lacks enrollment");
                unchanged(&store, vault).await;
                close(store, directory).await;
            }

            #[tokio::test]
            async fn invalid_signed_collections_and_identity_fail_without_pruning() {
                let (store, directory, request) = setup().await;
                ack(&store, &request, request.device_certificate.device_id, 2).await;
                let own = request.device_certificate.encode().expect("certificate");
                let mut bad_signature = request.device_certificate.clone();
                bad_signature.signature[0] ^= 1;
                let duplicate = certificate(request.account_id, request.device_certificate.device_id, 4);
                let wrong_account = certificate(Uuid::now_v7(), Uuid::now_v7(), 4).encode().expect("cross account");
                let revocation = RevocationStatement::issue(&account_key(), Uuid::now_v7(), 2, "retired".into()).expect("revocation");
                let mut bad_revocation = revocation.clone();
                bad_revocation.signature[0] ^= 1;
                let other_revocation = RevocationStatement::issue(&account_key(), revocation.device_id, 3, "duplicate".into()).expect("duplicate");
                let cases = [
                    (vec![vec![1]], vec![]),
                    (vec![bad_signature.encode().expect("bad signature")], vec![]),
                    (vec![own.clone(), duplicate.encode().expect("duplicate")], vec![]),
                    (vec![own.clone(), wrong_account], vec![]),
                    (vec![own.clone()], vec![bad_revocation.encode().expect("bad revocation")]),
                    (vec![own.clone()], vec![revocation.encode().expect("revocation"), other_revocation.encode().expect("duplicate revocation")]),
                ];
                for (certificates, revocations) in cases {
                    store.replace_account_key_statements(request.account_id.into_bytes(), &certificates, &revocations).await.expect("corrupt fixture collection");
                    assert!(store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await.is_err());
                    unchanged(&store, request.personal_vault_id).await;
                }
                store.replace_account_key_statements(request.account_id.into_bytes(), std::slice::from_ref(&own), &[]).await.expect("restore statements");
                let mismatch = certificate(request.account_id, request.device_certificate.device_id, 5).encode().expect("identity mismatch");
                sqlx::query(&sql("UPDATE identity_devices SET certificate=? WHERE device_id=?")).bind(mismatch).bind(request.device_certificate.device_id.as_bytes().as_slice()).execute(store.pool()).await.expect("corrupt identity projection");
                assert!(store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await.is_err());
                unchanged(&store, request.personal_vault_id).await;
                close(store, directory).await;
            }

            #[tokio::test]
            async fn corrupt_root_and_oversized_statement_collections_fail_before_purge() {
                let (store, directory, request) = setup().await;
                ack(&store, &request, request.device_certificate.device_id, 2).await;
                let wrong_root = Ed25519SigningKey::from_bytes(&[2; 32]).expect("other root").public_key();
                sqlx::query(&sql("UPDATE identity_accounts SET account_signing_public_key=? WHERE account_id=?")).bind(wrong_root.as_slice()).bind(request.account_id.as_bytes().as_slice()).execute(store.pool()).await.expect("corrupt account root");
                assert!(store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await.is_err());
                unchanged(&store, request.personal_vault_id).await;
                sqlx::query(&sql("UPDATE identity_accounts SET account_signing_public_key=? WHERE account_id=?")).bind(account_key().public_key().as_slice()).bind(request.account_id.as_bytes().as_slice()).execute(store.pool()).await.expect("restore root");
                let template = certificate(request.account_id, Uuid::now_v7(), 4);
                for _ in 0..68 {
                    let certificate = DeviceCertificate::issue(&account_key(), Uuid::now_v7(), request.account_id, template.signing_public_key.clone(), template.kem_public_key.clone(), "x".repeat(63_000), "windows".into(), 1).expect("large signed certificate").encode().expect("encoded certificate");
                    sqlx::query(&sql("INSERT INTO sync_account_key_certificates(account_id,certificate) VALUES(?,?)")).bind(request.account_id.as_bytes().as_slice()).bind(certificate).execute(store.pool()).await.expect("corrupt aggregate capacity");
                }
                assert!(matches!(store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await, Err(SyncStoreError::AuthorizationUnavailable)));
                unchanged(&store, request.personal_vault_id).await;
                close(store, directory).await;
            }

            #[tokio::test]
            async fn ahead_ack_and_late_horizon_failure_roll_back_all_history() {
                let (store, directory, request) = setup().await;
                ack(&store, &request, request.device_certificate.device_id, 2).await;
                sqlx::query(&sql("UPDATE sync_acks SET cursor=3 WHERE vault_id=?")).bind(request.personal_vault_id.as_bytes().as_slice()).execute(store.pool()).await.expect("corrupt ACK");
                assert!(matches!(store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await, Err(SyncStoreError::CorruptRow("retention acknowledgement"))));
                unchanged(&store, request.personal_vault_id).await;
                sqlx::query(&sql("UPDATE sync_acks SET cursor=2 WHERE vault_id=?")).bind(request.personal_vault_id.as_bytes().as_slice()).execute(store.pool()).await.expect("restore ACK");
                let name = format!("retention_fail_{}", Uuid::new_v4().simple());
                let hex = request.personal_vault_id.simple();
                let trigger = if $postgres {
                    format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'retention horizon unavailable'; END $$;
                        CREATE TRIGGER {name} BEFORE UPDATE ON sync_vaults FOR EACH ROW WHEN (OLD.vault_id=decode('{hex}','hex') AND NEW.purge_horizon>OLD.purge_horizon) EXECUTE FUNCTION {name}()")
                } else {
                    format!("CREATE TRIGGER {name} BEFORE UPDATE ON sync_vaults WHEN OLD.vault_id=X'{hex}' AND NEW.purge_horizon>OLD.purge_horizon BEGIN SELECT RAISE(FAIL,'retention horizon unavailable'); END")
                };
                sqlx::raw_sql(&trigger).execute(store.pool()).await.expect("install late failure");
                assert!(store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await.is_err());
                unchanged(&store, request.personal_vault_id).await;
                let remove = if $postgres { format!("DROP TRIGGER {name} ON sync_vaults; DROP FUNCTION {name}()") } else { format!("DROP TRIGGER {name}") };
                sqlx::raw_sql(&remove).execute(store.pool()).await.expect("remove fixture trigger");
                assert_eq!(store.purge_sync_history_for_worker(request.personal_vault_id.into_bytes(), now_ms()).await.expect("retry").purged_tombstones, 1);
                close(store, directory).await;
            }
        }
    };
}

retention_tests!(sqlite, SqliteStore, sqlite_open, false);
#[cfg(feature = "postgres-integration")]
retention_tests!(postgres, scoplen_store::PostgresStore, postgres_open, true);

#[tokio::test]
async fn sqlite_retention_reads_current_identity_after_obtaining_the_writer_lock() {
    let (store, directory, request) = sqlite::setup().await;
    sqlite::ack(&store, &request, request.device_certificate.device_id, 2).await;
    let mut holder = store.pool().begin_with("BEGIN IMMEDIATE").await.expect("writer");
    sqlx::query("UPDATE identity_devices SET active=0 WHERE device_id=?")
        .bind(request.device_certificate.device_id.as_bytes().as_slice())
        .execute(&mut *holder)
        .await
        .expect("uncommitted identity change");
    let attempting = store.clone();
    let vault = request.personal_vault_id.into_bytes();
    let mut task =
        tokio::spawn(
            async move { attempting.purge_sync_history_for_worker(vault, now_ms()).await },
        );
    assert!(tokio::time::timeout(std::time::Duration::from_millis(100), &mut task).await.is_err());
    holder.commit().await.expect("publish inactive identity");
    let report = task.await.expect("retention task").expect("serialized read");
    assert_eq!(report.purged_tombstones, 0);
    assert_eq!(report.purge_horizon, 0);
    store.pool().close().await;
    support::remove_test_directory(directory.expect("SQLite directory")).await;
}

#[cfg(feature = "postgres-integration")]
async fn blocked_by(store: &scoplen_store::PostgresStore, blocker: i32, prefix: &str) -> i32 {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar(
                "SELECT pid FROM pg_stat_activity WHERE datname=current_database()
                 AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE $2 LIMIT 1",
            )
            .bind(blocker)
            .bind(format!("{prefix}%"))
            .fetch_optional(store.pool())
            .await
            .expect("observe blocked backend");
            if let Some(pid) = pid {
                break pid;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("expected lock wait")
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_retention_waits_for_actual_pairing_commit_and_counts_the_new_device() {
    let (store, _, request) = postgres::setup().await;
    postgres::ack(&store, &request, request.device_certificate.device_id, 2).await;
    let (context, _, complete) = crate::postgres::ready(&store, &request).await;
    let mut holder = store.pool().begin().await.expect("pairing barrier");
    let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *holder)
        .await
        .expect("barrier pid");
    let gate = i32::from_be_bytes(Uuid::new_v4().as_bytes()[12..].try_into().expect("gate"));
    sqlx::query("SELECT pg_advisory_xact_lock(1935897196,$1)")
        .bind(gate)
        .execute(&mut *holder)
        .await
        .expect("hold gate");
    let name = format!("retention_gate_{}", Uuid::new_v4().simple());
    let hex = context.responder_device_id.simple();
    sqlx::raw_sql(&format!(
        "CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(1935897196,{gate}); RETURN NEW; END $$;
         CREATE TRIGGER {name} BEFORE INSERT ON identity_devices FOR EACH ROW WHEN (NEW.device_id=decode('{hex}','hex')) EXECUTE FUNCTION {name}()"
    )).execute(store.pool()).await.expect("gate actual pairing insert");
    let pairing_store = store.clone();
    let old = principal(&request);
    let pairing = tokio::spawn(async move {
        pairing_store.complete_pairing(ORIGIN, context.pairing_id, &old, &complete, source()).await
    });
    let pairing_pid = blocked_by(&store, holder_pid, "INSERT INTO identity_devices").await;
    let retention_store = store.clone();
    let vault = request.personal_vault_id.into_bytes();
    let retention = tokio::spawn(async move {
        retention_store.purge_sync_history_for_worker(vault, now_ms()).await
    });
    blocked_by(&store, pairing_pid, "SELECT pg_advisory_xact_lock_shared").await;
    holder.commit().await.expect("release pairing commit");
    let (paired, purged) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        (pairing.await.expect("pairing task"), retention.await.expect("retention task"))
    })
    .await
    .expect("serialized completion");
    paired.expect("actual membership commit");
    assert_eq!(purged.expect("new device missing ACK").purged_tombstones, 0);
    sqlx::raw_sql(&format!("DROP TRIGGER {name} ON identity_devices; DROP FUNCTION {name}()"))
        .execute(store.pool())
        .await
        .expect("remove fixture gate");
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_retention_publication_and_authorized_ack_keep_account_before_vault_order() {
    let (store, _, request) = postgres::setup().await;
    postgres::ack(&store, &request, request.device_certificate.device_id, 1).await;
    let mut holder = store.pool().begin().await.expect("vault holder");
    let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *holder)
        .await
        .expect("holder pid");
    sqlx::query("SELECT vault_id FROM sync_vaults WHERE vault_id=$1 FOR UPDATE")
        .bind(request.personal_vault_id.as_bytes().as_slice())
        .fetch_one(&mut *holder)
        .await
        .expect("hold vault");
    let retaining = store.clone();
    let vault = request.personal_vault_id.into_bytes();
    let retention =
        tokio::spawn(async move { retaining.purge_sync_history_for_worker(vault, now_ms()).await });
    let retention_pid = blocked_by(&store, holder_pid, "UPDATE sync_vaults").await;
    let mut update = request.key_bundle_update.clone();
    update.revision = 2;
    update.signature = account_key().sign(&update.signature_input().expect("input")).to_vec();
    let publishing = store.clone();
    let author = principal(&request);
    let publication = tokio::spawn(async move {
        publishing
            .publish_account_key_bundle(
                &author,
                u64::try_from(now_ms() / 1000).expect("clock") + 600,
                &update,
            )
            .await
    });
    blocked_by(&store, retention_pid, "SELECT pg_advisory_xact_lock(").await;
    let acknowledging = store.clone();
    let author = principal(&request);
    let ack = tokio::spawn(async move {
        let authorization = PersonalMutation {
            account_id: author.account_id,
            device_id: author.device_id,
            dpop_jkt: &author.jkt,
            signers: &[],
        };
        acknowledging.ack_personal_sync_cursor(vault, &authorization, 2).await
    });
    holder.commit().await.expect("release vault");
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        retention.await.expect("retention").expect("retention result");
        publication.await.expect("publication").expect("publication result");
        assert_eq!(ack.await.expect("ACK").expect("ACK result"), 2);
    })
    .await
    .expect("no reverse lock cycle");
    assert_eq!(
        store
            .purge_sync_history_for_worker(vault, now_ms())
            .await
            .expect("latest ACK")
            .purged_tombstones,
        1
    );
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_retention_rechecks_owner_after_waiting_for_its_row() {
    let (store, _, request) = postgres::setup().await;
    postgres::ack(&store, &request, request.device_certificate.device_id, 2).await;
    let mut holder = store.pool().begin().await.expect("owner change");
    let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *holder)
        .await
        .expect("holder pid");
    sqlx::query("UPDATE sync_personal_vaults SET account_id=$1 WHERE vault_id=$2")
        .bind(Uuid::now_v7().as_bytes().as_slice())
        .bind(request.personal_vault_id.as_bytes().as_slice())
        .execute(&mut *holder)
        .await
        .expect("uncommitted owner");
    let retaining = store.clone();
    let vault = request.personal_vault_id.into_bytes();
    let retention =
        tokio::spawn(async move { retaining.purge_sync_history_for_worker(vault, now_ms()).await });
    blocked_by(&store, holder_pid, "SELECT account_id FROM sync_personal_vaults").await;
    holder.commit().await.expect("commit changed owner");
    let report = retention.await.expect("retention").expect("conservative owner recheck");
    assert_eq!(report.purged_tombstones, 0);
    assert_eq!(report.purge_horizon, 0);
    store.pool().close().await;
}
