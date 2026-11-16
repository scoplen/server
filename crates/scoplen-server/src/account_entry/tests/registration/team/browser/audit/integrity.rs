// SPDX-License-Identifier: AGPL-3.0-only

use ed25519_dalek::{Signer as _, SigningKey};
use scoplen_audit::{MAX_EVENT_BYTES, checkpoint_payload};
use scoplen_store::{AuditCheckpoint, AuditEvent};

use super::*;

async fn checkpoint(f: &Fixture, event: &AuditEvent, time: i64) {
    let payload = checkpoint_payload(
        &event.organization_id,
        event.sequence,
        &event.event_hash,
        u64::try_from(time).unwrap(),
    )
    .unwrap();
    let checkpoint = AuditCheckpoint {
        organization_id: event.organization_id,
        sequence: event.sequence,
        head_hash: event.event_hash,
        signed_at_ms: time,
        signature: SigningKey::from_bytes(&[23; 32]).sign(&payload).to_bytes(),
    };
    match &f.backend {
        AuthBackend::Sqlite(store) => store.write_audit_checkpoint(&checkpoint).await,
        AuthBackend::Postgres(store) => store.write_audit_checkpoint(&checkpoint).await,
    }
    .expect("persist independently signed checkpoint");
}

async fn change_bytes(f: &Fixture, event: &AuditEvent, column: &str, bytes: &[u8]) {
    assert!(["event_bytes", "event_hash", "previous_hash"].contains(&column));
    let sql =
        format!("UPDATE audit_events SET {column}=$1 WHERE organization_id=$2 AND sequence=$3");
    match &f.backend {
        AuthBackend::Sqlite(store) => sqlx::query(&sql)
            .bind(bytes)
            .bind(event.organization_id.as_slice())
            .bind(i64::try_from(event.sequence).unwrap())
            .execute(store.pool())
            .await
            .map(|result| result.rows_affected()),
        AuthBackend::Postgres(store) => sqlx::query(&sql)
            .bind(bytes)
            .bind(event.organization_id.as_slice())
            .bind(i64::try_from(event.sequence).unwrap())
            .execute(store.pool())
            .await
            .map(|result| result.rows_affected()),
    }
    .expect("owned corruption fixture");
}

async fn change_time(f: &Fixture, event: &AuditEvent, time: i64, checkpoint: bool) {
    let sql = if checkpoint {
        "UPDATE audit_checkpoints SET signed_at_ms=$1 WHERE organization_id=$2 AND sequence=$3"
    } else {
        "UPDATE audit_events SET created_at_ms=$1 WHERE organization_id=$2 AND sequence=$3"
    };
    match &f.backend {
        AuthBackend::Sqlite(store) => sqlx::query(sql)
            .bind(time)
            .bind(event.organization_id.as_slice())
            .bind(i64::try_from(event.sequence).unwrap())
            .execute(store.pool())
            .await
            .map(|r| r.rows_affected()),
        AuthBackend::Postgres(store) => sqlx::query(sql)
            .bind(time)
            .bind(event.organization_id.as_slice())
            .bind(i64::try_from(event.sequence).unwrap())
            .execute(store.pool())
            .await
            .map(|r| r.rows_affected()),
    }
    .expect("owned row timestamp fixture");
}

async fn change_checkpoint(
    f: &Fixture,
    organization: Uuid,
    sequence: u64,
    column: &str,
    bytes: &[u8],
) {
    assert!(["signature", "head_hash"].contains(&column));
    let sql = format!(
        "UPDATE audit_checkpoints SET {column}=$1 WHERE organization_id=$2 AND sequence=$3"
    );
    match &f.backend {
        AuthBackend::Sqlite(store) => sqlx::query(&sql)
            .bind(bytes)
            .bind(organization.as_bytes().as_slice())
            .bind(i64::try_from(sequence).unwrap())
            .execute(store.pool())
            .await
            .map(|r| r.rows_affected()),
        AuthBackend::Postgres(store) => sqlx::query(&sql)
            .bind(bytes)
            .bind(organization.as_bytes().as_slice())
            .bind(i64::try_from(sequence).unwrap())
            .execute(store.pool())
            .await
            .map(|r| r.rows_affected()),
    }
    .expect("owned checkpoint corruption");
}

async fn read_report(
    f: &Fixture,
    native: &Actor,
    organization: Uuid,
    from: u64,
    to: u64,
) -> AuditVerification {
    report(
        &call(f, native, "GET", &verify_path(organization, from, to), &[], &[]).await,
        organization,
        from,
        to,
    )
}

fn failed(value: &AuditVerification, sequence: u64) {
    assert!(!value.valid);
    assert_eq!(value.failure_sequence, Some(sequence));
    assert_eq!(value.checked_events, sequence - value.from_sequence);
    assert!(value.previous_hash.is_none());
    assert!(value.head_hash.is_none());
    assert!(value.checkpoint.is_none());
    assert!(value.uncheckpointed_from_sequence.is_none());
}

#[allow(clippy::too_many_lines)]
async fn integrity(f: &Fixture) {
    let native = actor(f, "audit-integrity").await;
    let browser = login(f, &native.registration).await;
    let organization = create_team(f, &native).await.id;
    let mut events = Vec::new();
    for milliseconds in [0, 1, 10, 100, 999] {
        let time = 1_730_000_000_000 + milliseconds;
        let event = append(f, organization, b"original arbitrary bytes", time).await;
        checkpoint(f, &event, time).await;
        let value = read_report(f, &native, organization, event.sequence, event.sequence).await;
        assert!(value.valid);
        let evidence = value.checkpoint.unwrap();
        assert_eq!(evidence.signed_at, format_audit_timestamp(time).unwrap());
        assert_eq!(
            evidence.signed_payload(organization).unwrap(),
            checkpoint_payload(
                organization.as_bytes(),
                event.sequence,
                &event.event_hash,
                u64::try_from(time).unwrap()
            )
            .unwrap()
        );
        events.push(event);
        events.push(append(f, organization, b"uncheckpointed event", time).await);
    }
    let last = events.last().unwrap();
    let all = read_report(f, &native, organization, 1, last.sequence).await;
    assert!(all.valid);
    assert_eq!(all.previous_hash, Some([0; 32]));
    assert_eq!(all.head_hash, Some(last.event_hash));
    assert_eq!(all.checkpoint.as_ref().unwrap().sequence, last.sequence - 1);
    assert_eq!(all.uncheckpointed_from_sequence, Some(last.sequence));
    let historical = read_report(f, &native, organization, 3, 3).await;
    assert!(historical.valid && historical.checkpoint.is_none());
    assert_eq!(historical.uncheckpointed_from_sequence, Some(3));
    let first = read_report(f, &native, organization, 1, 5).await;
    let next = report(
        &business(f, &browser, "GET", &verify_path(organization, 6, 11), &[], &[]).await,
        organization,
        6,
        11,
    );
    assert!(first.valid && next.valid);
    assert_eq!(
        first.head_hash, next.previous_hash,
        "adjacent intervals join only through the exact chain hash"
    );
    let target = &events[2]; // Sequence 4, with its own checkpoint.
    for (column, corrupted, original) in [
        ("event_bytes", b"changed original bytes".as_slice(), target.event_bytes.as_slice()),
        ("event_hash", [9; 32].as_slice(), target.event_hash.as_slice()),
        ("previous_hash", [8; 32].as_slice(), target.previous_hash.as_slice()),
    ] {
        change_bytes(f, target, column, corrupted).await;
        failed(&read_report(f, &native, organization, 2, 8).await, 4);
        change_bytes(f, target, column, original).await;
    }
    let predecessor = &events[1];
    change_bytes(f, predecessor, "event_bytes", b"damaged predecessor").await;
    failed(&read_report(f, &native, organization, 4, 8).await, 4);
    change_bytes(f, predecessor, "event_bytes", &predecessor.event_bytes).await;
    // Unsigned row creation time is a query transport field, not signed chain material.
    change_time(f, target, i64::MAX, false).await;
    let expression = "occurred_at lt \"2024-10-27T03:33:20Z\"";
    call(
        f,
        &native,
        "GET",
        &format!("{}?{}", timeline(organization), filtered(expression)),
        &[],
        &[],
    )
    .await
    .problem(503, "organization.storage_unavailable", true);
    assert!(read_report(f, &native, organization, 1, 11).await.valid);
    change_time(f, target, target.created_at_ms, false).await;
    change_checkpoint(f, organization, 4, "signature", &[0; 64]).await;
    failed(&read_report(f, &native, organization, 2, 8).await, 4);
    let payload = checkpoint_payload(
        organization.as_bytes(),
        4,
        &target.event_hash,
        u64::try_from(target.created_at_ms).unwrap(),
    )
    .unwrap();
    let signature = SigningKey::from_bytes(&[23; 32]).sign(&payload).to_bytes();
    change_checkpoint(f, organization, 4, "signature", &signature).await;
    let wrong_signature = SigningKey::from_bytes(&[24; 32]).sign(&payload).to_bytes();
    change_checkpoint(f, organization, 4, "signature", &wrong_signature).await;
    failed(&read_report(f, &native, organization, 2, 8).await, 4);
    change_checkpoint(f, organization, 4, "signature", &signature).await;
    change_checkpoint(f, organization, 4, "head_hash", &[9; 32]).await;
    failed(&read_report(f, &native, organization, 2, 8).await, 4);
    change_checkpoint(f, organization, 4, "head_hash", &target.event_hash).await;
    change_time(f, target, i64::MAX, true).await;
    failed(&read_report(f, &native, organization, 2, 8).await, 4);
    change_time(f, target, target.created_at_ms, true).await;
    assert!(read_report(f, &native, organization, 2, 8).await.valid);
    // Keep the signed position while removing its event; this is corruption, not an uncreated range.
    let sql = "DELETE FROM audit_events WHERE organization_id=$1 AND sequence>=4";
    match &f.backend {
        AuthBackend::Sqlite(store) => sqlx::query(sql)
            .bind(organization.as_bytes().as_slice())
            .execute(store.pool())
            .await
            .map(|r| r.rows_affected()),
        AuthBackend::Postgres(store) => sqlx::query(sql)
            .bind(organization.as_bytes().as_slice())
            .execute(store.pool())
            .await
            .map(|r| r.rows_affected()),
    }
    .expect("owned missing-row fixture");
    failed(&read_report(f, &native, organization, 2, 8).await, 4);
    failed(&read_report(f, &native, organization, 4, 4).await, 4);
    failed(&read_report(f, &native, organization, 5, 8).await, 5);
    for table in ["audit_events", "audit_checkpoints"] {
        let sql = format!("DELETE FROM {table} WHERE organization_id=$1");
        match &f.backend {
            AuthBackend::Sqlite(store) => sqlx::query(&sql)
                .bind(organization.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .map(|r| r.rows_affected()),
            AuthBackend::Postgres(store) => sqlx::query(&sql)
                .bind(organization.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .map(|r| r.rows_affected()),
        }
        .expect("owned empty-chain fixture");
    }
    call(f, &native, "GET", &verify_path(organization, 1, 1), &[], &[]).await.problem(
        400,
        "organization.invalid_request",
        false,
    );
}

async fn bounded(f: &Fixture) {
    let native = actor(f, "audit-bounds").await;
    let organization = create_team(f, &native).await.id;
    macro_rules! fill {
        ($store:expr, $begin:literal, $append:path) => {{
            let mut tx =
                $store.pool().begin_with($begin).await.expect("bounded fixture transaction");
            for _ in 1..4096 {
                $append(&mut tx, organization.into_bytes(), b"{}", 1_730_000_000_000)
                    .await
                    .expect("bounded original row");
            }
            tx.commit().await.expect("bounded fixture commit");
        }};
    }
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            fill!(
                store,
                "BEGIN IMMEDIATE",
                scoplen_store::audit::append_audit_event_in_transaction
            );
        }
        AuthBackend::Postgres(store) => {
            fill!(store, "BEGIN", scoplen_store::audit::append_audit_event_in_postgres_transaction);
        }
    }
    let result = read_report(f, &native, organization, 1, 4096).await;
    assert!(result.valid);
    assert_eq!(result.checked_events, 4096);
    call(f, &native, "GET", &verify_path(organization, 1, 4097), &[], &[]).await.problem(
        413,
        "organization.invalid_request",
        false,
    );
    let organization = create_team(f, &native).await.id;
    let first = page(
        &call(f, &native, "GET", &timeline(organization), &[], &[]).await,
        organization,
        &AuditListQuery::default(),
    );
    assert_eq!(first.items.len(), 1);
    let first_length: i64 = {
        let sql = match &f.backend {
            AuthBackend::Sqlite(_) => {
                "SELECT length(event_bytes) FROM audit_events WHERE organization_id=$1"
            }
            AuthBackend::Postgres(_) => {
                "SELECT CAST(octet_length(event_bytes) AS BIGINT) FROM audit_events WHERE organization_id=$1"
            }
        };
        match &f.backend {
            AuthBackend::Sqlite(store) => {
                sqlx::query_scalar(sql)
                    .bind(organization.as_bytes().as_slice())
                    .fetch_one(store.pool())
                    .await
            }
            AuthBackend::Postgres(store) => {
                sqlx::query_scalar(sql)
                    .bind(organization.as_bytes().as_slice())
                    .fetch_one(store.pool())
                    .await
            }
        }
        .unwrap()
    };
    let payload = vec![b'x'; MAX_EVENT_BYTES];
    for _ in 0..15 {
        append(f, organization, &payload, 1_730_000_000_000).await;
    }
    let remaining = MAX_EVENT_BYTES - usize::try_from(first_length).unwrap();
    let tail = append(f, organization, &payload[..remaining], 1_730_000_000_000).await;
    let exact = read_report(f, &native, organization, 2, tail.sequence).await;
    assert!(exact.valid, "the 16 MiB boundary includes the immediate predecessor");
    let over = append(f, organization, b"x", 1_730_000_000_000).await;
    call(f, &native, "GET", &verify_path(organization, 2, over.sequence), &[], &[]).await.problem(
        413,
        "organization.invalid_request",
        false,
    );
}

browser_tests!(
    sqlite_organization_audit_integrity,
    postgres_organization_audit_integrity,
    integrity
);
browser_tests!(sqlite_organization_audit_bounds, postgres_organization_audit_bounds, bounded);
