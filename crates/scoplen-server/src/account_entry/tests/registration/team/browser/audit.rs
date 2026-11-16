// SPDX-License-Identifier: AGPL-3.0-only
//! Real Device and Account-browser HTTP reads of the retained Organization chain.

use scoplen_api::audit::{
    AuditCategory, AuditFilter, AuditListQuery, AuditPage, AuditRange, AuditResource,
    AuditResourceKind, AuditVerification, format_audit_timestamp,
};
use serde_json::json;

use super::{business::business, *};

mod integrity;
mod permissions;

fn timeline(organization: Uuid) -> String {
    format!("/api/v1/orgs/{organization}/audit-events")
}

fn verify_path(organization: Uuid, from: u64, to: u64) -> String {
    format!("{}/verify?from_sequence={from}&to_sequence={to}", timeline(organization))
}

fn page(reply: &Reply, organization: Uuid, query: &AuditListQuery) -> AuditPage {
    assert_eq!(reply.status, 200, "{}", String::from_utf8_lossy(&reply.body));
    reply.private();
    assert!(reply.header("x-request-id").is_some());
    assert!(reply.header("set-cookie").is_none());
    assert!(reply.header("etag").is_none());
    AuditPage::from_json_for(&reply.body, organization, query).expect("request-bound Audit Page")
}

fn report(reply: &Reply, organization: Uuid, from: u64, to: u64) -> AuditVerification {
    assert_eq!(reply.status, 200, "{}", String::from_utf8_lossy(&reply.body));
    reply.private();
    assert!(reply.header("x-request-id").is_some());
    assert!(reply.header("set-cookie").is_none());
    AuditVerification::from_json_for(
        &reply.body,
        organization,
        AuditRange::new(from, to).expect("range"),
    )
    .expect("request-bound Verification Result")
}

async fn append(
    f: &Fixture,
    organization: Uuid,
    bytes: &[u8],
    time: i64,
) -> scoplen_store::AuditEvent {
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            store.append_audit_event(organization.into_bytes(), bytes, time).await
        }
        AuthBackend::Postgres(store) => {
            store.append_audit_event(organization.into_bytes(), bytes, time).await
        }
    }
    .expect("append original audit bytes")
}

fn filtered(query: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new()).append_pair("filter", query).finish()
}

type OriginalMaterial = (i64, Vec<u8>, Vec<u8>, Vec<u8>);

async fn original_material(f: &Fixture, organization: Uuid) -> Vec<OriginalMaterial> {
    let sql = "SELECT sequence,event_bytes,previous_hash,event_hash FROM audit_events WHERE organization_id=$1 ORDER BY sequence";
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            sqlx::query_as(sql)
                .bind(organization.as_bytes().as_slice())
                .fetch_all(store.pool())
                .await
        }
        AuthBackend::Postgres(store) => {
            sqlx::query_as(sql)
                .bind(organization.as_bytes().as_slice())
                .fetch_all(store.pool())
                .await
        }
    }
    .expect("original immutable material")
}

#[allow(clippy::too_many_lines)]
async fn search(f: &Fixture) {
    let native = actor(f, "audit-search").await;
    let browser = login(f, &native.registration).await;
    let organization = create_team(f, &native).await.id;
    let root = timeline(organization);
    let target = Uuid::now_v7();
    let account = native.registration.payload.account_id;
    let known = json!({"action":"organization.inventory_deleted","account_id":account,
        "device_id":native.registration.payload.device_id,"object_id":target,"object_type":1,
        "unprojected":"private marker"});
    let first =
        append(f, organization, &serde_json::to_vec(&known).unwrap(), 1_730_000_000_001).await;
    let second = append(
        f,
        organization,
        &serde_json::to_vec(&json!({"action":"legacy.unknown","outcome":"failure",
            "account_id":account}))
        .unwrap(),
        1_730_000_000_010,
    )
    .await;
    let third = append(
        f,
        organization,
        br#"{"action":"organization.created","extra":{"x":1,"x":2}}"#,
        1_730_000_000_100,
    )
    .await;
    let query = AuditListQuery { limit: 2, ..AuditListQuery::default() };
    let first_page = page(
        &business(f, &browser, "GET", &format!("{root}?limit=2"), &[], &[]).await,
        organization,
        &query,
    );
    assert_eq!(
        first_page.items.iter().map(|event| event.sequence).collect::<Vec<_>>(),
        [third.sequence, second.sequence]
    );
    assert_eq!(first_page.next_cursor, Some(second.sequence));
    assert_eq!(first_page.items[0].category, AuditCategory::Unknown);
    assert!(first_page.items[0].event_class.is_none());
    assert_eq!(first_page.items[1].event_class.as_deref(), Some("legacy.unknown"));
    assert!(first_page.items[1].actor_account_id.is_none());
    let cursor = second.sequence;
    let next_query = AuditListQuery { cursor: Some(cursor), ..query };
    let next = page(
        &call(f, &native, "GET", &format!("{root}?limit=2&cursor={cursor}"), &[], &[]).await,
        organization,
        &next_query,
    );
    assert_eq!(next.items[0].sequence, first.sequence);
    assert!(next.next_cursor.is_none());
    assert_eq!(next.items[0].previous_hash, first.previous_hash);
    assert_eq!(next.items[0].event_hash, first.event_hash);
    assert_eq!(next.items[0].actor_account_id, Some(account));
    assert_eq!(
        next.items[0].resource,
        Some(AuditResource { kind: AuditResourceKind::Host, id: target })
    );
    assert!(!String::from_utf8(next.to_json().unwrap()).unwrap().contains("private marker"));

    for expression in [
        format!("actor_account_id eq \"{account}\""),
        format!("resource eq \"host:{target}\""),
        "event_class eq \"organization.inventory_deleted\"".into(),
        "outcome eq \"success\" and event_class eq \"organization.inventory_deleted\"".into(),
        "occurred_at ge \"2024-10-27T03:33:20.001Z\" and occurred_at lt \"2024-10-27T03:33:20.01Z\"".into(),
        format!("actor_account_id eq \"{account}\" and resource eq \"host:{target}\" and event_class eq \"organization.inventory_deleted\" and outcome eq \"success\" and occurred_at ge \"2024-10-27T03:33:20.001Z\" and occurred_at lt \"2024-10-27T03:33:20.01Z\""),
    ] {
        let query = AuditListQuery { filter: AuditFilter::parse(&expression).unwrap(),
            ..AuditListQuery::default() };
        let result = page(&business(f, &browser, "GET", &format!("{root}?{}", filtered(&expression)), &[], &[]).await,
            organization, &query);
        assert!(result.items.iter().any(|event| event.sequence == first.sequence));
        assert!(result.items.iter().all(|event| query.filter.matches(event).unwrap()));
    }
    let expression = "event_class eq \"legacy.unknown\" and outcome eq \"failure\"";
    let query = AuditListQuery {
        limit: 1,
        filter: AuditFilter::parse(expression).unwrap(),
        ..AuditListQuery::default()
    };
    let result = page(
        &call(f, &native, "GET", &format!("{root}?limit=1&{}", filtered(expression)), &[], &[])
            .await,
        organization,
        &query,
    );
    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].sequence, second.sequence);
    assert!(result.next_cursor.is_none(), "lookahead counts another match, not another row");
    let latest = append(f, organization, br#"{"action":"legacy.latest"}"#, 1_730_000_000_999).await;
    let original = original_material(f, organization).await;
    let refresh = page(
        &business(f, &browser, "GET", &format!("{root}?limit=2"), &[], &[]).await,
        organization,
        &AuditListQuery { limit: 2, ..AuditListQuery::default() },
    );
    assert_eq!(refresh.items[0].sequence, latest.sequence);
    let continued = page(
        &call(f, &native, "GET", &format!("{root}?limit=2&cursor={cursor}"), &[], &[]).await,
        organization,
        &next_query,
    );
    assert_eq!(continued, next, "appends do not move an existing sequence cursor");
    let full = page(
        &call(f, &native, "GET", &format!("{root}?cursor={}", u64::MAX), &[], &[]).await,
        organization,
        &AuditListQuery { cursor: Some(u64::MAX), ..AuditListQuery::default() },
    );
    assert_eq!(full.items.len(), 5);
    let valid = report(
        &business(f, &browser, "GET", &verify_path(organization, 1, latest.sequence), &[], &[])
            .await,
        organization,
        1,
        latest.sequence,
    );
    assert!(valid.valid, "unusable body metadata is not a chain-integrity failure");

    for query in [
        "limit=0",
        "limit=1&limit=2",
        "cursor=01",
        "sort=sequence",
        "unknown=x",
        "filter=outcome%20eq%20%22SUCCESS%22",
    ] {
        business(f, &browser, "GET", &format!("{root}?{query}"), &[], &[]).await.problem(
            400,
            "organization.invalid_request",
            false,
        );
    }
    for query in [
        "from_sequence=1",
        "from_sequence=0&to_sequence=1",
        "from_sequence=2&to_sequence=1",
        "from_sequence=1&to_sequence=1&cursor=2",
        "from_sequence=1&to_sequence=99",
    ] {
        call(f, &native, "GET", &format!("{root}/verify?{query}"), &[], &[]).await.problem(
            400,
            "organization.invalid_request",
            false,
        );
    }
    for path in [root.clone(), verify_path(organization, 1, 1)] {
        for header in ["If-Match", "Idempotency-Key"] {
            business(f, &browser, "GET", &path, &[], &[(header, "rejected")]).await.problem(
                400,
                "organization.invalid_request",
                false,
            );
        }
        call(f, &native, "GET", &path, b"{}", &[]).await.problem(
            400,
            "organization.invalid_request",
            false,
        );
        let ignored =
            business(f, &browser, "GET", &path, &[], &[("Cookie", "untrusted=ignored")]).await;
        assert_eq!(ignored.status, 200);
        assert!(ignored.header("set-cookie").is_none());
    }
    let overflow = "a".repeat(scoplen_api::audit::MAX_AUDIT_QUERY_BYTES + 1);
    call(f, &native, "GET", &format!("{root}?{overflow}"), &[], &[]).await.problem(
        413,
        "organization.invalid_request",
        false,
    );
    call(f, &native, "GET", &verify_path(organization, 1, 4097), &[], &[]).await.problem(
        413,
        "organization.invalid_request",
        false,
    );
    assert_eq!(
        original_material(f, organization).await,
        original,
        "queries and verification preserve original event bytes and stored hashes"
    );
}

browser_tests!(sqlite_organization_audit_search, postgres_organization_audit_search, search);
