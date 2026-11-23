// SPDX-License-Identifier: AGPL-3.0-only

use scoplen_api::audit::{
    AuditCategory, AuditFilter, AuditListQuery, AuditOutcome, AuditPage, AuditRange, AuditResource,
    AuditResourceKind, AuditVerification,
};

use super::*;

async fn draft_audit(f: &Fixture) {
    let owner = actor(f, "draft-audit-owner").await;
    let outsider = actor(f, "draft-audit-outsider").await;
    let org = create_team(f, &owner).await.id;
    let browser = login(f, &owner.registration).await;
    let token = AccountBrowserAccessToken::parse(&browser.access).unwrap();
    let session = match &f.backend {
        AuthBackend::Sqlite(store) => store.current_account_browser_session(&token, ORIGIN).await,
        AuthBackend::Postgres(store) => store.current_account_browser_session(&token, ORIGIN).await,
    }
    .unwrap()
    .unwrap();
    let device = Writer::device(&owner);
    let browser = Writer::browser(&browser);
    let tls = TlsFixture::start(f).await;
    let root = format!("/api/v1/orgs/{org}");
    let path = format!("{root}/auth-connection-draft");
    let new_key = || Uuid::now_v7().to_string();
    let first = resource(
        &device.send(&tls, "POST", &path, CREATE, &create_headers(&new_key())).await,
        201,
        org,
    );
    cancelled(
        &browser.send(&tls, "DELETE", &path, &[], &cancel_headers(&new_key(), &first.etag())).await,
    );
    let second = resource(
        &browser.send(&tls, "POST", &path, CREATE, &create_headers(&new_key())).await,
        201,
        org,
    );
    assert_ne!(first.id, second.id);

    let target = AuditResource { kind: AuditResourceKind::AuthConnectionDraft, id: first.id };
    let filter = format!("resource eq \"{}:{}\"", target.kind.as_str(), target.id);
    let audit_url = |filter: &str| {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("filter", filter)
            .finish();
        format!("{root}/audit-events?{query}")
    };
    let url = audit_url(&filter);
    let reply = browser.send(&tls, "GET", &url, &[], &[]).await;
    assert_eq!(reply.status, 200);
    reply.private();
    assert!(!String::from_utf8_lossy(&reply.body).contains(&first.issuer));
    let query =
        AuditListQuery { filter: AuditFilter::parse(&filter).unwrap(), ..Default::default() };
    let page = AuditPage::from_json_for(&reply.body, org, &query).unwrap();
    assert_eq!(page.items.len(), 2);
    assert!(page.next_cursor.is_none());
    let deleted = &page.items[0];
    let created = &page.items[1];
    assert_eq!(deleted.event_class.as_deref(), Some("organization.auth_draft_cancelled"));
    assert_eq!(created.event_class.as_deref(), Some("organization.auth_draft_created"));
    for item in &page.items {
        assert_eq!(item.category, AuditCategory::Scoplen);
        assert_eq!(item.outcome, AuditOutcome::Success);
        assert_eq!(item.resource.as_ref(), Some(&target));
        assert_eq!(item.actor_account_id, Some(owner.registration.payload.account_id));
    }
    assert_eq!(created.actor_device_id, Some(owner.registration.payload.device_id));
    assert!(created.actor_browser_family_id.is_none());
    assert_eq!(deleted.actor_browser_family_id, Some(Uuid::from_bytes(session.family_id)));
    assert!(deleted.actor_device_id.is_none());

    let filter = format!("{filter} and event_class eq \"organization.auth_draft_created\"");
    let query =
        AuditListQuery { filter: AuditFilter::parse(&filter).unwrap(), ..Default::default() };
    let reply = device.send(&tls, "GET", &audit_url(&filter), &[], &[]).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        AuditPage::from_json_for(&reply.body, org, &query).unwrap().items,
        std::slice::from_ref(created)
    );

    let range = AuditRange::new(created.sequence, deleted.sequence).unwrap();
    let verify = format!(
        "{root}/audit-events/verify?from_sequence={}&to_sequence={}",
        created.sequence, deleted.sequence
    );
    let reply = device.send(&tls, "GET", &verify, &[], &[]).await;
    assert_eq!(reply.status, 200);
    assert!(AuditVerification::from_json_for(&reply.body, org, range).unwrap().valid);
    denied(
        &Writer::device(&outsider).send(&tls, "GET", &url, &[], &[]).await,
        404,
        "organization.not_found",
    );
}

browser_tests!(
    sqlite_issuer_draft_https_audit_generation_and_writer,
    postgres_issuer_draft_https_audit_generation_and_writer,
    draft_audit
);
