// SPDX-License-Identifier: AGPL-3.0-only
//! A browser family's discovery admission is shared across mounted Server instances.

use axum::http::StatusCode;

use super::*;

async fn begin(tls: &TlsFixture, browser: &Browser, draft: &DraftResource) -> Reply {
    send(
        tls,
        browser,
        "POST",
        &format!("/api/v1/orgs/{}/auth-connection/activations", draft.organization_id),
        &start_headers(("If-None-Match", "*")),
        candidate(draft.id).as_bytes(),
    )
    .await
}

async fn concurrent_starts(f: &Fixture) {
    let (provider, gate) = Provider::start_with_discovery_gate(
        f.directory.join("activation-discovery-race"),
        ORIGIN,
        StatusCode::OK,
    )
    .await;
    let first = TlsFixture::start_with_enterprise_identity(f, provider.settings.clone()).await;
    let second = TlsFixture::start_with_enterprise_identity(f, provider.settings.clone()).await;
    let owner = actor(f, "activation-discovery-race").await;
    let org = create_team(f, &owner).await.id;
    let other_org = create_team(f, &owner).await.id;
    let browser = login(f, &owner.registration).await;
    let other_family = login(f, &owner.registration).await;
    let original = save_draft(&first, &browser, org, &provider.issuer).await;
    let competing = save_draft(&second, &browser, other_org, &provider.issuer).await;

    let while_discovering = async {
        tokio::time::timeout(Duration::from_secs(6), gate.request_received.notified())
            .await
            .expect("first Server reached the provider");
        begin(&second, &browser, &competing).await.problem(409, "organization.conflict", false);
        assert_eq!(provider.discoveries(), 1);
        assert_eq!(
            f.count("SELECT count(*) FROM organization_auth_connection_activations").await,
            0
        );

        // A different family can discover and commit against the very same draft.
        let independent = begin(&second, &other_family, &original).await;
        let independent = started(&independent, &original, ExpectedRevision::Empty);
        assert_eq!(provider.discoveries(), 2);
        gate.release_response.notify_one();
        independent.attempt.id
    };
    let (response, independent) =
        tokio::join!(begin(&first, &browser, &original), while_discovering);
    let original = started(&response, &original, ExpectedRevision::Empty);
    assert_ne!(original.attempt.id, independent);
    begin(&second, &browser, &competing).await.problem(409, "organization.conflict", false);
    assert_eq!(provider.discoveries(), 2);
    assert_eq!(provider.counts(), [0, 0, 0]);
    assert_eq!(
        f.count(
            "SELECT count(*) FROM organization_auth_connection_activations WHERE phase='pending'"
        )
        .await,
        2
    );
    provider.close().await;
}

browser_tests!(
    sqlite_auth_activation_https_discovery_reserved_across_servers,
    postgres_auth_activation_https_discovery_reserved_across_servers,
    concurrent_starts
);

async fn retry_after_discovery_failure(f: &Fixture) {
    let (provider, gate) = Provider::start_with_discovery_gate(
        f.directory.join("activation-discovery-retry"),
        ORIGIN,
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    let first = TlsFixture::start_with_enterprise_identity(f, provider.settings.clone()).await;
    let second = TlsFixture::start_with_enterprise_identity(f, provider.settings.clone()).await;
    let owner = actor(f, "activation-discovery-retry").await;
    let org = create_team(f, &owner).await.id;
    let browser = login(f, &owner.registration).await;
    let draft = save_draft(&first, &browser, org, &provider.issuer).await;
    let audit = f.count("SELECT count(*) FROM audit_events").await;
    let fail_discovery = async {
        tokio::time::timeout(Duration::from_secs(6), gate.request_received.notified())
            .await
            .expect("provider received the reserved discovery");
        begin(&second, &browser, &draft).await.problem(409, "organization.conflict", false);
        assert_eq!(provider.discoveries(), 1);
        gate.release_response.notify_one();
    };
    let (failed, ()) = tokio::join!(begin(&first, &browser, &draft), fail_discovery);
    failed.problem(503, "organization.auth_provider_unavailable", true);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_connection_activations").await, 0);
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit);

    let retried = begin(&second, &browser, &draft).await;
    started(&retried, &draft, ExpectedRevision::Empty);
    assert_eq!(provider.discoveries(), 2);
    assert_eq!(provider.counts(), [0, 0, 0]);
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit + 1);
    provider.close().await;
}

browser_tests!(
    sqlite_auth_activation_https_failed_discovery_releases_family,
    postgres_auth_activation_https_failed_discovery_releases_family,
    retry_after_discovery_failure
);
