// SPDX-License-Identifier: AGPL-3.0-only
//! Retained browser families keep their original, finite permission ceiling.

use scoplen_api::account_browser::{
    AccountBrowserAccessScope, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE,
};

use super::{business::business, *};

pub(super) async fn current_session(
    f: &Fixture,
    browser: &Browser,
) -> Option<scoplen_store::account_browser_sessions::CurrentAccountBrowserSession> {
    let token = AccountBrowserAccessToken::parse(&browser.access).expect("browser access");
    match &f.backend {
        AuthBackend::Sqlite(store) => store.current_account_browser_session(&token, ORIGIN).await,
        AuthBackend::Postgres(store) => store.current_account_browser_session(&token, ORIGIN).await,
    }
    .expect("current family lookup")
}

pub(super) async fn set_scope(f: &Fixture, family: [u8; 16], scope: &str) {
    let query = "UPDATE account_browser_families SET scope=$1 WHERE family_id=$2";
    let result = match &f.backend {
        AuthBackend::Sqlite(store) => sqlx::query(query)
            .bind(scope)
            .bind(family.as_slice())
            .execute(store.pool())
            .await
            .map(|result| result.rows_affected()),
        AuthBackend::Postgres(store) => sqlx::query(query)
            .bind(scope)
            .bind(family.as_slice())
            .execute(store.pool())
            .await
            .map(|result| result.rows_affected()),
    }
    .expect("retained fixture ceiling");
    assert_eq!(result, 1);
}

async fn retained_scope(f: &Fixture) {
    let account = register(f, "browser-retained-scope").await;
    let body = OrganizationCreateRequest::new("Missing permission")
        .expect("team name")
        .to_json()
        .expect("team request");
    let previous = INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE
        .split(' ')
        .filter(|scope| *scope != AccountBrowserAccessScope::OrganizationCreate.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    for scope in [previous.as_str(), "account:read orgs:read", "orgs:read"] {
        let mut browser = login(f, &account).await;
        let initial = current_session(f, &browser).await.expect("new family");
        assert_eq!(initial.scope, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE);
        // Model a family issued with a smaller ceiling before a later server upgrade.
        set_scope(f, initial.family_id, scope).await;
        for rotated in [false, true] {
            if rotated {
                let reply =
                    request(f, &browser.key, REFRESH, b"{}", None, Some(&browser.cookie)).await;
                (browser.access, browser.cookie) = session(&reply, false);
            }
            let retained = current_session(f, &browser).await.expect("retained family");
            assert_eq!(retained.scope, scope);
            assert_eq!(retained.family_id, initial.family_id);
            let reply = business(f, &browser, "GET", "/api/v1/orgs", &[], &[]).await;
            assert_eq!(reply.status, 200);
            reply.private();
            OrganizationPage::from_json(&reply.body).expect("permitted team discovery");
            let profile = business(f, &browser, "GET", "/api/v1/accounts/me", &[], &[]).await;
            if AccountBrowserAccessScope::AccountRead.is_present_in(scope) {
                assert_eq!(profile.status, 200);
                profile.private();
            } else {
                profile.problem(403, "policy.denied", false);
            }
            business(
                f,
                &browser,
                "POST",
                "/api/v1/orgs",
                &body,
                &[("Idempotency-Key", &Uuid::now_v7().to_string())],
            )
            .await
            .problem(403, "policy.denied", false);
        }
        assert_eq!(f.count("SELECT COUNT(*) FROM organizations").await, 0);
        let logout = request(f, &browser.key, LOGOUT, b"{}", Some(&browser.access), None).await;
        assert_eq!(logout.status, 200, "narrower families retain their own sign-out boundary");
        assert!(!current(f, &browser).await);
    }
    let fresh = login(f, &account).await;
    assert_eq!(
        current_session(f, &fresh).await.expect("fresh login family").scope,
        INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE
    );
}

async fn invalid_scope(f: &Fixture) {
    let account = register(f, "browser-invalid-scope").await;
    let mut browser = login(f, &account).await;
    let family = current_session(f, &browser).await.expect("new family").family_id;
    for scope in [
        "account:read account:read",
        "orgs:read account:read",
        "account:read  orgs:read",
        " account:read",
        "account:read ",
        "account:read\torgs:read",
        "account:read\norgs:read",
        "account:read\\orgs:read",
        "\"account:read\"",
        "Account:read",
        "account:r\u{e9}ad",
        "unknown:read",
        "account:read unknown:read",
    ] {
        set_scope(f, family, scope).await;
        assert!(current_session(f, &browser).await.is_none());
        business(f, &browser, "GET", "/api/v1/accounts/me", &[], &[]).await.problem(
            401,
            "auth.authentication_required",
            false,
        );
        request(f, &browser.key, REFRESH, b"{}", None, Some(&browser.cookie)).await.problem(
            401,
            "auth.authentication_required",
            false,
        );
        assert_eq!(f.count("SELECT COUNT(*) FROM account_browser_access_tokens").await, 1);
        assert_eq!(f.count("SELECT COUNT(*) FROM account_browser_refresh_tokens").await, 1);
        assert_eq!(
            f.count(
                "SELECT COUNT(*) FROM account_browser_refresh_tokens WHERE spent_at_ms IS NOT NULL"
            )
            .await,
            0
        );
        assert_eq!(
            f.count(
                "SELECT COUNT(*) FROM account_browser_families WHERE revoked_at_ms IS NOT NULL"
            )
            .await,
            0
        );
        reset_failure_cooldowns(f).await;
    }
    set_scope(f, family, "account:read").await;
    let rotated = request(f, &browser.key, REFRESH, b"{}", None, Some(&browser.cookie)).await;
    (browser.access, browser.cookie) = session(&rotated, false);
    assert_eq!(
        current_session(f, &browser).await.expect("same valid family").scope,
        "account:read"
    );
}

browser_tests!(
    sqlite_account_browser_retained_scope_ceiling,
    postgres_account_browser_retained_scope_ceiling,
    retained_scope
);
browser_tests!(
    sqlite_account_browser_invalid_scope_ceiling,
    postgres_account_browser_invalid_scope_ceiling,
    invalid_scope
);
