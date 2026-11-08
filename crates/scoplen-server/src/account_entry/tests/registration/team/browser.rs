// SPDX-License-Identifier: AGPL-3.0-only
//! Public Account-browser authentication against genuinely registered password Accounts.

use scoplen_api::account_browser::{
    AccountBrowserAccessToken, AccountBrowserLogoutResponse, AccountBrowserPasswordLoginRequest,
    AccountBrowserPasswordLoginResponse, AccountBrowserPasswordOptionsRequest,
    AccountBrowserPasswordOptionsResponse, AccountBrowserRefreshResponse,
};

use super::*;

const OPTIONS: &str = "/api/v1/auth/accounts/browser/password/options";
const LOGIN: &str = "/api/v1/auth/accounts/browser/password/login";
const REFRESH: &str = "/api/v1/auth/accounts/browser/refresh";
const LOGOUT: &str = "/api/v1/auth/accounts/browser/logout";
const NATIVE_OPTIONS: &str = "/api/v1/auth/accounts/password/options";
const NATIVE_LOGIN: &str = "/api/v1/auth/accounts/password/login";

struct Browser {
    key: P256SigningKey,
    access: String,
    cookie: String,
}

fn proof(key: &P256SigningKey, path: &str, access: Option<&str>) -> String {
    DpopProof::sign(
        key,
        &key.public_key_sec1(),
        &DpopTarget::new("POST", ORIGIN, path).expect("browser target"),
        access.map_or(DpopToken::Refresh, DpopToken::Protected),
        u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).expect("clock"),
        None,
    )
    .expect("fresh browser proof")
    .as_str()
    .to_owned()
}

async fn request(
    f: &Fixture,
    key: &P256SigningKey,
    path: &str,
    body: &[u8],
    access: Option<&str>,
    cookie: Option<&str>,
) -> Reply {
    let proof = proof(key, path, access);
    let authorization = access.map(|value| format!("DPoP {value}"));
    let mut headers =
        vec![("Content-Type", "application/json"), ("Origin", ORIGIN), ("DPoP", proof.as_str())];
    if let Some(value) = &authorization {
        headers.push(("Authorization", value));
    }
    if let Some(value) = cookie {
        headers.push(("Cookie", value));
    }
    http(f.address, "POST", path, body, &headers).await
}

async fn register(f: &Fixture, username: &str) -> Registration {
    let registration = Registration::with_username(username);
    let signed = registration.request(f.address, AccountRequestIntent::Submit).await;
    let reply =
        http(f.address, "POST", REGISTER, &signed.to_json().expect("registration"), JSON).await;
    committed(&reply, &signed, 201);
    registration
}

async fn options(
    f: &Fixture,
    key: &P256SigningKey,
    username: &str,
) -> AccountPasswordOptionsResponse {
    let body = AccountBrowserPasswordOptionsRequest(AccountPasswordOptionsRequest {
        username: username.into(),
    })
    .to_json()
    .expect("browser options body");
    let reply = request(f, key, OPTIONS, &body, None, None).await;
    assert_eq!(reply.status, 200);
    reply.private();
    AccountBrowserPasswordOptionsResponse::from_json(&reply.body).expect("browser options").0
}

fn login_body(options: AccountPasswordOptionsResponse, secret: SecretBytes<32>) -> SecretVec {
    AccountBrowserPasswordLoginRequest(AccountPasswordLoginRequest {
        attempt_id: options.attempt_id,
        auth_secret: secret,
    })
    .to_json()
    .expect("browser login body")
}

fn session(reply: &Reply, initial: bool) -> (String, String) {
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.header("pragma"), Some("no-cache"));
    assert_eq!(reply.header("content-type"), Some("application/json"));
    assert!(reply.header("access-control-allow-origin").is_none());
    assert!(reply.header("access-control-allow-credentials").is_none());
    let value = if initial {
        AccountBrowserPasswordLoginResponse::from_json(&reply.body).expect("initial session").0
    } else {
        AccountBrowserRefreshResponse::from_json(&reply.body).expect("rotated session").0
    };
    let json: serde_json::Value = serde_json::from_slice(&reply.body).expect("session JSON");
    assert_eq!(json.as_object().expect("four-field response").len(), 4);
    assert_eq!(value.token_type, "DPoP");
    assert_eq!(value.expires_in, 600);
    assert!((1..=2_592_000).contains(&value.refresh_expires_in));
    if initial {
        assert_eq!(value.refresh_expires_in, 2_592_000);
    }
    let cookie = reply.header("set-cookie").expect("HTTP-only refresh credential");
    assert!(cookie.starts_with("__Secure-spl-account-refresh=ar1_"));
    assert!(cookie.contains("; Path=/api/v1/auth/accounts/browser/refresh;"));
    for attribute in ["HttpOnly", "Secure", "SameSite=Strict"] {
        assert!(cookie.split("; ").any(|value| value == attribute));
    }
    assert!(!cookie.contains("Domain="));
    assert!(cookie.ends_with(&format!("Max-Age={}", value.refresh_expires_in)));
    AccountBrowserAccessToken::parse(&value.access_token).expect("opaque access profile");
    (value.access_token, cookie.split(';').next().expect("cookie pair").into())
}

async fn login(f: &Fixture, account: &Registration) -> Browser {
    let key = scoplen_crypto::generate_p256_signing_key().expect("independent browser key");
    let options = options(f, &key, &account.payload.username).await;
    assert_eq!(options.salt, account.payload.password_salt);
    let body = login_body(options, account.auth_secret.clone());
    let reply = request(f, &key, LOGIN, body.as_bytes(), None, None).await;
    let (access, cookie) = session(&reply, true);
    Browser { key, access, cookie }
}

async fn current(f: &Fixture, browser: &Browser) -> bool {
    let token = AccountBrowserAccessToken::parse(&browser.access).expect("original access token");
    match &f.backend {
        AuthBackend::Sqlite(store) => store.current_account_browser_session(&token, ORIGIN).await,
        AuthBackend::Postgres(store) => store.current_account_browser_session(&token, ORIGIN).await,
    }
    .expect("current browser lookup")
    .is_some()
}

async fn reset_failure_cooldowns(f: &Fixture) {
    // These negative cases are independent. Keep all attempt and quota debt while releasing
    // only the owned fixture's backoff; dedicated admission tests exercise the actual delay.
    f.execute("UPDATE account_entry_admission SET failure_streak=0,last_failure_ms=NULL,cooldown_until_ms=NULL").await;
}

fn changed_problem(reply: &Reply, status: u16, code: &str, retryable: bool) {
    assert_eq!(reply.status, status);
    reply.private();
    let value: serde_json::Value = serde_json::from_slice(&reply.body).expect("fixed problem");
    assert_eq!(value["code"], code);
    assert_eq!(value["changed"], true);
    assert_eq!(value["retryable"], retryable);
}

// Keep raw credentials out of assertion failure diagnostics.
#[allow(clippy::manual_assert_eq)]
async fn lifecycle(f: &Fixture) {
    let account = register(f, "browser-lifecycle").await;
    let first = login(f, &account).await;
    let second = login(f, &account).await;
    assert!(current(f, &first).await && current(f, &second).await);
    assert!(first.access != second.access);
    assert!(first.cookie != second.cookie);
    for table in ["identity_accounts", "identity_devices", "account_operation_receipts"] {
        assert_eq!(f.count(&format!("SELECT COUNT(*) FROM {table}")).await, 1);
    }
    assert_eq!(f.count("SELECT COUNT(*) FROM account_browser_families").await, 2);
    assert_eq!(f.count("SELECT COUNT(*) FROM account_admission_capabilities").await, 0);

    // A wrong browser key cannot rotate, revoke, or consume the original refresh credential.
    request(f, &second.key, REFRESH, b"{}", None, Some(&first.cookie)).await.problem(
        400,
        "auth.invalid_dpop_proof",
        false,
    );
    assert!(current(f, &first).await && current(f, &second).await);
    assert_eq!(
        f.count(
            "SELECT COUNT(*) FROM account_browser_refresh_tokens WHERE spent_at_ms IS NOT NULL"
        )
        .await,
        0
    );
    reset_failure_cooldowns(f).await;
    let rotated = request(f, &first.key, REFRESH, b"{}", None, Some(&first.cookie)).await;
    let (access, cookie) = session(&rotated, false);
    assert!(access != first.access);
    assert!(cookie != first.cookie);
    let rotated = Browser { key: first.key, access, cookie };
    let reused = request(f, &rotated.key, REFRESH, b"{}", None, Some(&first.cookie)).await;
    changed_problem(&reused, 401, "auth.authentication_required", false);
    assert!(!current(f, &rotated).await);
    assert!(current(f, &second).await, "reuse affects only the matching family");

    // A retained, otherwise-current access digest can confirm an already terminal family.
    let logout = request(f, &rotated.key, LOGOUT, b"{}", Some(&rotated.access), None).await;
    assert_eq!(logout.status, 200);
    logout.private();
    AccountBrowserLogoutResponse::from_json(&logout.body).expect("terminal confirmation");
    let audit = f.count("SELECT COUNT(*) FROM deployment_audit_events").await;
    let confirmed =
        request(f, &rotated.key, LOGOUT, b"{}", Some(&rotated.access), Some("malformed-cookie"))
            .await;
    assert_eq!(confirmed.body, logout.body);
    assert_eq!(confirmed.status, 200, "logout ignores all cookies");
    assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, audit);

    let logout = request(f, &second.key, LOGOUT, b"{}", Some(&second.access), None).await;
    assert_eq!(logout.status, 200);
    assert!(!current(f, &second).await);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM account_browser_access_tokens").await,
        3,
        "logout retains digests through original access expiry"
    );
    reset_failure_cooldowns(f).await;
    request(f, &second.key, REFRESH, b"{}", None, Some(&second.cookie)).await.problem(
        401,
        "auth.authentication_required",
        false,
    );
    let third = login(f, &account).await;
    assert!(current(f, &third).await);
}

async fn attempt_isolation(f: &Fixture) {
    let account = register(f, "browser-attempts").await;
    let key = scoplen_crypto::generate_p256_signing_key().expect("original browser");
    let other = scoplen_crypto::generate_p256_signing_key().expect("other browser");
    let browser_options = options(f, &key, &account.payload.username).await;
    let body = login_body(browser_options, account.auth_secret.clone());
    request(f, &other, LOGIN, body.as_bytes(), None, None).await.problem(
        400,
        "auth.invalid_dpop_proof",
        false,
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM account_password_attempts WHERE purpose=1").await, 1);
    reset_failure_cooldowns(f).await;
    http(f.address, "POST", NATIVE_LOGIN, body.as_bytes(), JSON).await.problem(
        401,
        "auth.authentication_required",
        false,
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM account_password_attempts WHERE purpose=1").await, 1);
    reset_failure_cooldowns(f).await;
    let reply = request(f, &key, LOGIN, body.as_bytes(), None, None).await;
    session(&reply, true);
    request(f, &key, LOGIN, body.as_bytes(), None, None).await.problem(
        401,
        "auth.authentication_required",
        false,
    );
    reset_failure_cooldowns(f).await;

    let native_body = AccountPasswordOptionsRequest { username: account.payload.username.clone() }
        .to_json()
        .expect("native options");
    let native = http(f.address, "POST", NATIVE_OPTIONS, &native_body, JSON).await;
    assert_eq!(native.status, 200);
    let native = AccountPasswordOptionsResponse::from_json(&native.body).expect("native response");
    let native_login = login_body(native, account.auth_secret.clone());
    request(f, &key, LOGIN, native_login.as_bytes(), None, None).await.problem(
        401,
        "auth.authentication_required",
        false,
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM account_password_attempts WHERE purpose=0").await, 1);
    reset_failure_cooldowns(f).await;
    let native = http(f.address, "POST", NATIVE_LOGIN, native_login.as_bytes(), JSON).await;
    assert_eq!(native.status, 200);
    native.private();
    AccountPasswordLoginResponse::from_json(&native.body).expect("native bootstrap stays native");

    for username in [account.payload.username.as_str(), "unknown-browser-account"] {
        let options = options(f, &key, username).await;
        let wrong = login_body(options, SecretBytes::new([0; 32]));
        request(f, &key, LOGIN, wrong.as_bytes(), None, None).await.problem(
            401,
            "auth.authentication_required",
            false,
        );
        reset_failure_cooldowns(f).await;
    }
    assert_eq!(
        f.count("SELECT COUNT(*) FROM account_password_attempts").await,
        0,
        "accepted credential denials consume both real and synthetic attempts"
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM account_browser_families").await, 1);
}

async fn metadata_and_authority(f: &Fixture) {
    let account = register(f, "browser-metadata").await;
    let browser = login(f, &account).await;
    let options_body = AccountPasswordOptionsRequest { username: account.payload.username.clone() }
        .to_json()
        .expect("options");
    let options_proof = proof(&browser.key, OPTIONS, None);
    for headers in [
        vec![("Content-Type", "application/json"), ("DPoP", options_proof.as_str())],
        vec![
            ("Content-Type", "application/json"),
            ("Origin", "https://other.example"),
            ("DPoP", options_proof.as_str()),
        ],
    ] {
        http(f.address, "POST", OPTIONS, &options_body, &headers).await.problem(
            403,
            "policy.denied",
            false,
        );
    }
    let refresh_proof = proof(&browser.key, REFRESH, None);
    for cookie in [
        format!("{}; {}", browser.cookie, browser.cookie),
        format!("{}; __Secure-spl-refresh=other", browser.cookie),
        format!("{}; refresh_token=other", browser.cookie),
    ] {
        http(
            f.address,
            "POST",
            REFRESH,
            b"{}",
            &[
                ("Content-Type", "application/json"),
                ("Origin", ORIGIN),
                ("DPoP", refresh_proof.as_str()),
                ("Cookie", &cookie),
            ],
        )
        .await
        .problem(400, "auth.invalid_request", false);
    }
    request(
        f,
        &browser.key,
        REFRESH,
        b"{\"refresh_token\":\"other\"}",
        None,
        Some(&browser.cookie),
    )
    .await
    .problem(400, "auth.invalid_request", false);
    request(f, &browser.key, LOGOUT, b"{}", None, Some(&browser.cookie)).await.problem(
        400,
        "auth.invalid_request",
        false,
    );
    request(f, &browser.key, REFRESH, b"{}", Some(&browser.access), Some(&browser.cookie))
        .await
        .problem(400, "auth.invalid_request", false);
    assert!(current(f, &browser).await);
    // A retained family must match the Account's current immutable credential generation.
    f.execute("UPDATE account_browser_families SET credential_generation=credential_generation+1")
        .await;
    assert!(!current(f, &browser).await);
    request(f, &browser.key, REFRESH, b"{}", None, Some(&browser.cookie)).await.problem(
        401,
        "auth.authentication_required",
        false,
    );
    request(f, &browser.key, LOGOUT, b"{}", Some(&browser.access), None).await.problem(
        401,
        "auth.authentication_required",
        false,
    );
}

async fn audit_failure(f: &Fixture, enabled: bool) {
    let sql = match (&f.backend, enabled) {
        (AuthBackend::Sqlite(_), true) => {
            "CREATE TRIGGER browser_audit_failure BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'owned fixture failure'); END;"
        }
        (AuthBackend::Sqlite(_), false) => "DROP TRIGGER browser_audit_failure;",
        (AuthBackend::Postgres(_), true) => {
            "CREATE FUNCTION browser_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned fixture failure'; END $$; CREATE TRIGGER browser_audit_failure BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION browser_audit_failure();"
        }
        (AuthBackend::Postgres(_), false) => {
            "DROP TRIGGER browser_audit_failure ON deployment_audit_events; DROP FUNCTION browser_audit_failure();"
        }
    };
    f.execute(sql).await;
}

async fn commit_failure(f: &Fixture, enabled: bool) {
    if enabled {
        f.execute("CREATE TABLE IF NOT EXISTS browser_commit_parent (id INTEGER PRIMARY KEY); CREATE TABLE IF NOT EXISTS browser_commit_child (id INTEGER REFERENCES browser_commit_parent(id) DEFERRABLE INITIALLY DEFERRED);").await;
    }
    let sql = match (&f.backend, enabled) {
        (AuthBackend::Sqlite(_), true) => {
            "CREATE TRIGGER browser_commit_failure AFTER INSERT ON account_browser_access_tokens BEGIN INSERT INTO browser_commit_child VALUES(1); END;"
        }
        (AuthBackend::Sqlite(_), false) => "DROP TRIGGER browser_commit_failure;",
        (AuthBackend::Postgres(_), true) => {
            "CREATE FUNCTION browser_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO browser_commit_child VALUES(1); RETURN NEW; END $$; CREATE TRIGGER browser_commit_failure AFTER INSERT ON account_browser_access_tokens FOR EACH ROW EXECUTE FUNCTION browser_commit_failure();"
        }
        (AuthBackend::Postgres(_), false) => {
            "DROP TRIGGER browser_commit_failure ON account_browser_access_tokens; DROP FUNCTION browser_commit_failure();"
        }
    };
    f.execute(sql).await;
}

async fn logout_commit_failure(f: &Fixture, enabled: bool) {
    let sql = match (&f.backend, enabled) {
        (AuthBackend::Sqlite(_), true) => {
            "CREATE TRIGGER browser_logout_commit_failure AFTER UPDATE OF revoked_at_ms ON account_browser_families WHEN OLD.revoked_at_ms IS NULL AND NEW.revoked_at_ms IS NOT NULL BEGIN INSERT INTO browser_commit_child VALUES(1); END;"
        }
        (AuthBackend::Sqlite(_), false) => "DROP TRIGGER browser_logout_commit_failure;",
        (AuthBackend::Postgres(_), true) => {
            "CREATE FUNCTION browser_logout_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.revoked_at_ms IS NULL AND NEW.revoked_at_ms IS NOT NULL THEN INSERT INTO browser_commit_child VALUES(1); END IF; RETURN NEW; END $$; CREATE TRIGGER browser_logout_commit_failure AFTER UPDATE OF revoked_at_ms ON account_browser_families FOR EACH ROW EXECUTE FUNCTION browser_logout_commit_failure();"
        }
        (AuthBackend::Postgres(_), false) => {
            "DROP TRIGGER browser_logout_commit_failure ON account_browser_families; DROP FUNCTION browser_logout_commit_failure();"
        }
    };
    f.execute(sql).await;
}

async fn non_disclosure(f: &Fixture) {
    let account = register(f, "browser-failures").await;
    let key = scoplen_crypto::generate_p256_signing_key().expect("browser key");
    let options = options(f, &key, &account.payload.username).await;
    let body = login_body(options, account.auth_secret.clone());
    audit_failure(f, true).await;
    request(f, &key, LOGIN, body.as_bytes(), None, None).await.problem(
        503,
        "auth.storage_unavailable",
        true,
    );
    audit_failure(f, false).await;
    assert_eq!(f.count("SELECT COUNT(*) FROM account_browser_families").await, 0);
    assert_eq!(f.count("SELECT COUNT(*) FROM account_password_attempts").await, 1);

    commit_failure(f, true).await;
    let reply = request(f, &key, LOGIN, body.as_bytes(), None, None).await;
    changed_problem(&reply, 503, "auth.commit_outcome_unknown", false);
    assert!(!String::from_utf8_lossy(&reply.body).contains("ab1_"));
    assert!(!String::from_utf8_lossy(&reply.body).contains("ar1_"));
    commit_failure(f, false).await;
    assert_eq!(f.count("SELECT COUNT(*) FROM account_browser_families").await, 0);
    let reply = request(f, &key, LOGIN, body.as_bytes(), None, None).await;
    let (access, cookie) = session(&reply, true);
    let browser = Browser { key, access, cookie };

    audit_failure(f, true).await;
    request(f, &browser.key, REFRESH, b"{}", None, Some(&browser.cookie)).await.problem(
        503,
        "auth.storage_unavailable",
        true,
    );
    request(f, &browser.key, LOGOUT, b"{}", Some(&browser.access), None).await.problem(
        503,
        "auth.storage_unavailable",
        true,
    );
    audit_failure(f, false).await;
    assert!(current(f, &browser).await);
    assert_eq!(
        f.count(
            "SELECT COUNT(*) FROM account_browser_refresh_tokens WHERE spent_at_ms IS NOT NULL"
        )
        .await,
        0
    );
    commit_failure(f, true).await;
    changed_problem(
        &request(f, &browser.key, REFRESH, b"{}", None, Some(&browser.cookie)).await,
        503,
        "auth.commit_outcome_unknown",
        false,
    );
    commit_failure(f, false).await;
    assert!(current(f, &browser).await);
    assert_eq!(
        f.count(
            "SELECT COUNT(*) FROM account_browser_refresh_tokens WHERE spent_at_ms IS NOT NULL"
        )
        .await,
        0
    );
    let reply = request(f, &browser.key, REFRESH, b"{}", None, Some(&browser.cookie)).await;
    let (access, cookie) = session(&reply, false);
    let browser = Browser { key: browser.key, access, cookie };
    logout_commit_failure(f, true).await;
    changed_problem(
        &request(f, &browser.key, LOGOUT, b"{}", Some(&browser.access), None).await,
        503,
        "auth.commit_outcome_unknown",
        true,
    );
    logout_commit_failure(f, false).await;
    assert!(current(f, &browser).await);
    let logout = request(f, &browser.key, LOGOUT, b"{}", Some(&browser.access), None).await;
    assert_eq!(logout.status, 200);
    AccountBrowserLogoutResponse::from_json(&logout.body).expect("explicit original logout retry");
}

async fn expiry(f: &Fixture) {
    let account = register(f, "browser-expiry").await;
    let key = scoplen_crypto::generate_p256_signing_key().expect("browser key");
    let options = options(f, &key, &account.payload.username).await;
    let body = login_body(options, account.auth_secret.clone());
    f.execute("UPDATE account_password_attempts SET issued_at_ms=issued_at_ms-120000,expires_at_ms=expires_at_ms-120000").await;
    request(f, &key, LOGIN, body.as_bytes(), None, None).await.problem(
        401,
        "auth.authentication_required",
        false,
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM account_password_attempts").await, 0);
    reset_failure_cooldowns(f).await;
    let browser = login(f, &account).await;
    f.execute("UPDATE account_browser_access_tokens SET issued_at_ms=issued_at_ms-600000,expires_at_ms=expires_at_ms-600000").await;
    assert!(!current(f, &browser).await);
    request(f, &browser.key, LOGOUT, b"{}", Some(&browser.access), None).await.problem(
        401,
        "auth.authentication_required",
        false,
    );
    let reply = request(f, &browser.key, REFRESH, b"{}", None, Some(&browser.cookie)).await;
    let (access, cookie) = session(&reply, false);
    let browser = Browser { key: browser.key, access, cookie };
    assert!(current(f, &browser).await);
    f.execute("UPDATE account_browser_families SET created_at_ms=created_at_ms-2592000000,expires_at_ms=expires_at_ms-2592000000").await;
    assert!(!current(f, &browser).await);
    request(f, &browser.key, REFRESH, b"{}", None, Some(&browser.cookie)).await.problem(
        401,
        "auth.authentication_required",
        false,
    );
    reset_failure_cooldowns(f).await;
    request(f, &browser.key, LOGOUT, b"{}", Some(&browser.access), None).await.problem(
        401,
        "auth.authentication_required",
        false,
    );
}

async fn shared_password_admission(f: &Fixture) {
    let account = register(f, "browser-shared-admission").await;
    // Keep this admission-only fixture inside one fixed window regardless of wall-clock boundaries.
    let now = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let fixed = (now / 60000 + 3) * 60000;
    f.execute(&format!(
        "UPDATE account_entry_state SET time_high_water_ms={fixed} WHERE singleton=1"
    ))
    .await;
    let key = scoplen_crypto::generate_p256_signing_key().unwrap();
    let body = AccountPasswordOptionsRequest { username: account.payload.username.clone() }
        .to_json()
        .unwrap();
    assert_eq!(http(f.address, "POST", NATIVE_OPTIONS, &body, JSON).await.status, 200);
    options(f, &key, &account.payload.username).await;
    assert_eq!(f.count("SELECT COUNT(*) FROM account_entry_admission WHERE endpoint=3 AND kind=1 AND attempts=2").await,1);
    assert_eq!(f.count("SELECT COUNT(*) FROM account_entry_admission WHERE endpoint=3 AND kind=2 AND attempts=2").await,1);
    assert_eq!(f.count("SELECT COUNT(*) FROM account_password_attempts WHERE purpose=0").await, 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM account_password_attempts WHERE purpose=1").await, 1);
    f.execute("UPDATE account_entry_admission SET attempts=10 WHERE endpoint=3 AND kind=2").await;
    http(f.address, "POST", NATIVE_OPTIONS, &body, JSON).await.problem(
        429,
        "auth.rate_limited",
        true,
    );
    let limited = request(f, &key, OPTIONS, &body, None, None).await;
    limited.problem(429, "auth.rate_limited", true);
    let wait = limited
        .header("retry-after")
        .expect("retry delay")
        .parse::<u16>()
        .expect("numeric retry delay");
    let headers = scoplen_api::auth::AuthRateLimitHeaders::new(wait).expect("bounded rate headers");
    assert_eq!(limited.header("ratelimit-policy"), Some(headers.rate_limit_policy()));
    assert_eq!(limited.header("ratelimit"), Some(headers.rate_limit().as_str()));
    assert_eq!(f.count("SELECT COUNT(*) FROM account_password_attempts").await, 2);
    f.execute("UPDATE account_entry_admission SET attempts=0 WHERE endpoint=3 AND kind=2; UPDATE account_entry_admission SET attempts=30 WHERE endpoint=3 AND kind=1;").await;
    http(f.address, "POST", NATIVE_OPTIONS, &body, JSON).await.problem(
        429,
        "auth.rate_limited",
        true,
    );
    request(f, &key, OPTIONS, &body, None, None).await.problem(429, "auth.rate_limited", true);
    assert_eq!(f.count("SELECT COUNT(*) FROM account_password_attempts").await, 2);
}

macro_rules! browser_tests {
    ($sqlite:ident,$postgres:ident,$scenario:ident) => {
        #[tokio::test]
        async fn $sqlite() {
            let directory = directory();
            let store =
                SqliteStore::open(&directory.join("store.sqlite")).await.expect("owned SQLite");
            let fixture = Fixture::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
            $scenario(&fixture).await;
            fixture.close().await;
        }

        #[cfg(feature = "postgres-integration")]
        #[tokio::test]
        async fn $postgres() {
            let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
            let fixture = Fixture::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
            $scenario(&fixture).await;
            fixture.close().await;
            crate::account_entry::tests::postgres_cleanup(admin, schema).await;
        }
    };
}

browser_tests!(sqlite_account_browser_lifecycle, postgres_account_browser_lifecycle, lifecycle);
browser_tests!(
    sqlite_account_browser_attempt_isolation,
    postgres_account_browser_attempt_isolation,
    attempt_isolation
);
browser_tests!(
    sqlite_account_browser_metadata_and_current_credentials,
    postgres_account_browser_metadata_and_current_credentials,
    metadata_and_authority
);
browser_tests!(
    sqlite_account_browser_failed_transactions_disclose_no_authority,
    postgres_account_browser_failed_transactions_disclose_no_authority,
    non_disclosure
);
browser_tests!(
    sqlite_account_browser_attempt_access_and_absolute_family_expiry,
    postgres_account_browser_attempt_access_and_absolute_family_expiry,
    expiry
);
browser_tests!(
    sqlite_native_and_browser_password_options_share_admission,
    postgres_native_and_browser_password_options_share_admission,
    shared_password_admission
);

#[cfg(feature = "postgres-integration")]
async fn lost_commit(operation: &str, skip: usize) {
    use std::sync::atomic::Ordering;
    let (store, admin, schema, database) = crate::account_entry::tests::postgres_fixture().await;
    let proxy =
        crate::test_lost_commit::LostCommitProxy::start_skipping(database.as_str(), skip).await;
    let proxied = scoplen_store::PostgresStore::connect(&proxy.database_url)
        .await
        .expect("proxied owned store");
    let f = Fixture::start(AuthBackend::Postgres(Arc::new(proxied)), directory()).await;
    let account = register(&f, "browser-lost-commit").await;
    if operation == LOGIN {
        let key = scoplen_crypto::generate_p256_signing_key().unwrap();
        let options = options(&f, &key, &account.payload.username).await;
        let body = login_body(options, account.auth_secret.clone());
        proxy.armed.store(true, Ordering::SeqCst);
        let reply = request(&f, &key, LOGIN, body.as_bytes(), None, None).await;
        changed_problem(&reply, 503, "auth.commit_outcome_unknown", false);
        assert_eq!(
            f.count("SELECT COUNT(*) FROM account_browser_families").await,
            1,
            "the transaction committed, but the response grants no usable authority"
        );
        assert_eq!(f.count("SELECT COUNT(*) FROM account_password_attempts").await, 0);
    } else {
        let browser = login(&f, &account).await;
        proxy.armed.store(true, Ordering::SeqCst);
        let reply = if operation == REFRESH {
            request(&f, &browser.key, REFRESH, b"{}", None, Some(&browser.cookie)).await
        } else {
            request(&f, &browser.key, LOGOUT, b"{}", Some(&browser.access), None).await
        };
        changed_problem(&reply, 503, "auth.commit_outcome_unknown", operation == LOGOUT);
        if operation == REFRESH {
            assert_eq!(f.count("SELECT COUNT(*) FROM account_browser_refresh_tokens").await, 2);
            assert_eq!(f.count("SELECT COUNT(*) FROM account_browser_refresh_tokens WHERE spent_at_ms IS NOT NULL").await,1);
            assert!(current(&f, &browser).await);
            let reused =
                request(&f, &browser.key, REFRESH, b"{}", None, Some(&browser.cookie)).await;
            changed_problem(&reused, 401, "auth.authentication_required", false);
            assert!(!current(&f, &browser).await);
        } else {
            assert!(!current(&f, &browser).await);
            let audit = f.count("SELECT COUNT(*) FROM deployment_audit_events").await;
            let confirmed =
                request(&f, &browser.key, LOGOUT, b"{}", Some(&browser.access), None).await;
            assert_eq!(confirmed.status, 200);
            AccountBrowserLogoutResponse::from_json(&confirmed.body)
                .expect("explicit terminal confirmation");
            assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, audit);
        }
    }
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    f.close().await;
    store.pool().close().await;
    drop(proxy);
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_account_browser_login_lost_commit_discloses_no_credentials_or_cookie() {
    lost_commit(LOGIN, 2).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_account_browser_refresh_lost_commit_never_replays_the_spent_cookie() {
    lost_commit(REFRESH, 2).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_account_browser_logout_lost_commit_requires_explicit_terminal_confirmation() {
    lost_commit(LOGOUT, 3).await;
}

mod business;
