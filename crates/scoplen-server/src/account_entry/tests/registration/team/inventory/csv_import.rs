// SPDX-License-Identifier: AGPL-3.0-only
//! Authenticated HTTP admission and changed-only publication for atomic imports.

use super::*;
use scoplen_api::inventory_import::{
    InventoryImportFields, InventoryImportRequest, InventoryImportResult, InventoryImportRow,
    MAX_INVENTORY_IMPORT_REQUEST_BYTES,
};

#[allow(clippy::too_many_lines)]
async fn authoring(f: &Fixture) {
    let mut owner = actor(f, "csv-import-owner").await;
    let outsider = actor(f, "csv-import-outsider").await;
    let org = create_team(f, &owner).await.id;
    let path = format!("/api/v1/orgs/{org}/inventory/imports");
    let request = InventoryImportRequest {
        rows: (0..2)
            .map(|_| InventoryImportRow {
                host_id: Uuid::now_v7(),
                access_profile_id: Uuid::now_v7(),
                fields: InventoryImportFields {
                    name: "CSV Host".into(),
                    address: "host.example.test".into(),
                    port: 2222,
                    username: "operator".into(),
                    login_name: None,
                },
            })
            .collect(),
    };
    let body = request.to_json().unwrap();
    let key = Uuid::now_v7().to_string();
    let mut events = f.notifications.subscribe(scoplen_sync::http::AuthenticatedDevice {
        account_id: owner.registration.payload.account_id.into_bytes(),
        device_id: owner.registration.payload.device_id.into_bytes(),
    });
    let revision = f.revision(org).await;
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    let imported = call(f, &owner, "POST", &path, &body, &[("Idempotency-Key", &key)]).await;
    assert_eq!(imported.status, 201);
    imported.private();
    assert!(imported.header("etag").is_none());
    assert!(imported.header("location").is_none());
    InventoryImportResult::from_http_json(
        &imported.body,
        imported.header("cache-control"),
        imported.header("pragma"),
        &request,
    )
    .unwrap();
    assert_eq!(f.revision(org).await, revision + 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit + 4);
    tokio::time::timeout(std::time::Duration::from_secs(5),async{
        loop {
            let event=scoplen_api::sync::SyncNotification::from_cbor(&events.recv().await.unwrap()).unwrap();
            if matches!(event,scoplen_api::sync::SyncNotification::OrganizationViewChanged{organization,view_revision,..} if organization==org&&view_revision==revision+1){break;}
        }
    }).await.expect("one committed import notification");
    for row in &request.rows {
        let host = resource(
            &call(f, &owner, "GET", &format!("/api/v1/orgs/{org}/hosts/{}", row.host_id), &[], &[])
                .await,
            InventoryType::Host,
            200,
        );
        let login = resource(
            &call(
                f,
                &owner,
                "GET",
                &format!("/api/v1/orgs/{org}/access-profiles/{}", row.access_profile_id),
                &[],
                &[],
            )
            .await,
            InventoryType::AccessProfile,
            200,
        );
        let (desired_host, desired_login) = row.inventory_creates().unwrap();
        assert_eq!(host.fields, desired_host.fields);
        assert_eq!(login.fields, desired_login.fields);
    }
    let confirmed = call(f, &owner, "POST", &path, &body, &[("Idempotency-Key", &key)]).await;
    assert_eq!(confirmed.status, 201);
    assert_eq!(confirmed.body, imported.body);
    assert_eq!(f.revision(org).await, revision + 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit + 4);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), events.recv()).await.is_err(),
        "confirmation publishes no second hint"
    );
    let mut changed = request.clone();
    changed.rows[0].fields.username = "another".into();
    problem(
        &call(f, &owner, "POST", &path, &changed.to_json().unwrap(), &[("Idempotency-Key", &key)])
            .await,
        409,
        "organization.conflict",
    );
    problem(
        &call(f, &owner, "POST", &path, &body, &[("Idempotency-Key", &Uuid::now_v7().to_string())])
            .await,
        409,
        "organization.conflict",
    );
    problem(
        &call(
            f,
            &outsider,
            "POST",
            &path,
            &body,
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        404,
        "organization.not_found",
    );
    problem(
        &call(
            f,
            &owner,
            "POST",
            &format!("{path}?unexpected=1"),
            &body,
            &[("Idempotency-Key", &key)],
        )
        .await,
        400,
        "organization.invalid_request",
    );
    problem(
        &call(
            f,
            &owner,
            "POST",
            &path,
            &body,
            &[("Idempotency-Key", &key), ("If-Match", "\"unexpected\"")],
        )
        .await,
        400,
        "organization.invalid_request",
    );
    problem(&call(f, &owner, "POST", &path, &body, &[]).await, 400, "organization.invalid_request");
    problem(
        &call(f, &owner, "POST", &path, br#"{"rows":[],"rows":[]}"#, &[("Idempotency-Key", &key)])
            .await,
        400,
        "organization.invalid_request",
    );
    let oversized = vec![b' '; MAX_INVENTORY_IMPORT_REQUEST_BYTES + 1];
    problem(
        &call(f, &owner, "POST", &path, &oversized, &[("Idempotency-Key", &key)]).await,
        413,
        "organization.invalid_request",
    );
    narrow(f, &mut owner, "inventory:read").await;
    problem(
        &call(f, &owner, "POST", &path, &body, &[("Idempotency-Key", &key)]).await,
        403,
        "policy.denied",
    );
    assert_eq!(f.revision(org).await, revision + 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit + 4);
    assert_eq!(call(f, &owner, "GET", &path, &[], &[]).await.status, 405);
    assert_eq!(
        call(f, &owner, "GET", &format!("{path}/{}", Uuid::now_v7()), &[], &[]).await.status,
        404
    );
}

#[tokio::test]
async fn sqlite_public_csv_import_admission_receipts_and_notification() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.unwrap();
    let fixture = Fixture::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
    authoring(&fixture).await;
    fixture.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_public_csv_import_admission_receipts_and_notification() {
    let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
    let fixture = Fixture::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
    authoring(&fixture).await;
    fixture.close().await;
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}
