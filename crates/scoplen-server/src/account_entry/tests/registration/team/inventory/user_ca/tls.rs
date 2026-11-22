// SPDX-License-Identifier: AGPL-3.0-only
//! Real authenticated TLS downloads and optional synthetic artifacts for owned sshd acceptance.

use super::super::super::tls::TlsFixture;
use super::*;
use scoplen_api::krl::UserCaKrl;
use scoplen_api::sync::{
    SyncAckRequest, SyncAckResponse, SyncChangesResponse, SyncVaultKeysResponse, SyncWrite,
    SyncWriteBatch, SyncWriteBatchResponse, VaultKind,
};
use scoplen_crypto::{ObjectEnvelope, PersonalVaultKeyWrap};
use scoplen_model::{FieldEntry, FieldPath, Hlc, cbor};

async fn personal_sync_after_revocation(tls: &TlsFixture, member: &Actor, owner: &Actor) {
    let device = member.registration.payload.device_id;
    let vault = member.registration.payload.personal_vault_id;
    let body =
        SyncSessionRequest { client_version: "0.1.0".into(), model_version: 1, device_id: device }
            .to_cbor()
            .unwrap();
    let reply = tls.request(member, "POST", "/sync/v1/session", &body).await;
    assert_eq!(reply.status, 200);
    reply.private();
    let session = SyncSessionResponse::from_cbor(&reply.body).unwrap();
    assert_eq!(session.vaults.len(), 1);
    assert_eq!(session.vaults[0].id, vault);
    assert_eq!(session.vaults[0].kind, VaultKind::Personal);
    assert_eq!(session.vaults[0].organization, None);
    let reply = tls.get(member, &format!("/sync/v1/vaults/{vault}/keys")).await;
    assert_eq!(reply.status, 200);
    reply.private();
    let keys = SyncVaultKeysResponse::from_cbor(&reply.body).unwrap();
    assert_eq!(keys.keys.len(), 1);
    assert_eq!(keys.keys[0].epoch, 1);
    let key = PersonalVaultKeyWrap::decode(&keys.keys[0].wrapped_vault_key)
        .unwrap()
        .open(member.registration.payload.account_id, vault, 1, &SecretBytes::new([11; 32]))
        .unwrap();
    let mut object = Object::new(Uuid::now_v7(), ObjectType::HOST, 1).unwrap();
    for (field, value) in [(1, "Personal after team revocation"), (2, "personal.example.test")] {
        object
            .insert(
                FieldPath::field(field).unwrap(),
                FieldEntry::new(cbor::Value::Text(value.into()), Hlc::at(1).unwrap(), device)
                    .unwrap(),
            )
            .unwrap();
    }
    let payload =
        ObjectEnvelope::encrypt(vault, 1, &object, &key, device, &member.registration.device)
            .and_then(|envelope| envelope.encode())
            .unwrap();
    let body = SyncWriteBatch {
        writes: vec![SyncWrite {
            object_id: object.id,
            base_seq: None,
            payload: payload.clone(),
            tombstone: false,
        }],
    }
    .to_cbor()
    .unwrap();
    let reply =
        tls.request(member, "POST", &format!("/sync/v1/vaults/{vault}/objects"), &body).await;
    assert_eq!(reply.status, 200);
    reply.private();
    let written = SyncWriteBatchResponse::from_cbor(&reply.body).unwrap();
    assert_eq!(written.assignments.len(), 1);
    assert_eq!(written.assignments[0].object_id, object.id);
    assert_eq!(written.assignments[0].seq, 1);
    let path = format!("/sync/v1/vaults/{vault}/changes?after=0&limit=10");
    sync_problem(&tls.get(owner, &path).await, 404, "sync.object_not_found");
    let reply = tls.get(member, &path).await;
    assert_eq!(reply.status, 200);
    reply.private();
    let changes = SyncChangesResponse::from_cbor(&reply.body).unwrap();
    assert_eq!(changes.changes.len(), 1);
    assert_eq!(changes.next_cursor, 1);
    assert!(!changes.more);
    let retained = &changes.changes[0];
    assert_eq!(retained.object_id, object.id);
    assert_eq!(retained.signer_device_id, Some(device));
    assert_eq!(retained.seq, 1);
    assert_eq!(retained.payload, payload);
    let opened = ObjectEnvelope::decode(&retained.payload)
        .and_then(|envelope| {
            envelope.decrypt(vault, object.id, &key, &member.registration.device.public_key_sec1())
        })
        .unwrap();
    assert_eq!(opened, object);
    let body = SyncAckRequest { cursor: changes.next_cursor }.to_cbor().unwrap();
    let reply = tls.request(member, "POST", &format!("/sync/v1/vaults/{vault}/ack"), &body).await;
    assert_eq!(reply.status, 200);
    reply.private();
    assert_eq!(SyncAckResponse::from_cbor(&reply.body).unwrap().cursor, 1);
}

fn downloaded(reply: &Reply, trust: &UserCaResource) -> UserCaKrl {
    assert_eq!(reply.status, 200, "{}", String::from_utf8_lossy(&reply.body));
    reply.private();
    assert!(reply.header("etag").is_none());
    UserCaKrl::from_http_bytes(
        &reply.body,
        &trust.public_key,
        reply.header("content-type"),
        reply.header("cache-control"),
        reply.header("pragma"),
        reply.header("x-request-id"),
    )
    .unwrap()
}

async fn status(f: &Fixture, owner: &Actor, org: Uuid, membership: Uuid, status: TeamMemberStatus) {
    let path = format!("/api/v1/orgs/{org}/members/{membership}");
    let current =
        TeamMemberResource::from_json(&call(f, owner, "GET", &path, &[], &[]).await.body).unwrap();
    let request = TeamMemberUpdateRequest { roles: current.roles, status }.to_json().unwrap();
    assert_eq!(
        call(f, owner, "PATCH", &path, &request, &[("If-Match", &current.etag)]).await.status,
        200
    );
}

fn export_ssh_artifacts(
    label: &str,
    trust: &UserCaResource,
    other_trust: &UserCaResource,
    empty: &[u8],
    revoked: &[u8],
    certificates: &[(&str, &CertificateIssuanceResponse)],
) {
    let Some(root) = std::env::var_os("SCOPLEN_KRL_ACCEPTANCE_DIRECTORY") else { return };
    let root = PathBuf::from(root);
    std::fs::create_dir_all(&root).unwrap();
    let directory = root.join(label);
    std::fs::create_dir(&directory).expect("acceptance output must be new");
    let subject = ssh_key::PrivateKey::from(Ed25519Keypair::from_seed(&[9; 32]));
    let personal = ssh_key::PrivateKey::from(Ed25519Keypair::from_seed(&[18; 32]));
    std::fs::write(
        directory.join("subject-key"),
        subject.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    std::fs::write(
        directory.join("personal-key"),
        personal.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    std::fs::write(directory.join("personal.pub"), personal.public_key().to_openssh().unwrap())
        .unwrap();
    std::fs::write(
        directory.join("trusted-ca.pub"),
        format!("{}\n{}\n", trust.public_key, other_trust.public_key),
    )
    .unwrap();
    std::fs::write(directory.join("empty.krl"), empty).unwrap();
    std::fs::write(directory.join("revoked.krl"), revoked).unwrap();
    let mut principals = std::collections::BTreeSet::new();
    for (name, resource) in certificates {
        std::fs::write(directory.join(format!("{name}.pub")), &resource.certificate).unwrap();
        principals.extend(
            Certificate::from_openssh(&resource.certificate)
                .unwrap()
                .valid_principals()
                .iter()
                .cloned(),
        );
    }
    std::fs::write(
        directory.join("principals"),
        principals.into_iter().collect::<Vec<_>>().join("\n") + "\n",
    )
    .unwrap();
}

#[allow(clippy::too_many_lines)]
async fn tls_contract(f: &Fixture, label: &str) {
    let owner = actor(f, "krl-tls-owner").await;
    let member = actor(f, "krl-tls-member").await;
    let org = create_team(f, &owner).await.id;
    let membership = enroll_member(f, &owner, &member, org).await;
    let host = create_asset(
        f,
        &owner,
        org,
        InventoryType::Host,
        json!({"name":"TLS certificate host","address":"ssh.example.test"}),
    )
    .await;
    rule(
        f,
        &owner,
        org,
        membership,
        SimpleRule::View {
            resources: vec![SimpleRuleSelector { object_type: ObjectType::HOST, id: host.id }],
        },
    )
    .await;
    rule(
        f,
        &owner,
        org,
        membership,
        SimpleRule::Connect {
            hosts: vec![host.id],
            host_groups: vec![],
            remote_user: "deploy".into(),
        },
    )
    .await;
    let trust = provision(f, &owner, org).await;
    let request = request(CertificateTargets::Hosts(vec![host.id]), 1_800);
    let original_key = Uuid::now_v7();
    let original = issued(&sign(f, &member, org, &request, original_key).await);
    let unaffected = issued(&sign(f, &owner, org, &request, Uuid::now_v7()).await);
    let other_org = create_team(f, &owner).await.id;
    let other_trust = provision(f, &owner, other_org).await;
    let other_host = create_asset(
        f,
        &owner,
        other_org,
        InventoryType::Host,
        json!({"name":"Other team host","address":"other.example.test"}),
    )
    .await;
    let other_request = super::request(CertificateTargets::Hosts(vec![other_host.id]), 1_800);
    let other = issued(&sign(f, &owner, other_org, &other_request, Uuid::now_v7()).await);
    assert_eq!(
        Certificate::from_openssh(&original.certificate).unwrap().serial(),
        Certificate::from_openssh(&other.certificate).unwrap().serial()
    );
    let tls = TlsFixture::start(f).await;
    let path = format!("/api/v1/orgs/{org}/certificate-authorities/{}/krl", trust.id);
    let other_path =
        format!("/api/v1/orgs/{other_org}/certificate-authorities/{}/krl", other_trust.id);
    let other_snapshot = tls.get(&owner, &other_path).await;
    assert_eq!(downloaded(&other_snapshot, &other_trust).revoked_serials(), &[] as &[u64]);
    let empty = tls.get(&owner, &path).await;
    assert_eq!(downloaded(&empty, &trust).revoked_serials(), &[] as &[u64]);
    status(f, &owner, org, membership, TeamMemberStatus::Suspended).await;
    let revoked = tls.get(&owner, &path).await;
    let snapshot = downloaded(&revoked, &trust);
    assert_eq!(snapshot.version(), 2);
    assert_eq!(snapshot.revoked_serials(), [1]);
    assert_eq!(tls.get(&owner, &path).await.body, revoked.body);
    problem(&tls.get(&member, &path).await, 404, "organization.not_found");
    status(f, &owner, org, membership, TeamMemberStatus::Active).await;
    problem(&sign(f, &member, org, &request, original_key).await, 409, "certificate.revoked");
    let fresh = issued(&sign(f, &member, org, &request, Uuid::now_v7()).await);
    assert_eq!(Certificate::from_openssh(&fresh.certificate).unwrap().serial(), 3);
    assert_eq!(tls.get(&member, &path).await.body, revoked.body);
    export_ssh_artifacts(
        label,
        &trust,
        &other_trust,
        &empty.body,
        &revoked.body,
        &[
            ("old-cert", &original),
            ("fresh-cert", &fresh),
            ("other-member-cert", &unaffected),
            ("other-team-cert", &other),
        ],
    );
    let member_path = format!("/api/v1/orgs/{org}/members/{membership}");
    let current =
        TeamMemberResource::from_json(&call(f, &owner, "GET", &member_path, &[], &[]).await.body)
            .unwrap();
    let mutation =
        TeamMemberUpdateRequest { roles: current.roles, status: TeamMemberStatus::Suspended }
            .to_json()
            .unwrap();
    let headers = [("If-Match", current.etag.as_str())];
    let (racing, suspended) = tokio::join!(
        sign(f, &member, org, &request, Uuid::now_v7()),
        call(f, &owner, "PATCH", &member_path, &mutation, &headers),
    );
    assert_eq!(suspended.status, 200);
    let complete = tls.get(&owner, &path).await;
    let snapshot = downloaded(&complete, &trust);
    if racing.status == 201 {
        let issued = Certificate::from_openssh(&issued(&racing).certificate).unwrap();
        assert_eq!(snapshot.revoked_serials(), [1, 3, issued.serial()]);
    } else {
        problem(&racing, 404, "organization.not_found");
        assert_eq!(snapshot.revoked_serials(), [1, 3]);
    }
    personal_sync_after_revocation(&tls, &member, &owner).await;
    assert_eq!(tls.get(&owner, &path).await.body, complete.body);
    assert_eq!(tls.get(&owner, &other_path).await.body, other_snapshot.body);
    problem(&tls.get(&member, &other_path).await, 404, "organization.not_found");
}

#[tokio::test]
async fn sqlite_user_ca_krl_download_over_verified_tls() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.unwrap();
    let fixture = Fixture::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
    tls_contract(&fixture, "sqlite").await;
    fixture.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_user_ca_krl_download_over_verified_tls() {
    let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
    let fixture = Fixture::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
    tls_contract(&fixture, "postgres").await;
    fixture.close().await;
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}
