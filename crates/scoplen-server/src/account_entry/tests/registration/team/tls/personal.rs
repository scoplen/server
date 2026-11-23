// SPDX-License-Identifier: AGPL-3.0-only
//! Personal sync remains independent of the team membership under test.

use super::super::inventory::sync_problem;
use super::*;
use scoplen_api::sync::{
    SyncAckRequest, SyncAckResponse, SyncChangesResponse, SyncSessionRequest, SyncSessionResponse,
    SyncVaultKeysResponse, SyncWrite, SyncWriteBatch, SyncWriteBatchResponse, VaultKind,
};
use scoplen_crypto::{ObjectEnvelope, PersonalVaultKeyWrap};
use scoplen_model::{FieldEntry, FieldPath, Hlc, Object, ObjectType, cbor};

pub(in super::super) async fn personal_sync_after_revocation(
    tls: &TlsFixture,
    member: &Actor,
    owner: &Actor,
    remaining_teams: &[Uuid],
) {
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
    assert_eq!(session.vaults.len(), 1 + remaining_teams.len());
    let personal = session.vaults.iter().find(|descriptor| descriptor.id == vault).unwrap();
    assert_eq!(personal.kind, VaultKind::Personal);
    assert_eq!(personal.organization, None);
    let organizations: Vec<_> = session
        .vaults
        .iter()
        .filter_map(|descriptor| descriptor.organization.map(|context| context.organization))
        .collect();
    assert_eq!(organizations, remaining_teams);
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
