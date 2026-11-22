// SPDX-License-Identifier: AGPL-3.0-only
//! Synthetic shared-password Credentials through the production Personal HTTPS routes.

use super::{
    AuthTokenResponse, Device, FieldEntry, FieldPath, Hlc, Https, Object, ObjectEnvelope,
    ObjectType, PersonalConsumer, ProblemDetails, Result, SecretBytes, SecretVec,
    SyncSnapshotResponse, URL_SAFE_NO_PAD, Uuid, admitted_vault_key, cbor, random_key,
    upload_object,
};
use base64::Engine as _;

fn password() -> Result<SecretVec> {
    Ok(SecretVec::new(
        URL_SAFE_NO_PAD
            .encode(random_key().map_err(|_| "Credential password generation failed")?.as_bytes())
            .into_bytes(),
    ))
}

fn credential(device: Uuid, secret: &SecretVec) -> Result<Object> {
    let mut object = Object::new(Uuid::now_v7(), ObjectType::CREDENTIAL, 1)
        .map_err(|_| "Credential object invalid")?;
    for (field, value) in [
        (1, cbor::Value::Text("Disposable HTTPS password".into())),
        (2, cbor::Value::UInt(1)),
        (3, cbor::Value::UInt(1)),
        (4, cbor::Value::Bytes(secret.as_bytes().to_vec())),
    ] {
        object
            .insert(
                FieldPath::field(field).map_err(|_| "Credential field path invalid")?,
                FieldEntry::new(value, Hlc::at(1).map_err(|_| "Credential clock invalid")?, device)
                    .map_err(|_| "Credential field invalid")?,
            )
            .map_err(|_| "Credential field insertion failed")?;
    }
    object.validate().map_err(|_| "Credential schema invalid")?;
    Ok(object)
}

async fn download(
    https: &Https,
    consumer: &PersonalConsumer,
    reader: (&Device, &AuthTokenResponse),
    key: &SecretBytes<32>,
    writer: &Device,
    expected: &Object,
    sequence: u64,
) -> Result<()> {
    let vault = consumer.account.payload.personal_vault_id;
    let bytes = https
        .exchange(
            "GET",
            &format!("/sync/v1/vaults/{vault}/snapshot?after=0&limit=10"),
            &[],
            Some((&reader.0.keys.signing, Some(&reader.1.access_token))),
            200,
        )
        .await?;
    let snapshot = SyncSnapshotResponse::from_cbor(&bytes)
        .map_err(|_| "Credential snapshot response invalid")?;
    if snapshot.objects.len() != 2 || snapshot.next_cursor != sequence || snapshot.more {
        return Err("Credential snapshot completeness invalid");
    }
    let host = snapshot
        .objects
        .iter()
        .find(|object| object.object_id == consumer.object.id)
        .ok_or("Credential snapshot lost the existing Host")?;
    if host.seq != consumer.sequence || host.signer_device_id != Some(consumer.device.id) {
        return Err("Credential exchange changed the existing Host");
    }
    let opened_host = ObjectEnvelope::decode(&host.payload)
        .and_then(|envelope| {
            envelope.decrypt(
                vault,
                consumer.object.id,
                key,
                &consumer.device.keys.signing.public_key_sec1(),
            )
        })
        .map_err(|_| "Existing Host signature or authenticated decryption failed")?;
    if opened_host != consumer.object {
        return Err("Credential exchange changed the existing Host content");
    }
    let retained = snapshot
        .objects
        .iter()
        .find(|object| object.object_id == expected.id)
        .ok_or("Credential snapshot omitted the Credential")?;
    if retained.seq != sequence || retained.signer_device_id != Some(writer.id) {
        return Err("Credential snapshot identity or sequence invalid");
    }
    let opened = ObjectEnvelope::decode(&retained.payload)
        .and_then(|envelope| {
            envelope.decrypt(vault, expected.id, key, &writer.keys.signing.public_key_sec1())
        })
        .map_err(|_| "Credential signature or authenticated decryption failed")?;
    if &opened != expected {
        return Err("Decrypted Credential differs from the original, including its secret");
    }
    Ok(())
}

async fn exchange(https: &Https, consumer: &PersonalConsumer) -> Result<Uuid> {
    let original = password()?;
    let mut object = credential(consumer.account.device.id, &original)?;
    let vault = consumer.account.payload.personal_vault_id;
    let sequence = upload_object(
        https,
        &consumer.account.device,
        &consumer.first_token,
        vault,
        &consumer.account.vault_key,
        &object,
        None,
    )
    .await?;
    if sequence != consumer.sequence + 1 {
        return Err("Initial Credential sequence invalid");
    }
    let key = admitted_vault_key(
        https,
        &consumer.device,
        &consumer.token,
        &consumer.snapshot,
        &consumer.bootstrap,
        consumer.account.device.id,
    )
    .await?;
    download(
        https,
        consumer,
        (&consumer.device, &consumer.token),
        &key,
        &consumer.account.device,
        &object,
        sequence,
    )
    .await?;
    let edited = password()?;
    if original.as_bytes() == edited.as_bytes() {
        return Err("Independent synthetic Credential passwords unexpectedly match");
    }
    object
        .insert(
            FieldPath::field(4).map_err(|_| "Credential secret path invalid")?,
            FieldEntry::new(
                cbor::Value::Bytes(edited.as_bytes().to_vec()),
                Hlc::at(2).map_err(|_| "Credential edit clock invalid")?,
                consumer.device.id,
            )
            .map_err(|_| "Credential secret edit invalid")?,
        )
        .map_err(|_| "Credential secret edit failed")?;
    object.validate().map_err(|_| "Edited Credential schema invalid")?;
    let edited_sequence = upload_object(
        https,
        &consumer.device,
        &consumer.token,
        vault,
        &key,
        &object,
        Some(sequence),
    )
    .await?;
    if edited_sequence != sequence + 1 {
        return Err("Edited Credential sequence invalid");
    }
    download(
        https,
        consumer,
        (&consumer.account.device, &consumer.first_token),
        &consumer.account.vault_key,
        &consumer.device,
        &object,
        edited_sequence,
    )
    .await?;
    Ok(object.id)
}

pub(super) async fn verify(
    https: &Https,
    mut first: PersonalConsumer,
    mut second: PersonalConsumer,
) -> Result<()> {
    first.first_token = first.account.device.refresh(https, first.first_token).await?;
    first = first.refresh(https).await?;
    second.first_token = second.account.device.refresh(https, second.first_token).await?;
    second = second.refresh(https).await?;
    let first_credential = exchange(https, &first).await?;
    let second_credential = exchange(https, &second).await?;
    for (reader, owner, credential) in
        [(&first, &second, second_credential), (&second, &first, first_credential)]
    {
        let vault = owner.account.payload.personal_vault_id;
        for suffix in
            ["snapshot?after=0&limit=10".to_owned(), format!("objects/{credential}/versions")]
        {
            let bytes = https
                .exchange(
                    "GET",
                    &format!("/sync/v1/vaults/{vault}/{suffix}"),
                    &[],
                    Some((&reader.device.keys.signing, Some(&reader.token.access_token))),
                    404,
                )
                .await?;
            let problem = ProblemDetails::from_cbor(&bytes)
                .map_err(|_| "Foreign Credential read problem invalid")?;
            if problem.status != 404
                || problem.code.as_str() != "sync.object_not_found"
                || problem.changed
                || problem.retryable
            {
                return Err(
                    "Foreign Account could read the Credential or changed its refusal boundary",
                );
            }
        }
    }
    Ok(())
}
