// SPDX-License-Identifier: AGPL-3.0-only
//! Live public writes and original-Device verification after controller-owned restoration.

use super::{
    Duration, FieldEntry, FieldPath, Hlc, Https, Object, Path, PersonalConsumer, Result,
    SyncSnapshotResponse, cbor, upload, verify_team, verify_team_isolation,
};

async fn wait(directory: &Path, name: &str) -> Result<()> {
    let timeout = if name.starts_with("daily-backup.") { 300 } else { 120 };
    tokio::time::timeout(Duration::from_secs(timeout), async {
        loop {
            if signal(directory, name)? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| "online backup controller signal timed out")?
}

fn signal(directory: &Path, name: &str) -> Result<bool> {
    match std::fs::symlink_metadata(directory.join(name)) {
        Ok(metadata) if metadata.file_type().is_file() => {
            let contents = crate::read_bounded(&directory.join(name), 16)?;
            if !"continue\n".starts_with(contents.as_str()) {
                return Err("invalid online backup controller signal");
            }
            Ok(contents.as_str() == "continue\n")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        _ => Err("unsafe online backup controller signal"),
    }
}

fn ready(directory: &Path, name: &str) -> Result<()> {
    crate::write_private(&directory.join(name), "ready")
}

async fn write_revision(https: &Https, actor: &mut PersonalConsumer, marker: &str) -> Result<()> {
    let next = actor.sequence + 1;
    for (field, text) in [(1, format!("Online archive revision {next}")), (2, marker.into())] {
        actor
            .object
            .insert(
                FieldPath::field(field).map_err(|_| "online Host edit path invalid")?,
                FieldEntry::new(
                    cbor::Value::Text(text),
                    Hlc::at(next).map_err(|_| "online Host clock invalid")?,
                    actor.device.id,
                )
                .map_err(|_| "online Host field invalid")?,
            )
            .map_err(|_| "online Host edit failed")?;
    }
    upload(
        https,
        &actor.device,
        &actor.token,
        actor.account.payload.personal_vault_id,
        &actor.account.vault_key,
        &actor.object,
        Some(actor.sequence),
    )
    .await?;
    actor.sequence = next;
    Ok(())
}

async fn select_restored_revision(
    https: &Https,
    actor: &mut PersonalConsumer,
    retained: &[Object],
) -> Result<()> {
    // Fresh challenges prove that the original Device keys still authenticate after restore.
    actor.token = actor.device.authenticate(https).await?;
    actor.first_token = actor.account.device.authenticate(https).await?;
    let bytes = https
        .exchange(
            "GET",
            &format!(
                "/sync/v1/vaults/{}/snapshot?after=0&limit=10",
                actor.account.payload.personal_vault_id
            ),
            &[],
            Some((&actor.device.keys.signing, Some(&actor.token.access_token))),
            200,
        )
        .await?;
    let snapshot =
        SyncSnapshotResponse::from_cbor(&bytes).map_err(|_| "online restored snapshot invalid")?;
    let sequence = snapshot.next_cursor;
    let index = sequence
        .checked_sub(3)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or("online restore omitted the pre-capture marker")?;
    actor.object =
        retained.get(index).ok_or("online restore contains a post-completion marker")?.clone();
    actor.sequence = sequence;
    actor.read_personal(https).await?;
    actor.read_personal_from_original_device(https).await
}

pub(super) async fn verify(https: &Https, directory: &Path, daily: bool) -> Result<()> {
    let prefix = if daily { "daily-backup" } else { "online-backup" };
    let mut first = PersonalConsumer::new(https).await?.exchange(https).await?;
    let first_team =
        verify_team(https, &first.device, &first.token, first.account.payload.account_id).await?;
    let mut second = PersonalConsumer::new(https).await?.exchange(https).await?;
    let second_team =
        verify_team(https, &second.device, &second.token, second.account.payload.account_id)
            .await?;
    verify_team_isolation(https, &first, &first_team, &second, &second_team).await?;
    write_revision(https, &mut first, "pre-capture.example").await?;
    let mut retained = vec![first.object.clone()];
    ready(directory, &format!("{prefix}.ready"))?;
    wait(directory, &format!("{prefix}.start")).await?;
    let mut writes = Vec::new();
    while !signal(directory, &format!("{prefix}.complete"))? {
        write_revision(https, &mut first, "pre-capture.example").await?;
        retained.push(first.object.clone());
        writes.push(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "online write receipt clock invalid")?
                .as_millis(),
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if writes.is_empty() {
        return Err("online capture completed without a public write");
    }
    write_revision(https, &mut first, "post-completion.example").await?;
    crate::write_private(
        &directory.join(format!("{prefix}-writes.json")),
        &serde_json::to_string(&writes).map_err(|_| "online write receipt invalid")?,
    )?;
    ready(directory, &format!("{prefix}.post"))?;
    wait(directory, &format!("{prefix}.resume")).await?;
    select_restored_revision(https, &mut first, &retained).await?;
    second.token = second.device.authenticate(https).await?;
    verify_team_isolation(https, &first, &first_team, &second, &second_team).await?;
    ready(directory, &format!("{prefix}.restored"))?;
    wait(directory, &format!("{prefix}.restart")).await?;
    select_restored_revision(https, &mut first, &retained).await?;
    second.token = second.device.authenticate(https).await?;
    verify_team_isolation(https, &first, &first_team, &second, &second_team).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn controller_signal_requires_a_complete_fixed_line() {
        let directory =
            std::env::temp_dir().join(format!("scoplen-online-signal-{}", Uuid::now_v7()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("signal");
        assert!(!signal(&directory, "signal").unwrap());
        for partial in ["", "con", "continue"] {
            std::fs::write(&path, partial).unwrap();
            assert!(!signal(&directory, "signal").unwrap());
        }
        std::fs::write(&path, "continue\n").unwrap();
        assert!(signal(&directory, "signal").unwrap());
        for invalid in ["resume\n", "continue\nextra"] {
            std::fs::write(&path, invalid).unwrap();
            assert!(signal(&directory, "signal").is_err());
        }
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
