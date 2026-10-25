// SPDX-License-Identifier: AGPL-3.0-only
//! Owned legacy database fixtures, independent of retired registration protocols.

use scoplen_api::sync::{SyncAccountDeviceWrap, SyncAccountKeyBundleUpdate};
use scoplen_crypto::{
    AccountKemKeyPair, AccountKemKeyWrap, AccountSigningKeyWrap, DeviceArkWrap, DeviceCertificate,
    DeviceKemKeyPair, Ed25519SigningKey, P256SigningKey, PersonalVaultKeyWrap, RecoveryBlob,
    RecoveryKey, SecretBytes,
};
use uuid::Uuid;

pub struct LegacyIdentity {
    pub account_id: Uuid,
    pub personal_vault_id: Uuid,
    pub account_signing_public_key: [u8; 32],
    pub account_kem_public_key: [u8; 32],
    pub key_bundle_update: SyncAccountKeyBundleUpdate,
    pub device_certificate: DeviceCertificate,
    pub wrapped_personal_vault_key: Vec<u8>,
}

impl LegacyIdentity {
    pub fn new(signing: &Ed25519SigningKey, client: &P256SigningKey) -> Self {
        let account_id = Uuid::now_v7();
        let device_id = Uuid::now_v7();
        let personal_vault_id = Uuid::now_v7();
        let kem = AccountKemKeyPair::from_private_bytes(&[4; 32]).expect("account KEM");
        let device_kem = DeviceKemKeyPair::from_private_bytes(&[3; 32]).expect("device KEM");
        let ark = SecretBytes::new([11; 32]);
        let vault_key = SecretBytes::new([8; 32]);
        let mut key_bundle_update = SyncAccountKeyBundleUpdate {
            revision: 1,
            device_wraps: vec![SyncAccountDeviceWrap {
                device_id,
                wrapped_ark: DeviceArkWrap::seal(
                    account_id,
                    device_id,
                    device_kem.public_key(),
                    &ark,
                )
                .expect("device wrap")
                .encode()
                .to_vec(),
            }],
            account_signing_key: AccountSigningKeyWrap::seal(account_id, &ark, signing)
                .expect("signing wrap")
                .encode()
                .to_vec(),
            account_kem_key: AccountKemKeyWrap::seal(account_id, &ark, &kem)
                .expect("KEM wrap")
                .encode()
                .to_vec(),
            recovery_blob: RecoveryBlob::wrap(
                &RecoveryKey::generate().expect("recovery key"),
                account_id,
                &ark,
            )
            .expect("recovery wrap")
            .encode()
            .expect("recovery encoding"),
            signature: vec![0; 64],
        };
        key_bundle_update.signature =
            signing.sign(&key_bundle_update.signature_input().expect("bundle input")).to_vec();
        Self {
            account_id,
            personal_vault_id,
            account_signing_public_key: signing.public_key(),
            account_kem_public_key: kem.public_key().try_into().expect("account KEM size"),
            device_certificate: DeviceCertificate::issue(
                signing,
                device_id,
                account_id,
                client.public_key_sec1(),
                device_kem.public_key().to_vec(),
                "Legacy test device".into(),
                "test".into(),
                1,
            )
            .expect("signed certificate"),
            wrapped_personal_vault_key: PersonalVaultKeyWrap::seal(
                account_id,
                personal_vault_id,
                1,
                &ark,
                &vault_key,
            )
            .expect("Personal wrap")
            .encode()
            .to_vec(),
            key_bundle_update,
        }
    }
}

macro_rules! seed {
    ($(#[$attribute:meta])* $name:ident, $pool:ty, $postgres:literal) => {
        $(#[$attribute])*
        pub async fn $name(pool: &$pool, identity: &LegacyIdentity, accepted: bool) {
            let sql = |source: &str| {
                let mut parameter = 0;
                if !$postgres { return source.to_owned(); }
                source.chars().map(|character| if character == '?' {
                    parameter += 1; format!("${parameter}")
                } else { character.to_string() }).collect::<String>()
            };
            let mut tx = pool.begin().await.expect("owned fixture transaction");
            let account = identity.account_id.as_bytes().as_slice();
            let device = identity.device_certificate.device_id.as_bytes().as_slice();
            let vault = identity.personal_vault_id.as_bytes().as_slice();
            let update = &identity.key_bundle_update;
            let certificate = identity.device_certificate.encode().expect("certificate bytes");
            let put = update.to_cbor().expect("signed PUT");
            sqlx::query(&sql("INSERT INTO identity_accounts (account_id,account_signing_public_key,account_kem_public_key,created_at_ms) VALUES (?,?,?,1)"))
                .bind(account).bind(identity.account_signing_public_key.as_slice()).bind(identity.account_kem_public_key.as_slice())
                .execute(&mut *tx).await.expect("legacy Account seed");
            sqlx::query(&sql("INSERT INTO identity_devices (device_id,account_id,certificate,active,created_at_ms) VALUES (?,?,?,?,1)"))
                .bind(device).bind(account).bind(&certificate).bind(true).execute(&mut *tx).await.expect("legacy Device seed");
            sqlx::query(&sql("INSERT INTO sync_account_key_bundles (account_id,revision,account_signing_key,account_kem_key,recovery_blob,signature,updated_at_ms,accepted_put_cbor) VALUES (?,1,?,?,?,?,1,?)"))
                .bind(account).bind(&update.account_signing_key).bind(&update.account_kem_key).bind(&update.recovery_blob).bind(&update.signature)
                .bind(accepted.then_some(&put)).execute(&mut *tx).await.expect("legacy bundle seed");
            sqlx::query(&sql("INSERT INTO sync_account_key_device_wraps (account_id,device_id,wrapped_ark) VALUES (?,?,?)"))
                .bind(account).bind(device).bind(&update.device_wraps[0].wrapped_ark).execute(&mut *tx).await.expect("legacy wrap seed");
            sqlx::query(&sql("INSERT INTO sync_account_key_certificates (account_id,certificate) VALUES (?,?)"))
                .bind(account).bind(certificate).execute(&mut *tx).await.expect("legacy statement seed");
            sqlx::query(&sql("INSERT INTO sync_vaults (vault_id,kind) VALUES (?,'personal')"))
                .bind(vault).execute(&mut *tx).await.expect("legacy vault seed");
            sqlx::query(&sql("INSERT INTO sync_personal_vaults (account_id,vault_id,key_epoch,wrapped_vault_key) VALUES (?,?,1,?)"))
                .bind(account).bind(vault).bind(&identity.wrapped_personal_vault_key).execute(&mut *tx).await.expect("legacy Personal key seed");
            tx.commit().await.expect("legacy fixture committed");
        }
    };
}

seed!(seed_sqlite, sqlx::SqlitePool, false);
seed!(
    #[allow(
        dead_code,
        reason = "Shared with server tests; store callers require postgres-integration"
    )]
    seed_postgres,
    sqlx::PgPool,
    true
);
