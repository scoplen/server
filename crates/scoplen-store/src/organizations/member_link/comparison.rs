// SPDX-License-Identifier: AGPL-3.0-only
//! Stable tenant-scoped comparison keys wrapped under the deployment KEK.

use scoplen_crypto::{SecretVec, hkdf_sha256, random_key};
use zeroize::Zeroizing;

use super::{
    ConnectionTarget, Error, Postgres, PostgresStore, Sqlite, SqliteStore, Transaction, Uuid,
};
use crate::{kms::KeyManagementService, organizations::auth_envelope};

fn key_aad(org: Uuid, usage: u8) -> Vec<u8> {
    let mut value = b"spl-member-link-comparison-key\0v1\0".to_vec();
    value.push(usage);
    value.extend_from_slice(org.as_bytes());
    value
}

fn compare(
    key: &[u8],
    org: Uuid,
    target: &ConnectionTarget,
    subject: &SecretVec,
) -> Result<SecretVec, Error> {
    if subject.is_empty() || subject.len() > 255 || !subject.as_bytes().is_ascii() {
        return Err(Error::InvalidRequest);
    }
    let mut info = Zeroizing::new(Vec::new());
    for field in [
        org.as_bytes().as_slice(),
        target.issuer.as_bytes(),
        target.client_id.as_bytes(),
        target.space_id.as_bytes(),
        subject.as_bytes(),
    ] {
        info.extend_from_slice(&(field.len() as u64).to_be_bytes());
        info.extend_from_slice(field);
    }
    hkdf_sha256(key, Some(b"spl-member-link-subject-comparison\0v1\0"), &info, 32)
        .map(SecretVec::new)
        .map_err(|_| Error::StorageUnavailable)
}

macro_rules! comparison_keys {
    ($store:ty,$db:ty) => {
        impl $store {
            // The caller holds the Organization lock across key selection, verification and audit.
            pub(super) async fn compare_link_subject(
                tx: &mut Transaction<'_, $db>,
                org: Uuid,
                target: &ConnectionTarget,
                subject: &SecretVec,
                kms: &dyn KeyManagementService,
            ) -> Result<SecretVec, Error> {
                let stored:Option<Vec<u8>>=sqlx::query_scalar("SELECT encrypted_key FROM organization_auth_link_comparison_keys WHERE organization_id=$1")
                            .bind(org.as_bytes().as_slice()).fetch_optional(&mut **tx).await?;
                if let Some(stored) = stored {
                    let key = auth_envelope::open(&stored, 32..=32, |usage| key_aad(org, usage), kms)?;
                    return compare(key.as_bytes(), org, target, subject);
                }
                let used:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organization_auth_links WHERE organization_id=$1)
                            OR EXISTS(SELECT 1 FROM organization_auth_link_attempts WHERE organization_id=$1 AND subject_comparison IS NOT NULL)")
                            .bind(org.as_bytes().as_slice()).fetch_one(&mut **tx).await?;
                if used {
                    return Err(Error::StorageUnavailable);
                }
                let key = random_key().map_err(|_| Error::StorageUnavailable)?;
                let result = compare(key.as_bytes(), org, target, subject)?;
                let wrapped = auth_envelope::seal(key.as_bytes(), |usage| key_aad(org, usage), kms)?;
                sqlx::query("INSERT INTO organization_auth_link_comparison_keys(organization_id,encrypted_key) VALUES ($1,$2)")
                            .bind(org.as_bytes().as_slice()).bind(wrapped).execute(&mut **tx).await?;
                Ok(result)
            }
        }
    };
}
comparison_keys!(SqliteStore, Sqlite);
comparison_keys!(PostgresStore, Postgres);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_subject_comparisons_are_keyed_and_length_delimited() {
        let org = Uuid::now_v7();
        let target = ConnectionTarget {
            issuer: "https://example.test".into(),
            client_id: "ab".into(),
            space_id: "spc_c".into(),
        };
        let subject = SecretVec::new(b"user".to_vec());
        let original = compare(&[1; 32], org, &target, &subject).unwrap();
        assert_eq!(compare(&[1; 32], org, &target, &subject).unwrap(), original);
        assert_ne!(compare(&[2; 32], org, &target, &subject).unwrap(), original);
        assert_ne!(compare(&[1; 32], Uuid::now_v7(), &target, &subject).unwrap(), original);
        let split = ConnectionTarget {
            issuer: target.issuer.clone(),
            client_id: "a".into(),
            space_id: "bspc_c".into(),
        };
        assert_ne!(compare(&[1; 32], org, &split, &subject).unwrap(), original);
        assert_ne!(
            compare(&[1; 32], org, &target, &SecretVec::new(b"User".to_vec())).unwrap(),
            original
        );
        for bytes in [vec![], vec![65; 256], vec![0xc3, 0xa9]] {
            assert_eq!(
                compare(&[1; 32], org, &target, &SecretVec::new(bytes)),
                Err(Error::InvalidRequest)
            );
        }
    }
}
