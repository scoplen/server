// SPDX-License-Identifier: AGPL-3.0-only
//! Durable Personal invitations and first-device enrollment.
//!
//! Operator authentication and HTTP decoding precede these internal storage methods. A
//! [`VerifiedPersonalEnrollment`] is the only accepted redemption input; the verifier owns the
//! K-2, K-4, and possession-signature checks. Neither method grants a session or operator role.

use std::{
    fmt,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use scoplen_crypto::validate_server_origin;
use scoplen_identity::VerifiedPersonalEnrollment;
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row, Sqlite, Transaction};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    AuditStoreError, PostgresStore, RelationalStore, SqliteStore,
    account_keys::{
        AccountId, AccountKeyStoreError, DeviceId, check_postgres_key_response_capacity,
        check_sqlite_key_response_capacity,
    },
    deployment_audit::{
        append_deployment_audit_event_in_postgres_transaction,
        append_deployment_audit_event_in_transaction,
    },
    personal_admission::{clear_postgres_failure_streak, clear_sqlite_failure_streak},
};

const INVITATION_LIFETIME_MS: i64 = 24 * 60 * 60 * 1_000;
const EVENT_DOMAIN: &[u8] = b"spl-personal-invitation-audit-v1";

/// An issued one-use bearer secret. Its debug output and drop path never reveal the token.
pub struct IssuedPersonalInvitation {
    invitation_id: [u8; 16],
    token: [u8; 32],
    trusted_origin: String,
    expires_at_ms: i64,
}

impl IssuedPersonalInvitation {
    #[must_use]
    pub const fn invitation_id(&self) -> &[u8; 16] {
        &self.invitation_id
    }

    /// The token must be disclosed only once to the authenticated operator in a URL fragment.
    #[must_use]
    pub const fn token_bytes(&self) -> &[u8; 32] {
        &self.token
    }

    #[must_use]
    pub fn trusted_origin(&self) -> &str {
        &self.trusted_origin
    }

    #[must_use]
    pub const fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }
}

impl fmt::Debug for IssuedPersonalInvitation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IssuedPersonalInvitation([REDACTED])")
    }
}

impl Drop for IssuedPersonalInvitation {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

/// Identifiers committed by a successful first-device enrollment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersonalEnrollmentReceipt {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub personal_vault_id: [u8; 16],
}

/// A device visible to the later challenge/device authentication service.
pub struct EnrolledPersonalDevice {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    account_signing_public_key: [u8; 32],
    certificate_cbor: Vec<u8>,
}

impl EnrolledPersonalDevice {
    #[must_use]
    pub const fn account_signing_public_key(&self) -> &[u8; 32] {
        &self.account_signing_public_key
    }

    #[must_use]
    pub fn certificate_cbor(&self) -> &[u8] {
        &self.certificate_cbor
    }
}

impl fmt::Debug for EnrolledPersonalDevice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnrolledPersonalDevice([REDACTED])")
    }
}

/// Errors at the internal invitation persistence boundary. `Denied` deliberately covers every
/// missing, expired, spent, wrong-origin, and conflicting-identifier redemption.
#[derive(Debug, Error)]
pub enum PersonalInvitationStoreError {
    #[error("trusted Personal invitation origin is invalid")]
    InvalidOrigin,
    #[error("Personal invitation issuer is invalid")]
    InvalidIssuer,
    #[error("Personal enrollment denied")]
    Denied,
    #[error("Personal enrollment artifacts are invalid")]
    InvalidEnrollment,
    #[error("system clock cannot represent Personal invitation time")]
    Clock,
    #[error("could not generate a Personal invitation")]
    Entropy,
    #[error("Personal invitation storage failed")]
    Database,
    #[error("Personal invitation commit outcome is unknown")]
    CommitOutcomeUnknown,
    #[error("Personal invitation audit failed")]
    Audit,
    #[error("Personal enrollment key response failed")]
    KeyResponse,
}

impl From<sqlx::Error> for PersonalInvitationStoreError {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}

impl From<AuditStoreError> for PersonalInvitationStoreError {
    fn from(_: AuditStoreError) -> Self {
        Self::Audit
    }
}

impl From<AccountKeyStoreError> for PersonalInvitationStoreError {
    fn from(_: AccountKeyStoreError) -> Self {
        Self::KeyResponse
    }
}

impl SqliteStore {
    /// Persist a one-use invitation for an operator authenticated by the calling service.
    /// This library method does not authenticate the issuer or expose an HTTP route.
    ///
    /// # Errors
    ///
    /// Returns validation, entropy, clock, audit, or database errors without exposing a token.
    pub async fn issue_personal_invitation(
        &self,
        issuer_operator_id: AccountId,
        trusted_origin: &str,
    ) -> Result<IssuedPersonalInvitation, PersonalInvitationStoreError> {
        let issue = prepare_issue(issuer_operator_id, trusted_origin)?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "INSERT INTO personal_invitations
             (invitation_id, token_digest, trusted_origin, issuer_operator_id, issued_at_ms, expires_at_ms)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(issue.invitation_id.as_slice())
        .bind(issue.token_digest.as_slice())
        .bind(trusted_origin)
        .bind(issuer_operator_id.as_slice())
        .bind(issue.issued_at_ms)
        .bind(issue.expires_at_ms)
        .execute(&mut *transaction)
        .await?;
        let event = audit_event(1, issue.issued_at_ms, &[issuer_operator_id, issue.invitation_id])?;
        append_deployment_audit_event_in_transaction(&mut transaction, &event, issue.issued_at_ms)
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| PersonalInvitationStoreError::CommitOutcomeUnknown)?;
        Ok(issue.disclose(trusted_origin))
    }

    /// Consume a verified invitation and commit the first account, device, K-4 bundle, Personal
    /// vault, and deployment audit event together.
    ///
    /// # Errors
    ///
    /// Returns one `Denied` for invalid entitlement or any assigned identifier. Other errors
    /// roll back the entire transaction, including invitation consumption.
    pub async fn redeem_verified_personal_invitation(
        &self,
        verified: &VerifiedPersonalEnrollment,
    ) -> Result<PersonalEnrollmentReceipt, PersonalInvitationStoreError> {
        self.redeem_verified_personal_invitation_with_source(verified, None).await
    }

    /// Redeem through a source-admitted HTTP request, clearing its failure streak on commit.
    ///
    /// # Errors
    /// A failure before commit rolls back identity, invitation, and audit changes. A failed
    /// commit acknowledgement returns `CommitOutcomeUnknown`; the transaction may have committed.
    pub async fn redeem_verified_personal_invitation_from_source(
        &self,
        verified: &VerifiedPersonalEnrollment,
        source: IpAddr,
    ) -> Result<PersonalEnrollmentReceipt, PersonalInvitationStoreError> {
        self.redeem_verified_personal_invitation_with_source(verified, Some(source)).await
    }

    async fn redeem_verified_personal_invitation_with_source(
        &self,
        verified: &VerifiedPersonalEnrollment,
        source: Option<IpAddr>,
    ) -> Result<PersonalEnrollmentReceipt, PersonalInvitationStoreError> {
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let row = sqlx::query(
            "SELECT invitation_id, trusted_origin, issued_at_ms, expires_at_ms, consumed_at_ms
             FROM personal_invitations WHERE token_digest = ?",
        )
        .bind(verified.invitation_token_digest().as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
        let now = now_ms()?;
        let invitation_id = eligible_invitation(row, verified, now)?;
        let receipt = receipt(verified);
        insert_sqlite_enrollment(&mut transaction, verified, receipt, now).await?;
        let consumed = sqlx::query(
            "UPDATE personal_invitations SET consumed_at_ms = ?, consumed_account_id = ?
             WHERE invitation_id = ? AND consumed_at_ms IS NULL AND expires_at_ms > ?",
        )
        .bind(now)
        .bind(receipt.account_id.as_slice())
        .bind(invitation_id.as_slice())
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        if consumed.rows_affected() != 1 {
            return Err(PersonalInvitationStoreError::Denied);
        }
        let event = audit_event(
            2,
            now,
            &[invitation_id, receipt.account_id, receipt.device_id, receipt.personal_vault_id],
        )?;
        append_deployment_audit_event_in_transaction(&mut transaction, &event, now).await?;
        if let Some(source) = source {
            clear_sqlite_failure_streak(
                &mut transaction,
                source,
                verified.invitation_token_digest(),
            )
            .await
            .map_err(|_| PersonalInvitationStoreError::Database)?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| PersonalInvitationStoreError::CommitOutcomeUnknown)?;
        Ok(receipt)
    }

    /// Resolve an active first device for a later authenticated challenge exchange.
    ///
    /// # Errors
    ///
    /// Returns a database or corrupt-row error. Absence and inactive devices both return `None`.
    pub async fn find_active_personal_device(
        &self,
        device_id: DeviceId,
    ) -> Result<Option<EnrolledPersonalDevice>, PersonalInvitationStoreError> {
        let row = sqlx::query(
            "SELECT d.account_id, d.certificate, a.account_signing_public_key
             FROM identity_devices AS d JOIN identity_accounts AS a ON a.account_id = d.account_id
             WHERE d.device_id = ? AND d.active = 1",
        )
        .bind(device_id.as_slice())
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| enrolled_device(&row, device_id)).transpose()
    }
}

impl PostgresStore {
    /// Persist a one-use invitation for an operator authenticated by the calling service.
    /// This library method does not authenticate the issuer or expose an HTTP route.
    ///
    /// # Errors
    ///
    /// Returns validation, entropy, clock, audit, or database errors without exposing a token.
    pub async fn issue_personal_invitation(
        &self,
        issuer_operator_id: AccountId,
        trusted_origin: &str,
    ) -> Result<IssuedPersonalInvitation, PersonalInvitationStoreError> {
        let issue = prepare_issue(issuer_operator_id, trusted_origin)?;
        let mut transaction = self.pool().begin().await?;
        sqlx::query(
            "INSERT INTO personal_invitations
             (invitation_id, token_digest, trusted_origin, issuer_operator_id, issued_at_ms, expires_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(issue.invitation_id.as_slice())
        .bind(issue.token_digest.as_slice())
        .bind(trusted_origin)
        .bind(issuer_operator_id.as_slice())
        .bind(issue.issued_at_ms)
        .bind(issue.expires_at_ms)
        .execute(&mut *transaction)
        .await?;
        let event = audit_event(1, issue.issued_at_ms, &[issuer_operator_id, issue.invitation_id])?;
        append_deployment_audit_event_in_postgres_transaction(
            &mut transaction,
            &event,
            issue.issued_at_ms,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| PersonalInvitationStoreError::CommitOutcomeUnknown)?;
        Ok(issue.disclose(trusted_origin))
    }

    /// Atomically consume a verified invitation and enroll the first Personal device.
    ///
    /// # Errors
    ///
    /// Returns one `Denied` for invalid entitlement or any assigned identifier. Other errors
    /// roll back the entire transaction, including invitation consumption.
    pub async fn redeem_verified_personal_invitation(
        &self,
        verified: &VerifiedPersonalEnrollment,
    ) -> Result<PersonalEnrollmentReceipt, PersonalInvitationStoreError> {
        self.redeem_verified_personal_invitation_with_source(verified, None).await
    }

    /// Redeem through a source-admitted HTTP request, clearing its failure streak on commit.
    ///
    /// # Errors
    /// A failure before commit rolls back identity, invitation, and audit changes. A failed
    /// commit acknowledgement returns `CommitOutcomeUnknown`; the transaction may have committed.
    pub async fn redeem_verified_personal_invitation_from_source(
        &self,
        verified: &VerifiedPersonalEnrollment,
        source: IpAddr,
    ) -> Result<PersonalEnrollmentReceipt, PersonalInvitationStoreError> {
        self.redeem_verified_personal_invitation_with_source(verified, Some(source)).await
    }

    async fn redeem_verified_personal_invitation_with_source(
        &self,
        verified: &VerifiedPersonalEnrollment,
        source: Option<IpAddr>,
    ) -> Result<PersonalEnrollmentReceipt, PersonalInvitationStoreError> {
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT invitation_id, trusted_origin, issued_at_ms, expires_at_ms, consumed_at_ms
             FROM personal_invitations WHERE token_digest = $1 FOR UPDATE",
        )
        .bind(verified.invitation_token_digest().as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
        let now = now_ms()?;
        let invitation_id = eligible_invitation(row, verified, now)?;
        let receipt = receipt(verified);
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
            .bind(receipt.account_id.as_slice())
            .execute(&mut *transaction)
            .await?;
        insert_postgres_enrollment(&mut transaction, verified, receipt, now).await?;
        let consumed = sqlx::query(
            "UPDATE personal_invitations SET consumed_at_ms = $1, consumed_account_id = $2
             WHERE invitation_id = $3 AND consumed_at_ms IS NULL AND expires_at_ms > $4",
        )
        .bind(now)
        .bind(receipt.account_id.as_slice())
        .bind(invitation_id.as_slice())
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        if consumed.rows_affected() != 1 {
            return Err(PersonalInvitationStoreError::Denied);
        }
        let event = audit_event(
            2,
            now,
            &[invitation_id, receipt.account_id, receipt.device_id, receipt.personal_vault_id],
        )?;
        if let Some(source) = source {
            clear_postgres_failure_streak(
                &mut transaction,
                source,
                verified.invitation_token_digest(),
            )
            .await
            .map_err(|_| PersonalInvitationStoreError::Database)?;
        }
        append_deployment_audit_event_in_postgres_transaction(&mut transaction, &event, now)
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| PersonalInvitationStoreError::CommitOutcomeUnknown)?;
        Ok(receipt)
    }

    /// Resolve an active first device for a later authenticated challenge exchange.
    ///
    /// # Errors
    ///
    /// Returns a database or corrupt-row error. Absence and inactive devices both return `None`.
    pub async fn find_active_personal_device(
        &self,
        device_id: DeviceId,
    ) -> Result<Option<EnrolledPersonalDevice>, PersonalInvitationStoreError> {
        let row = sqlx::query(
            "SELECT d.account_id, d.certificate, a.account_signing_public_key
             FROM identity_devices AS d JOIN identity_accounts AS a ON a.account_id = d.account_id
             WHERE d.device_id = $1 AND d.active = TRUE",
        )
        .bind(device_id.as_slice())
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| enrolled_device(&row, device_id)).transpose()
    }
}

struct PendingInvitation {
    invitation_id: [u8; 16],
    token: Zeroizing<[u8; 32]>,
    token_digest: [u8; 32],
    issued_at_ms: i64,
    expires_at_ms: i64,
}

impl PendingInvitation {
    fn disclose(self, trusted_origin: &str) -> IssuedPersonalInvitation {
        IssuedPersonalInvitation {
            invitation_id: self.invitation_id,
            token: *self.token,
            trusted_origin: trusted_origin.to_owned(),
            expires_at_ms: self.expires_at_ms,
        }
    }
}

fn prepare_issue(
    issuer_operator_id: AccountId,
    trusted_origin: &str,
) -> Result<PendingInvitation, PersonalInvitationStoreError> {
    if issuer_operator_id == [0; 16] {
        return Err(PersonalInvitationStoreError::InvalidIssuer);
    }
    validate_server_origin(trusted_origin)
        .map_err(|_| PersonalInvitationStoreError::InvalidOrigin)?;
    let issued_at_ms = now_ms()?;
    let expires_at_ms = issued_at_ms
        .checked_add(INVITATION_LIFETIME_MS)
        .ok_or(PersonalInvitationStoreError::Clock)?;
    let mut token = Zeroizing::new([0; 32]);
    getrandom::fill(&mut *token).map_err(|_| PersonalInvitationStoreError::Entropy)?;
    let mut invitation_id = [0; 16];
    getrandom::fill(&mut invitation_id).map_err(|_| PersonalInvitationStoreError::Entropy)?;
    let token_digest = Sha256::digest(*token).into();
    Ok(PendingInvitation { invitation_id, token, token_digest, issued_at_ms, expires_at_ms })
}

fn now_ms() -> Result<i64, PersonalInvitationStoreError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PersonalInvitationStoreError::Clock)?
        .as_millis();
    i64::try_from(millis).map_err(|_| PersonalInvitationStoreError::Clock)
}

fn audit_event(
    class: u8,
    at_ms: i64,
    ids: &[[u8; 16]],
) -> Result<Vec<u8>, PersonalInvitationStoreError> {
    let at_ms = u64::try_from(at_ms).map_err(|_| PersonalInvitationStoreError::Clock)?;
    // Versioned fixed-width internal event: class (issue=1, consume=2), success=1, time,
    // then issuer/invitation or invitation/account/device/vault ids in that order.
    let mut bytes = Vec::with_capacity(EVENT_DOMAIN.len() + 10 + ids.len() * 16);
    bytes.extend_from_slice(EVENT_DOMAIN);
    bytes.extend_from_slice(&[class, 1]);
    bytes.extend_from_slice(&at_ms.to_be_bytes());
    for id in ids {
        bytes.extend_from_slice(id);
    }
    Ok(bytes)
}

fn eligible_invitation<R: Row>(
    row: Option<R>,
    verified: &VerifiedPersonalEnrollment,
    now: i64,
) -> Result<[u8; 16], PersonalInvitationStoreError>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    Option<i64>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    String: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    Vec<u8>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    let row = row.ok_or(PersonalInvitationStoreError::Denied)?;
    let origin: String = row.try_get("trusted_origin")?;
    let issued_at_ms: i64 = row.try_get("issued_at_ms")?;
    let expires_at_ms: i64 = row.try_get("expires_at_ms")?;
    let consumed_at_ms: Option<i64> = row.try_get("consumed_at_ms")?;
    if origin != verified.trusted_origin()
        || now < issued_at_ms
        || now >= expires_at_ms
        || consumed_at_ms.is_some()
    {
        return Err(PersonalInvitationStoreError::Denied);
    }
    row.try_get::<Vec<u8>, _>("invitation_id")?
        .try_into()
        .map_err(|_| PersonalInvitationStoreError::Denied)
}

fn receipt(verified: &VerifiedPersonalEnrollment) -> PersonalEnrollmentReceipt {
    PersonalEnrollmentReceipt {
        account_id: *verified.account_id().as_bytes(),
        device_id: *verified.device_id().as_bytes(),
        personal_vault_id: *verified.personal_vault_id().as_bytes(),
    }
}

fn enrollment_wrap(
    verified: &VerifiedPersonalEnrollment,
) -> Result<(&[u8], &[u8; 64]), PersonalInvitationStoreError> {
    let update = verified.key_bundle_update();
    let [wrap] = update.device_wraps.as_slice() else {
        return Err(PersonalInvitationStoreError::InvalidEnrollment);
    };
    if wrap.device_id != verified.device_id() {
        return Err(PersonalInvitationStoreError::InvalidEnrollment);
    }
    let signature: &[u8; 64] = update
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| PersonalInvitationStoreError::InvalidEnrollment)?;
    Ok((&wrap.wrapped_ark, signature))
}

fn enrolled_device<R: Row>(
    row: &R,
    device_id: DeviceId,
) -> Result<EnrolledPersonalDevice, PersonalInvitationStoreError>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    Vec<u8>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    let account_id = row
        .try_get::<Vec<u8>, _>("account_id")?
        .try_into()
        .map_err(|_| PersonalInvitationStoreError::InvalidEnrollment)?;
    let account_signing_public_key = row
        .try_get::<Vec<u8>, _>("account_signing_public_key")?
        .try_into()
        .map_err(|_| PersonalInvitationStoreError::InvalidEnrollment)?;
    let certificate_cbor: Vec<u8> = row.try_get("certificate")?;
    if certificate_cbor.is_empty() || certificate_cbor.len() > 65_536 {
        return Err(PersonalInvitationStoreError::InvalidEnrollment);
    }
    Ok(EnrolledPersonalDevice {
        account_id,
        device_id,
        account_signing_public_key,
        certificate_cbor,
    })
}

fn map_unique_to_denied(error: sqlx::Error) -> PersonalInvitationStoreError {
    let is_unique =
        matches!(&error, sqlx::Error::Database(database) if database.is_unique_violation());
    drop(error);
    if is_unique {
        PersonalInvitationStoreError::Denied
    } else {
        PersonalInvitationStoreError::Database
    }
}

async fn insert_sqlite_enrollment(
    transaction: &mut Transaction<'_, Sqlite>,
    verified: &VerifiedPersonalEnrollment,
    receipt: PersonalEnrollmentReceipt,
    now: i64,
) -> Result<(), PersonalInvitationStoreError> {
    let (wrapped_ark, signature) = enrollment_wrap(verified)?;
    let update = verified.key_bundle_update();
    let account = receipt.account_id.as_slice();
    let device = receipt.device_id.as_slice();
    let vault = receipt.personal_vault_id.as_slice();

    // K-4 and vault rows can predate identity enrollment. None may be adopted by a new account.
    let conflict = sqlx::query_scalar::<_, i64>(
        "SELECT 1 WHERE
         EXISTS (SELECT 1 FROM identity_accounts WHERE account_id = ?)
         OR EXISTS (SELECT 1 FROM sync_account_key_bundles WHERE account_id = ?)
         OR EXISTS (SELECT 1 FROM sync_account_key_certificates WHERE account_id = ?)
         OR EXISTS (SELECT 1 FROM sync_account_key_revocations WHERE account_id = ?)
         OR EXISTS (SELECT 1 FROM sync_personal_vaults WHERE account_id = ? OR vault_id = ?)
         OR EXISTS (SELECT 1 FROM identity_devices WHERE device_id = ?)
         OR EXISTS (SELECT 1 FROM sync_account_key_device_wraps WHERE device_id = ?)
         OR EXISTS (SELECT 1 FROM sync_vaults WHERE vault_id = ?)",
    )
    .bind(account)
    .bind(account)
    .bind(account)
    .bind(account)
    .bind(account)
    .bind(vault)
    .bind(device)
    .bind(device)
    .bind(vault)
    .fetch_optional(&mut **transaction)
    .await?;
    if conflict.is_some() {
        return Err(PersonalInvitationStoreError::Denied);
    }

    sqlx::query(
        "INSERT INTO identity_accounts
        (account_id, email, account_signing_public_key, account_kem_public_key, created_at_ms)
        VALUES (?, NULL, ?, ?, ?)",
    )
    .bind(account)
    .bind(verified.account_signing_public_key().as_slice())
    .bind(verified.account_kem_public_key().as_slice())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(map_unique_to_denied)?;
    sqlx::query("INSERT INTO sync_account_key_bundles
        (account_id, revision, account_signing_key, account_kem_key, recovery_blob, signature, updated_at_ms)
        VALUES (?, 1, ?, ?, ?, ?, ?)")
        .bind(account).bind(&update.account_signing_key).bind(&update.account_kem_key)
        .bind(&update.recovery_blob).bind(signature.as_slice()).bind(now)
        .execute(&mut **transaction).await.map_err(map_unique_to_denied)?;
    sqlx::query(
        "INSERT INTO sync_account_key_device_wraps (account_id, device_id, wrapped_ark)
        VALUES (?, ?, ?)",
    )
    .bind(account)
    .bind(device)
    .bind(wrapped_ark)
    .execute(&mut **transaction)
    .await
    .map_err(map_unique_to_denied)?;
    sqlx::query(
        "INSERT INTO sync_account_key_certificates (account_id, certificate)
        VALUES (?, ?)",
    )
    .bind(account)
    .bind(verified.device_certificate_cbor())
    .execute(&mut **transaction)
    .await
    .map_err(map_unique_to_denied)?;
    sqlx::query(
        "INSERT INTO identity_devices
        (device_id, account_id, certificate, active, created_at_ms)
        VALUES (?, ?, ?, 1, ?)",
    )
    .bind(device)
    .bind(account)
    .bind(verified.device_certificate_cbor())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(map_unique_to_denied)?;
    sqlx::query("INSERT INTO sync_vaults (vault_id, kind) VALUES (?, 'personal')")
        .bind(vault)
        .execute(&mut **transaction)
        .await
        .map_err(map_unique_to_denied)?;
    sqlx::query(
        "INSERT INTO sync_personal_vaults
        (account_id, vault_id, wrapped_vault_key) VALUES (?, ?, ?)",
    )
    .bind(account)
    .bind(vault)
    .bind(verified.wrapped_personal_vault_key())
    .execute(&mut **transaction)
    .await
    .map_err(map_unique_to_denied)?;
    check_sqlite_key_response_capacity(transaction, receipt.account_id).await?;
    Ok(())
}

async fn insert_postgres_enrollment(
    transaction: &mut Transaction<'_, Postgres>,
    verified: &VerifiedPersonalEnrollment,
    receipt: PersonalEnrollmentReceipt,
    now: i64,
) -> Result<(), PersonalInvitationStoreError> {
    let (wrapped_ark, signature) = enrollment_wrap(verified)?;
    let update = verified.key_bundle_update();
    let account = receipt.account_id.as_slice();
    let device = receipt.device_id.as_slice();
    let vault = receipt.personal_vault_id.as_slice();
    // Serialize the legacy K-4 wrap lookup with concurrent K-4 inserts.
    sqlx::query("LOCK TABLE sync_account_key_device_wraps IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut **transaction)
        .await?;
    let conflict = sqlx::query_scalar::<_, i64>(
        "SELECT 1::bigint WHERE
         EXISTS (SELECT 1 FROM identity_accounts WHERE account_id = $1)
         OR EXISTS (SELECT 1 FROM sync_account_key_bundles WHERE account_id = $1)
         OR EXISTS (SELECT 1 FROM sync_account_key_certificates WHERE account_id = $1)
         OR EXISTS (SELECT 1 FROM sync_account_key_revocations WHERE account_id = $1)
         OR EXISTS (SELECT 1 FROM sync_personal_vaults WHERE account_id = $1 OR vault_id = $3)
         OR EXISTS (SELECT 1 FROM identity_devices WHERE device_id = $2)
         OR EXISTS (SELECT 1 FROM sync_account_key_device_wraps WHERE device_id = $2)
         OR EXISTS (SELECT 1 FROM sync_vaults WHERE vault_id = $3)",
    )
    .bind(account)
    .bind(device)
    .bind(vault)
    .fetch_optional(&mut **transaction)
    .await?;
    if conflict.is_some() {
        return Err(PersonalInvitationStoreError::Denied);
    }

    sqlx::query(
        "INSERT INTO identity_accounts
        (account_id, email, account_signing_public_key, account_kem_public_key, created_at_ms)
        VALUES ($1, NULL, $2, $3, $4)",
    )
    .bind(account)
    .bind(verified.account_signing_public_key().as_slice())
    .bind(verified.account_kem_public_key().as_slice())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(map_unique_to_denied)?;
    sqlx::query("INSERT INTO sync_account_key_bundles
        (account_id, revision, account_signing_key, account_kem_key, recovery_blob, signature, updated_at_ms)
        VALUES ($1, 1, $2, $3, $4, $5, $6)")
        .bind(account).bind(&update.account_signing_key).bind(&update.account_kem_key)
        .bind(&update.recovery_blob).bind(signature.as_slice()).bind(now)
        .execute(&mut **transaction).await.map_err(map_unique_to_denied)?;
    sqlx::query(
        "INSERT INTO sync_account_key_device_wraps (account_id, device_id, wrapped_ark)
        VALUES ($1, $2, $3)",
    )
    .bind(account)
    .bind(device)
    .bind(wrapped_ark)
    .execute(&mut **transaction)
    .await
    .map_err(map_unique_to_denied)?;
    sqlx::query(
        "INSERT INTO sync_account_key_certificates (account_id, certificate)
        VALUES ($1, $2)",
    )
    .bind(account)
    .bind(verified.device_certificate_cbor())
    .execute(&mut **transaction)
    .await
    .map_err(map_unique_to_denied)?;
    sqlx::query(
        "INSERT INTO identity_devices
        (device_id, account_id, certificate, active, created_at_ms)
        VALUES ($1, $2, $3, TRUE, $4)",
    )
    .bind(device)
    .bind(account)
    .bind(verified.device_certificate_cbor())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(map_unique_to_denied)?;
    sqlx::query("INSERT INTO sync_vaults (vault_id, kind) VALUES ($1, 'personal')")
        .bind(vault)
        .execute(&mut **transaction)
        .await
        .map_err(map_unique_to_denied)?;
    sqlx::query(
        "INSERT INTO sync_personal_vaults
        (account_id, vault_id, wrapped_vault_key) VALUES ($1, $2, $3)",
    )
    .bind(account)
    .bind(vault)
    .bind(verified.wrapped_personal_vault_key())
    .execute(&mut **transaction)
    .await
    .map_err(map_unique_to_denied)?;
    check_postgres_key_response_capacity(transaction, receipt.account_id).await?;
    Ok(())
}
