// SPDX-License-Identifier: AGPL-3.0-only
//! Digest-only possession challenges, consumed only inside the owning business transaction.

use std::net::IpAddr;

use scoplen_api::account_admission::{
    ACCOUNT_ATTEMPT_LIFETIME_MS, AccountRequestChallengeRequest, AccountRequestChallengeResponse,
    AccountRequestIntent, AccountRequestKind,
};
use scoplen_crypto::{DpopTarget, SecretBytes};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row, Sqlite, Transaction};
use zeroize::Zeroizing;

use crate::{
    PostgresStore, RelationalStore, SqliteStore,
    account_entry_admission::{
        AccountEntryAdmissionDecision, AccountEntryEndpoint, AccountEntryFailureReason,
        AccountEntryPrivateBucket, AccountEntryStateError,
        admit_postgres_account_entry_private_in_transaction,
        admit_sqlite_account_entry_private_in_transaction,
        audit_postgres_account_entry_failure_in_transaction,
        audit_sqlite_account_entry_failure_in_transaction, postgres_account_entry_now,
        sqlite_account_entry_now, valid_id,
    },
};

const CHALLENGE_CAPACITY: i64 = 16_384;

/// A staged consumption. Dropping this value does not commit the caller's transaction.
///
/// A false nonce match permits only a denial. A true match is not proof verification:
/// callers still verify the fresh Device signature and all protected bindings before success.
pub struct ClaimedAccountRequestChallenge {
    kind: AccountRequestKind,
    intent: AccountRequestIntent,
    expires_at_ms: i64,
    nonce_matches: bool,
    bindings_match: bool,
}

impl ClaimedAccountRequestChallenge {
    /// Compare the supplied nonce with the retained digest before verifying possession.
    #[must_use]
    pub fn nonce_matches(&self) -> bool {
        self.nonce_matches
    }

    /// All retained origin/kind/intent/operation/Device bindings match this submission.
    #[must_use]
    pub fn bindings_match(&self) -> bool {
        self.bindings_match
    }
}

impl std::fmt::Debug for ClaimedAccountRequestChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClaimedAccountRequestChallenge([REDACTED])")
    }
}

/// Terminal outcome established by the trusted transaction coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountRequestChallengeOutcome {
    /// Includes invalid nonce, signature or protected binding; appends mandatory denial audit.
    Denied,
    /// Requires verified possession and a newly staged complete Account/Device mutation.
    Committed,
    /// Requires verified original keys and an exact retained receipt; emits no duplicate audit.
    TerminalConfirmation,
}

fn digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(value);
    hash.finalize().into()
}

fn binding(
    origin: &str,
    request: &AccountRequestChallengeRequest,
) -> Result<([u8; 32], i64, i64), AccountEntryStateError> {
    DpopTarget::new("POST", origin, "/api/v1/auth/accounts/requests/challenge")
        .map_err(|_| AccountEntryStateError::InvalidInput)?;
    valid_id(request.operation_id)?;
    valid_id(request.device_id)?;
    let kind = match request.kind {
        AccountRequestKind::Register => 1,
        AccountRequestKind::Admit => 2,
    };
    let intent = match request.intent {
        AccountRequestIntent::Submit => 1,
        AccountRequestIntent::Confirm => 2,
    };
    Ok((digest(b"spl-account-request-origin-v1", origin.as_bytes()), kind, intent))
}

async fn sqlite_begin(store: &SqliteStore) -> Result<Transaction<'_, Sqlite>, sqlx::Error> {
    store.pool().begin_with("BEGIN IMMEDIATE").await
}
async fn postgres_begin(store: &PostgresStore) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    store.pool().begin().await
}

macro_rules! challenge_store {
    ($store:ty,$db:ty,$begin:expr,$now:ident,$admit:ident,$audit:ident,$claim:ident,$finish:ident,$append:path) => {
        impl $store {
            /// Issue an independent random attempt and nonce after source admission by HTTP.
            /// Charges decoded Device debt, without querying identity existence. Capacity,
            /// durable time, digest persistence and complete response preflight share one tx.
            /// # Errors
            /// A rate denial is audited before returning; uncertain writes disclose no secret.
            pub async fn issue_account_request_challenge(&self,source:IpAddr,trusted_origin:&str,
                request:&AccountRequestChallengeRequest)->Result<AccountRequestChallengeResponse,AccountEntryStateError> {
                let (origin,kind,intent)=binding(trusted_origin,request)?;
                let mut tx=$begin(self).await?;
                let decision=$admit(&mut tx,AccountEntryEndpoint::RequestChallenge,
                    AccountEntryPrivateBucket::DecodedDevice(request.device_id)).await?;
                let count:i64=sqlx::query_scalar("SELECT challenge_rows FROM account_entry_state WHERE singleton=1")
                    .fetch_one(&mut *tx).await?;
                if !(0..=CHALLENGE_CAPACITY).contains(&count){return Err(AccountEntryStateError::Integrity);}
                let wait=match decision {
                    AccountEntryAdmissionDecision::RateLimited(wait)=>Some(wait),
                    AccountEntryAdmissionDecision::Admitted if count==CHALLENGE_CAPACITY=>Some(1),
                    AccountEntryAdmissionDecision::Admitted=>None,
                };
                if let Some(wait)=wait {
                    $audit(&mut tx,AccountEntryEndpoint::RequestChallenge,source,AccountEntryFailureReason::RateLimited,&[]).await?;
                    tx.commit().await?;
                    return Err(AccountEntryStateError::RateLimited(wait));
                }
                let mut attempt=Zeroizing::new([0;32]);
                let mut nonce=Zeroizing::new([0;32]);
                // Independent entropy draws, with no use of Account ids or other credentials.
                getrandom::fill(&mut *attempt).map_err(|_|AccountEntryStateError::Entropy)?;
                getrandom::fill(&mut *nonce).map_err(|_|AccountEntryStateError::Entropy)?;
                let now=$now(&mut tx).await?;
                let lifetime=i64::try_from(ACCOUNT_ATTEMPT_LIFETIME_MS).map_err(|_|AccountEntryStateError::Clock)?;
                let expires=now.checked_add(lifetime).ok_or(AccountEntryStateError::Clock)?;
                let response=AccountRequestChallengeResponse{attempt_id:SecretBytes::new(*attempt),nonce:SecretBytes::new(*nonce),expires_at_ms:u64::try_from(expires).map_err(|_|AccountEntryStateError::Clock)?};
                let _encoded=Zeroizing::new(response.to_json().map_err(|_|AccountEntryStateError::Integrity)?);
                let attempt_digest=digest(b"spl-account-request-attempt-v1",response.attempt_id.as_ref());
                let nonce_digest=digest(b"spl-account-request-nonce-v1",response.nonce.as_ref());
                let inserted=sqlx::query("INSERT INTO account_request_challenges (attempt_digest,nonce_digest,origin_digest,kind,intent,operation_id,device_id,issued_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
                    .bind(attempt_digest.as_slice()).bind(nonce_digest.as_slice()).bind(origin.as_slice())
                    .bind(kind).bind(intent).bind(request.operation_id.as_bytes().as_slice())
                    .bind(request.device_id.as_bytes().as_slice()).bind(now).bind(expires).execute(&mut *tx).await?.rows_affected();
                if inserted!=1 {return Err(AccountEntryStateError::Integrity);}
                if sqlx::query("UPDATE account_entry_state SET challenge_rows=challenge_rows+1 WHERE singleton=1")
                    .execute(&mut *tx).await?.rows_affected()!=1 {return Err(AccountEntryStateError::Integrity);}
                if $now(&mut tx).await?>=expires {return Err(AccountEntryStateError::ChallengeExpired);}
                tx.commit().await?;
                Ok(response)
            }
        }

        /// Claim a live challenge by its attempt digest in the owning transaction.
        /// Structural decoding must already have completed; this never verifies Device proof.
        /// Wrong canonical bindings or nonce still return a staged claim, which must finish
        /// as an audited denial. They never leave a live challenge available for another guess.
        /// Source/decoded Device admission must precede this call. SQLite requires BEGIN IMMEDIATE.
        /// # Errors
        /// Any error requires rollback. A later rate rejection must also roll back this claim.
        pub async fn $claim(tx:&mut Transaction<'_,$db>,trusted_origin:&str,request:&AccountRequestChallengeRequest,
            attempt:&[u8;32],nonce:&[u8;32])->Result<Option<ClaimedAccountRequestChallenge>,AccountEntryStateError> {
            let (origin,kind,intent)=binding(trusted_origin,request)?;
            let now=$now(tx).await?;
            let attempt=digest(b"spl-account-request-attempt-v1",attempt);
            let row=sqlx::query("SELECT nonce_digest,origin_digest,kind,intent,operation_id,device_id,issued_at_ms,expires_at_ms FROM account_request_challenges WHERE attempt_digest=$1")
                .bind(attempt.as_slice())
                .fetch_optional(&mut **tx).await?;
            let Some(row)=row else{return Ok(None);};
            let issued:i64=row.try_get("issued_at_ms")?;
            let expires:i64=row.try_get("expires_at_ms")?;
            let retained:Vec<u8>=row.try_get("nonce_digest")?;
            let retained_origin:Vec<u8>=row.try_get("origin_digest")?;
            let retained_kind:i64=row.try_get("kind")?;
            let retained_intent:i64=row.try_get("intent")?;
            let operation:Vec<u8>=row.try_get("operation_id")?;
            let device:Vec<u8>=row.try_get("device_id")?;
            if issued<=0 || issued.checked_add(120_000)!=Some(expires) || retained.len()!=32 {
                return Err(AccountEntryStateError::Integrity);
            }
            if retained_origin.len()!=32 || operation.len()!=16 || device.len()!=16
                || !(1..=2).contains(&retained_kind) || !(1..=2).contains(&retained_intent) {
                return Err(AccountEntryStateError::Integrity);
            }
            if now<issued || now>=expires{return Ok(None);}
            let supplied=SecretBytes::new(digest(b"spl-account-request-nonce-v1",nonce));
            let retained=SecretBytes::<32>::from_slice(&retained).ok_or(AccountEntryStateError::Integrity)?;
            if sqlx::query("DELETE FROM account_request_challenges WHERE attempt_digest=$1")
                .bind(attempt.as_slice()).execute(&mut **tx).await?.rows_affected()!=1 {return Err(AccountEntryStateError::Integrity);}
            if sqlx::query("UPDATE account_entry_state SET challenge_rows=challenge_rows-1 WHERE singleton=1")
                .execute(&mut **tx).await?.rows_affected()!=1 {return Err(AccountEntryStateError::Integrity);}
            Ok(Some(ClaimedAccountRequestChallenge{
                kind:if retained_kind==1 {AccountRequestKind::Register}else{AccountRequestKind::Admit},
                intent:if retained_intent==1 {AccountRequestIntent::Submit}else{AccountRequestIntent::Confirm},
                expires_at_ms:expires,nonce_matches:retained==supplied,
                bindings_match:retained_origin.as_slice()==origin.as_slice() && retained_kind==kind && retained_intent==intent
                    && operation.as_slice()==request.operation_id.as_bytes().as_slice()
                    && device.as_slice()==request.device_id.as_bytes().as_slice(),
            }))
        }

        /// Finish staged consumption with a mandatory fixed audit, or an exact receipt exception.
        /// For successful outcomes the caller must first verify the Device proof and all Account
        /// signatures/bindings. Confirmation additionally requires its exact original receipt.
        /// Apply admission cooldown/success changes in this same tx before this final check.
        /// Commit immediately after this call; no awaited business work may follow it.
        /// # Errors
        /// Expiry requires rollback of all staged business state, followed by a separately
        /// committed generic denial audit before reporting denial. Never disclose a receipt.
        pub async fn $finish(tx:&mut Transaction<'_,$db>,claim:ClaimedAccountRequestChallenge,
            outcome:AccountRequestChallengeOutcome)->Result<i64,AccountEntryStateError> {
            let now=$now(tx).await?;
            if now>=claim.expires_at_ms{return Err(AccountEntryStateError::ChallengeExpired);}
            if outcome!=AccountRequestChallengeOutcome::Denied && (!claim.nonce_matches || !claim.bindings_match) {
                return Err(AccountEntryStateError::InvalidInput);
            }
            match (claim.intent,outcome) {
                (AccountRequestIntent::Submit,AccountRequestChallengeOutcome::TerminalConfirmation)
                | (AccountRequestIntent::Confirm,AccountRequestChallengeOutcome::Committed)=>return Err(AccountEntryStateError::InvalidInput),
                _=>(),
            }
            if outcome!=AccountRequestChallengeOutcome::TerminalConfirmation {
                let mut event=b"spl-account-request-outcome-v1".to_vec();
                event.extend_from_slice(&[match claim.kind {AccountRequestKind::Register=>1,AccountRequestKind::Admit=>2},
                    match claim.intent {AccountRequestIntent::Submit=>1,AccountRequestIntent::Confirm=>2},
                    u8::from(outcome==AccountRequestChallengeOutcome::Committed)]);
                event.extend_from_slice(&now.to_be_bytes());
                $append(tx,&event,now).await?;
            }
            let final_now=$now(tx).await?;
            if final_now>=claim.expires_at_ms{return Err(AccountEntryStateError::ChallengeExpired);}
            Ok(final_now)
        }
    };
}

challenge_store!(
    SqliteStore,
    Sqlite,
    sqlite_begin,
    sqlite_account_entry_now,
    admit_sqlite_account_entry_private_in_transaction,
    audit_sqlite_account_entry_failure_in_transaction,
    claim_sqlite_account_request_challenge_in_transaction,
    finish_sqlite_account_request_challenge_in_transaction,
    crate::append_deployment_audit_event_in_transaction
);
challenge_store!(
    PostgresStore,
    Postgres,
    postgres_begin,
    postgres_account_entry_now,
    admit_postgres_account_entry_private_in_transaction,
    audit_postgres_account_entry_failure_in_transaction,
    claim_postgres_account_request_challenge_in_transaction,
    finish_postgres_account_request_challenge_in_transaction,
    crate::append_deployment_audit_event_in_postgres_transaction
);
