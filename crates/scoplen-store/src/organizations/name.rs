// SPDX-License-Identifier: AGPL-3.0-only
//! D-134 name settings through the current Organization Cedar boundary.

use cedar_policy::{Context, Decision, Entities, EntityUid, PolicySet, Request};
use scoplen_api::{
    control_plane::{OrganizationAuthorizationContext, OrganizationAuthorizer},
    organization::{
        OrganizationUpdateRequest, parse_organization_idempotency_key, parse_organization_if_match,
    },
};

use sqlx::Row;

use super::{
    CurrentPrincipal, OrganizationResource, OrganizationStoreError, PostgresStore, SqliteStore,
    Uuid, append_audit_event_in_postgres_transaction, append_audit_event_in_transaction,
    check_identity, lock_postgres, lock_sqlite, now_ms, postgres_principal, sqlite_principal,
};

fn name_authorization(
    expected: &CurrentPrincipal,
    organization: Uuid,
    value: &OrganizationResource,
    membership_status: &str,
    now: i64,
) -> Result<(OrganizationAuthorizationContext, Request, Entities), OrganizationStoreError> {
    let account = Uuid::from_bytes(expected.account_id);
    let trusted = OrganizationAuthorizationContext::new(
        account,
        organization,
        value.membership.id,
        now.div_euclid(1000),
    )
    .map_err(|_| OrganizationStoreError::StorageUnavailable)?;
    let reference =
        |kind: &str, id: Uuid| serde_json::json!({"__entity":{"type":kind,"id":id.to_string()}});
    let context = Context::from_json_value(
        serde_json::json!({
            "organization": reference("Organization", organization),
            "membership": reference("Membership", value.membership.id),
            "now": now.div_euclid(1000),
        }),
        None,
    )
    .map_err(|_| OrganizationStoreError::StorageUnavailable)?;
    let uid = |kind: &str, id: Uuid| {
        format!("{kind}::\"{id}\"")
            .parse::<EntityUid>()
            .map_err(|_| OrganizationStoreError::StorageUnavailable)
    };
    let request = Request::new(
        uid("Account", account)?,
        "Action::\"manage_organization\""
            .parse::<EntityUid>()
            .map_err(|_| OrganizationStoreError::StorageUnavailable)?,
        uid("Organization", organization)?,
        context,
        None,
    )
    .map_err(|_| OrganizationStoreError::StorageUnavailable)?;
    // The Account predicate comes only from transaction-current principal verification.
    // Groups and custom policies have no production storage in this first Organization route.
    let entities = Entities::from_json_value(
        serde_json::json!([
            {"uid":{"type":"Account","id":account},"attrs":{"status":"active"},"parents":[]},
            {"uid":{"type":"Organization","id":value.id},"attrs":{"name":value.name},"parents":[]},
            {"uid":{"type":"Membership","id":value.membership.id},"attrs":{
                "account":reference("Account",value.membership.account_id),
                "organization":reference("Organization",value.id),
                "status":membership_status,"roles":value.membership.roles,"groups":[],
            },"parents":[]},
        ]),
        None,
    )
    .map_err(|_| OrganizationStoreError::StorageUnavailable)?;
    Ok((trusted, request, entities))
}

fn authorize_name_change(
    expected: &CurrentPrincipal,
    organization: Uuid,
    value: &OrganizationResource,
    membership_status: &str,
    now: i64,
) -> Result<(), OrganizationStoreError> {
    let (trusted, request, entities) =
        name_authorization(expected, organization, value, membership_status, now)?;
    let authorizer = OrganizationAuthorizer::new(organization, &PolicySet::new())
        .map_err(|_| OrganizationStoreError::StorageUnavailable)?;
    match authorizer.authorize(&trusted, &request, &entities) {
        Ok(Decision::Allow) => Ok(()),
        Ok(Decision::Deny) => Err(OrganizationStoreError::PermissionDenied),
        Err(_) => Err(OrganizationStoreError::StorageUnavailable),
    }
}

macro_rules! name_settings {
    ($store:ty, $begin:literal, $lock:ident, $principal:ident, $audit:ident, $postgres:literal) => {
        impl $store {
            /// Update only the name after current tenant/Cedar authorization and exact If-Match.
            /// The caller must verify the original token's `orgs:write` scope and `DPoP` first;
            /// its immutable scope and expiry are not replaced by current discovery metadata.
            ///
            /// # Errors
            /// Returns a fixed authentication, permission, precondition, storage or
            /// uncertain-update class. An uncertain update must not be replayed automatically.
            pub async fn update_organization(
                &self,
                expected: &CurrentPrincipal,
                expires_at: u64,
                organization: Uuid,
                if_match: &str,
                request: &OrganizationUpdateRequest,
            ) -> Result<OrganizationResource, OrganizationStoreError> {
                parse_organization_idempotency_key(&organization.to_string())
                    .map_err(|_| OrganizationStoreError::InvalidRequest)?;
                parse_organization_if_match(Some(if_match))
                    .map_err(|_| OrganizationStoreError::InvalidRequest)?;
                request.validate().map_err(|_| OrganizationStoreError::InvalidRequest)?;
                let mut tx = self.pool.begin_with($begin).await?;
                $lock(&mut tx, &expected.account_id, false).await?;
                check_identity($principal(&mut tx, expected.device_id).await?, expected, expires_at)?;
                let suffix = if $postgres { " FOR UPDATE OF o,m" } else { "" };
                let query = format!("SELECT m.status,o.updated_at_ms FROM organizations o JOIN organization_memberships m ON m.organization_id=o.id WHERE o.id=$1 AND m.account_id=$2{suffix}");
                let row = sqlx::query(&query)
                    .bind(organization.as_bytes().as_slice())
                    .bind(expected.account_id.as_slice())
                    .fetch_optional(&mut *tx).await?
                    .ok_or(OrganizationStoreError::NotFound)?;
                let status: String = row.try_get("status")?;
                if status != "active" {
                    return Err(OrganizationStoreError::NotFound);
                }
                let current = Self::read_organization_in_transaction(
                    &mut tx, &expected.account_id, organization.as_bytes(),
                ).await?;
                let now = now_ms()?;
                authorize_name_change(expected, organization, &current, &status, now)?;
                if current.etag != if_match {
                    return Err(OrganizationStoreError::PreconditionFailed);
                }
                if current.name == request.name {
                    check_identity($principal(&mut tx, expected.device_id).await?, expected, expires_at)?;
                    tx.commit().await?;
                    return Ok(current);
                }
                let updated_at = now.max(row.try_get("updated_at_ms")?);
                sqlx::query("UPDATE organizations SET name=$1,updated_at_ms=$2 WHERE id=$3")
                    .bind(&request.name).bind(updated_at)
                    .bind(organization.as_bytes().as_slice()).execute(&mut *tx).await?;
                let event = serde_json::to_vec(&serde_json::json!({
                    "action":"organization.name_updated", "account_id":Uuid::from_bytes(expected.account_id),
                    "device_id":Uuid::from_bytes(expected.device_id),"organization_id":organization,
                    "membership_id":current.membership.id,"updated_at_ms":updated_at,
                })).map_err(|_| OrganizationStoreError::StorageUnavailable)?;
                $audit(&mut tx,organization.into_bytes(),&event,now).await
                    .map_err(|_| OrganizationStoreError::StorageUnavailable)?;
                let value = Self::read_organization_in_transaction(
                    &mut tx, &expected.account_id, organization.as_bytes(),
                ).await?;
                check_identity($principal(&mut tx, expected.device_id).await?, expected, expires_at)?;
                tx.commit().await.map_err(|_| OrganizationStoreError::UpdateCommitOutcomeUnknown)?;
                Ok(value)
            }
        }
    };
}

name_settings!(
    SqliteStore,
    "BEGIN IMMEDIATE",
    lock_sqlite,
    sqlite_principal,
    append_audit_event_in_transaction,
    false
);
name_settings!(
    PostgresStore,
    "BEGIN",
    lock_postgres,
    postgres_principal,
    append_audit_event_in_postgres_transaction,
    true
);

#[cfg(test)]
mod tests {
    use super::super::OrganizationMembership;
    use super::*;

    fn fixture() -> (CurrentPrincipal, OrganizationResource) {
        let account = Uuid::now_v7();
        let principal = CurrentPrincipal {
            account_id: account.into_bytes(),
            device_id: Uuid::now_v7().into_bytes(),
            signing_public_key: Vec::new(),
            jkt: "unit-fixture".into(),
            certificate: Vec::new(),
        };
        let value = OrganizationResource {
            id: Uuid::now_v7(),
            etag: "\"fixture\"".into(),
            created_at: "2026-10-26T00:00:00Z".into(),
            updated_at: "2026-10-26T00:00:00Z".into(),
            name: "Operations".into(),
            membership: OrganizationMembership {
                id: Uuid::now_v7(),
                account_id: account,
                roles: vec!["owner".into()],
            },
        };
        (principal, value)
    }

    #[test]
    fn production_name_authorizer_uses_cedar_roles_in_the_current_membership() {
        let (principal, mut value) = fixture();
        for role in ["owner", "administrator"] {
            value.membership.roles = vec![role.into()];
            authorize_name_change(&principal, value.id, &value, "active", 1_000)
                .expect("permitted role");
        }
        for role in ["member", "security_auditor", "approver", "future_role"] {
            value.membership.roles = vec![role.into()];
            assert_eq!(
                authorize_name_change(&principal, value.id, &value, "active", 1_000),
                Err(OrganizationStoreError::PermissionDenied)
            );
        }
    }

    #[test]
    fn name_loader_and_mandatory_guards_reject_foreign_or_inactive_entities_even_with_permit_all() {
        let (principal, original) = fixture();
        let policy: PolicySet = "permit(principal,action,resource);".parse().expect("test policy");
        let authorizer =
            OrganizationAuthorizer::new(original.id, &policy).expect("canonical guards");
        for case in 0..3 {
            let mut value = original.clone();
            if case == 0 {
                value.membership.account_id = Uuid::now_v7();
            }
            if case == 1 {
                value.id = Uuid::now_v7();
            }
            let status = if case == 2 { "suspended" } else { "active" };
            let (trusted, request, entities) =
                name_authorization(&principal, original.id, &value, status, 1_000)
                    .expect("same production graph constructor");
            assert!(!matches!(
                authorizer.authorize(&trusted, &request, &entities),
                Ok(Decision::Allow)
            ));
        }
    }
}
