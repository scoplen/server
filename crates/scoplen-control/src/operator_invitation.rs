// SPDX-License-Identifier: AGPL-3.0-only
//! Deployment-only invitation authorization; identity state is supplied by the durable store.

use std::str::FromStr as _;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema, ValidationMode,
    Validator,
};
use scoplen_api::control_plane::{BUILT_IN_POLICIES, CEDAR_SCHEMA};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
#[error("deployment authorization could not be evaluated")]
pub struct OperatorPolicyError;

/// Uses the published schema and built-in policies, validated once at listener construction.
pub struct OperatorInvitationPolicy {
    schema: Schema,
    policies: PolicySet,
}

impl OperatorInvitationPolicy {
    /// # Errors
    /// Returns a safe error if the published schema or policies cannot be validated.
    pub fn new() -> Result<Self, OperatorPolicyError> {
        let schema = Schema::from_str(CEDAR_SCHEMA).map_err(|_| OperatorPolicyError)?;
        let policies = PolicySet::from_str(BUILT_IN_POLICIES).map_err(|_| OperatorPolicyError)?;
        if Validator::new(schema.clone())
            .validate(&policies, ValidationMode::Strict)
            .validation_errors()
            .next()
            .is_some()
        {
            return Err(OperatorPolicyError);
        }
        Ok(Self { schema, policies })
    }

    /// Authorize only the singleton deployment action using current, authenticated status.
    ///
    /// # Errors
    /// Rejects invalid Operator identifiers and any failed Cedar evaluation.
    pub fn allows_personal_invitation(
        &self,
        operator_id: Uuid,
        active: bool,
    ) -> Result<bool, OperatorPolicyError> {
        if operator_id.get_version_num() != 7 || operator_id.get_variant() != uuid::Variant::RFC4122
        {
            return Err(OperatorPolicyError);
        }
        let id = operator_id.to_string();
        let principal: EntityUid =
            format!("Operator::\"{id}\"").parse().map_err(|_| OperatorPolicyError)?;
        let action =
            r#"Action::"issuePersonalInvitation""#.parse().map_err(|_| OperatorPolicyError)?;
        let resource = r#"Deployment::"self""#.parse().map_err(|_| OperatorPolicyError)?;
        let request =
            Request::new(principal, action, resource, Context::empty(), Some(&self.schema))
                .map_err(|_| OperatorPolicyError)?;
        let entities = Entities::from_json_value(
            serde_json::json!([
                {
                    "uid": {"type": "Operator", "id": id},
                    "attrs": {"status": if active { "active" } else { "revoked" }},
                    "parents": []
                },
                {"uid": {"type": "Deployment", "id": "self"}, "attrs": {}, "parents": []}
            ]),
            Some(&self.schema),
        )
        .map_err(|_| OperatorPolicyError)?;
        let response = Authorizer::new().is_authorized(&request, &self.policies, &entities);
        if response.diagnostics().errors().next().is_some() {
            return Err(OperatorPolicyError);
        }
        Ok(response.decision() == Decision::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_policy_allows_only_active_operator() {
        let policy = OperatorInvitationPolicy::new().expect("canonical policy");
        let id = Uuid::now_v7();
        assert!(policy.allows_personal_invitation(id, true).expect("active"));
        assert!(!policy.allows_personal_invitation(id, false).expect("revoked"));
        assert!(policy.allows_personal_invitation(Uuid::nil(), true).is_err());
    }
}
