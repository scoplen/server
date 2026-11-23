// SPDX-License-Identifier: AGPL-3.0-only
//! Historical body metadata is optional; stored transport metadata is mandatory.

use std::fmt;

use scoplen_api::audit::{
    AuditCategory, AuditEvent, AuditOutcome, AuditResource, AuditResourceKind,
    format_audit_timestamp,
};
use scoplen_model::{ObjectType, validate_uuid_v7};
use serde::{Deserialize, Deserializer, de};
use serde_json::{Map, Value};
use uuid::Uuid;

use super::Error;

pub(super) fn project(
    organization_id: Uuid,
    sequence: i64,
    previous_hash: Vec<u8>,
    event_hash: Vec<u8>,
    created_at_ms: i64,
    bytes: Option<&[u8]>,
) -> Result<AuditEvent, Error> {
    let mut event = AuditEvent {
        organization_id,
        sequence: u64::try_from(sequence).map_err(|_| Error::StorageUnavailable)?,
        occurred_at: format_audit_timestamp(created_at_ms)
            .map_err(|_| Error::StorageUnavailable)?,
        category: AuditCategory::Unknown,
        event_class: None,
        outcome: AuditOutcome::Unknown,
        actor_account_id: None,
        actor_device_id: None,
        actor_browser_family_id: None,
        resource: None,
        previous_hash: previous_hash.try_into().map_err(|_| Error::StorageUnavailable)?,
        event_hash: event_hash.try_into().map_err(|_| Error::StorageUnavailable)?,
    };
    event.validate().map_err(|_| Error::StorageUnavailable)?;
    let Some(Value::Object(fields)) = bytes
        .and_then(|bytes| serde_json::from_slice::<UniqueValue>(bytes).ok())
        .map(|value| value.0)
    else {
        return Ok(event);
    };
    if let Some(class) = fields.get("action").and_then(Value::as_str) {
        event.event_class = Some(class.to_owned());
        if event.validate().is_err() {
            event.event_class = None;
        }
    }
    let classified = classification(event.event_class.as_deref());
    event.outcome = match fields.get("outcome") {
        Some(Value::String(value)) => value.parse().unwrap_or(AuditOutcome::Unknown),
        None if classified.is_some() => AuditOutcome::Success,
        _ => AuditOutcome::Unknown,
    };
    if let Some((category, resource_field, resource_kind, actor_kind)) = classified {
        event.category = category;
        let kind = resource_kind.or_else(|| inventory_kind(&fields));
        event.resource = kind
            .zip(recorded_id(&fields, resource_field))
            .map(|(kind, id)| AuditResource { kind, id });
        if actor_kind != ActorKind::System {
            let device = recorded_id(&fields, "device_id");
            let browser = recorded_id(&fields, "browser_family_id");
            if device.is_none() || browser.is_none() {
                event.actor_account_id = recorded_id(&fields, "account_id");
                event.actor_device_id = device;
                if actor_kind == ActorKind::Either {
                    event.actor_browser_family_id = browser;
                }
            }
        }
    }
    event.to_json().map_err(|_| Error::StorageUnavailable)?;
    Ok(event)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ActorKind {
    Either,
    Device,
    System,
}

fn classification(
    class: Option<&str>,
) -> Option<(AuditCategory, &'static str, Option<AuditResourceKind>, ActorKind)> {
    use AuditCategory::{AccountChange, Authorization, Scoplen};
    use AuditResourceKind as Kind;
    let (category, field, kind, actor) = match class? {
        "organization.created" | "organization.name_updated" | "organization.dissolved" => {
            (AccountChange, "organization_id", Some(Kind::Organization), ActorKind::Either)
        }
        "organization.invitation_created"
        | "organization.invitation_accepted"
        | "organization.invitation_revoked" => {
            (AccountChange, "target_id", Some(Kind::Invitation), ActorKind::Either)
        }
        "organization.member_updated" | "organization.member_removed" => {
            (AccountChange, "target_id", Some(Kind::Membership), ActorKind::Either)
        }
        "organization.inventory_created"
        | "organization.inventory_updated"
        | "organization.inventory_deleted" => (Scoplen, "object_id", None, ActorKind::Either),
        "organization.groups_created"
        | "organization.groups_updated"
        | "organization.groups_deleted" => {
            (AccountChange, "object_id", Some(Kind::Group), ActorKind::Either)
        }
        "organization.policies_created"
        | "organization.policies_updated"
        | "organization.policies_deleted" => {
            (Authorization, "object_id", Some(Kind::Policy), ActorKind::Either)
        }
        "organization.user_ca_created" => {
            (Authorization, "authority_id", Some(Kind::CertificateAuthority), ActorKind::Device)
        }
        "organization.grants_created"
        | "organization.grants_updated"
        | "organization.grants_deleted" => {
            (Authorization, "object_id", Some(Kind::Grant), ActorKind::Either)
        }
        "organization.access_request_created"
        | "organization.access_request_approved"
        | "organization.access_request_denied"
        | "organization.access_request_cancelled" => {
            (Authorization, "request_id", Some(Kind::AccessRequest), ActorKind::Either)
        }
        "organization.access_request_expired" => {
            (Authorization, "request_id", Some(Kind::AccessRequest), ActorKind::System)
        }
        "organization.auth_draft_created"
        | "organization.auth_draft_cancelled"
        | "organization.auth_draft_test_started"
        | "organization.auth_draft_test_finished" => {
            (Scoplen, "generation", Some(Kind::AuthConnectionDraft), ActorKind::Either)
        }
        "organization.user_ca_krl_activated" => {
            (Authorization, "authority_id", Some(Kind::CertificateAuthority), ActorKind::System)
        }
        "organization.certificate_issued" => {
            (Authorization, "certificate_id", Some(Kind::Certificate), ActorKind::Device)
        }
        _ => return None,
    };
    Some((category, field, kind, actor))
}

fn recorded_id(fields: &Map<String, Value>, name: &str) -> Option<Uuid> {
    let text = fields.get(name)?.as_str()?;
    let id = Uuid::parse_str(text).ok()?;
    (id.to_string() == text && validate_uuid_v7(id).is_ok()).then_some(id)
}

fn inventory_kind(fields: &Map<String, Value>) -> Option<AuditResourceKind> {
    let kind = ObjectType::from_wire(fields.get("object_type")?.as_u64()?).ok()?;
    Some(match kind {
        ObjectType::HOST => AuditResourceKind::Host,
        ObjectType::HOST_GROUP => AuditResourceKind::HostGroup,
        ObjectType::ACCESS_PROFILE => AuditResourceKind::AccessProfile,
        ObjectType::ROUTE => AuditResourceKind::Route,
        ObjectType::TRUST_RECORD => AuditResourceKind::TrustRecord,
        ObjectType::SNIPPET => AuditResourceKind::Snippet,
        ObjectType::GATEWAY_NETWORK => AuditResourceKind::GatewayNetwork,
        _ => return None,
    })
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Value;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON without duplicate object names")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
                Ok(Value::Bool(value))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
                Ok(Value::Number(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
                Ok(Value::Number(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .ok_or_else(|| E::custom("invalid JSON number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
                Ok(Value::String(value.into()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(Value::Array(values))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut object: A) -> Result<Value, A::Error> {
                let mut values = Map::new();
                while let Some(name) = object.next_key::<String>()? {
                    if values.contains_key(&name) {
                        return Err(de::Error::custom("duplicate JSON name"));
                    }
                    values.insert(name, object.next_value::<UniqueValue>()?.0);
                }
                Ok(Value::Object(values))
            }
        }
        deserializer.deserialize_any(Visitor).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn id(value: u8) -> Uuid {
        Uuid::from_bytes([1, 2, 3, 4, 5, 6, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, value])
    }

    fn from_bytes(bytes: &[u8]) -> AuditEvent {
        project(id(1), 7, vec![4; 32], vec![5; 32], 1_730_000_000_001, Some(bytes))
            .expect("safe projection")
    }

    #[test]
    fn historical_bodies_never_replace_immutable_transport_or_leak_payload() {
        let bodies: &[&[u8]] = &[
            b"not JSON",
            b"[{}]",
            b"\xef\xbb\xbf{}",
            b"{\"action\":\"organization.created\",\"action\":\"organization.created\"}",
            b"{\"action\":\"organization.created\",\"extension\":[{\"x\":1,\"x\":2}]}",
            b"{\"action\":\"organization.created\",\"extension\":\"\xff\"}",
        ];
        for body in bodies {
            let event = from_bytes(body);
            assert_eq!(event.organization_id, id(1));
            assert_eq!(event.sequence, 7);
            assert_eq!(event.previous_hash, [4; 32]);
            assert_eq!(event.event_hash, [5; 32]);
            assert_eq!(event.category, AuditCategory::Unknown);
            assert_eq!(event.outcome, AuditOutcome::Unknown);
            assert!(event.event_class.is_none());
            assert!(event.actor_account_id.is_none());
            assert!(event.actor_device_id.is_none());
            assert!(event.actor_browser_family_id.is_none());
            assert!(event.resource.is_none());
        }
        let event = from_bytes(
            &serde_json::to_vec(&json!({"action":"legacy.unknown","account_id":id(2),
                "device_id":id(3),"outcome":"failure","password":"private marker"}))
            .expect("body"),
        );
        assert_eq!(event.event_class.as_deref(), Some("legacy.unknown"));
        assert_eq!(event.outcome, AuditOutcome::Failure);
        assert!(event.actor_account_id.is_none());
        assert!(event.actor_device_id.is_none());
        assert!(
            !String::from_utf8(event.to_json().expect("wire"))
                .expect("text")
                .contains("private marker")
        );
    }

    #[test]
    fn registered_producers_project_recorded_targets_without_current_lookups() {
        for (action, field, category, kind) in [
            (
                "organization.created",
                "organization_id",
                AuditCategory::AccountChange,
                AuditResourceKind::Organization,
            ),
            (
                "organization.invitation_accepted",
                "target_id",
                AuditCategory::AccountChange,
                AuditResourceKind::Invitation,
            ),
            (
                "organization.member_removed",
                "target_id",
                AuditCategory::AccountChange,
                AuditResourceKind::Membership,
            ),
            (
                "organization.inventory_deleted",
                "object_id",
                AuditCategory::Scoplen,
                AuditResourceKind::Host,
            ),
            (
                "organization.groups_updated",
                "object_id",
                AuditCategory::AccountChange,
                AuditResourceKind::Group,
            ),
            (
                "organization.policies_created",
                "object_id",
                AuditCategory::Authorization,
                AuditResourceKind::Policy,
            ),
            (
                "organization.user_ca_created",
                "authority_id",
                AuditCategory::Authorization,
                AuditResourceKind::CertificateAuthority,
            ),
            (
                "organization.certificate_issued",
                "certificate_id",
                AuditCategory::Authorization,
                AuditResourceKind::Certificate,
            ),
        ] {
            let mut fields = json!({"action":action,"account_id":id(2),"device_id":id(3),
                "object_type":ObjectType::HOST.to_wire()});
            fields[field] = json!(id(4));
            let event = from_bytes(&serde_json::to_vec(&fields).expect("body"));
            assert_eq!(event.category, category);
            assert_eq!(event.outcome, AuditOutcome::Success);
            assert_eq!(event.actor_account_id, Some(id(2)));
            assert_eq!(event.actor_device_id, Some(id(3)));
            assert_eq!(event.resource, Some(AuditResource { kind, id: id(4) }));
        }
        let system = from_bytes(
            &serde_json::to_vec(&json!({
            "action":"organization.user_ca_krl_activated","authority_id":id(4),
            "account_id":id(2),"device_id":id(3)}))
            .expect("body"),
        );
        assert_eq!(system.category, AuditCategory::Authorization);
        assert!(system.actor_account_id.is_none());
        assert!(system.actor_device_id.is_none());
    }

    #[test]
    fn grant_producers_preserve_real_native_and_browser_attribution() {
        for action in [
            "organization.grants_created",
            "organization.grants_updated",
            "organization.grants_deleted",
        ] {
            for actor_field in ["device_id", "browser_family_id"] {
                let mut fields = json!({"action":action,"account_id":id(2),"object_id":id(4)});
                fields[actor_field] = json!(id(3));
                let event = from_bytes(&serde_json::to_vec(&fields).unwrap());
                assert_eq!(event.category, AuditCategory::Authorization);
                assert_eq!(event.outcome, AuditOutcome::Success);
                assert_eq!(event.actor_account_id, Some(id(2)));
                assert_eq!(event.actor_device_id, (actor_field == "device_id").then_some(id(3)));
                assert_eq!(
                    event.actor_browser_family_id,
                    (actor_field == "browser_family_id").then_some(id(3))
                );
                assert_eq!(
                    event.resource,
                    Some(AuditResource { kind: AuditResourceKind::Grant, id: id(4) })
                );
            }
        }
    }

    #[test]
    fn access_request_producers_preserve_callers_and_expiry_is_system() {
        for action in [
            "organization.access_request_created",
            "organization.access_request_approved",
            "organization.access_request_denied",
            "organization.access_request_cancelled",
            "organization.access_request_expired",
        ] {
            for actor in ["device_id", "browser_family_id"] {
                let mut fields = json!({"action":action,"account_id":id(2),"request_id":id(4)});
                fields[actor] = json!(id(3));
                let event = from_bytes(&serde_json::to_vec(&fields).unwrap());
                let system = action == "organization.access_request_expired";
                assert_eq!(event.category, AuditCategory::Authorization);
                assert_eq!(event.outcome, AuditOutcome::Success);
                assert_eq!(
                    event.resource,
                    Some(AuditResource { kind: AuditResourceKind::AccessRequest, id: id(4) })
                );
                assert_eq!(event.actor_account_id, (!system).then_some(id(2)));
                assert_eq!(
                    event.actor_device_id,
                    (!system && actor == "device_id").then_some(id(3))
                );
                assert_eq!(
                    event.actor_browser_family_id,
                    (!system && actor == "browser_family_id").then_some(id(3))
                );
            }
        }
    }

    #[test]
    fn invalid_fields_and_ambiguous_actors_do_not_gain_inferred_values() {
        let base = json!({"action":"organization.name_updated","account_id":id(2),
            "browser_family_id":id(3),"organization_id":id(1)});
        let event = from_bytes(&serde_json::to_vec(&base).expect("body"));
        assert_eq!(event.actor_browser_family_id, Some(id(3)));
        assert_eq!(event.actor_account_id, Some(id(2)));
        for outcome in [Value::Null, json!(false), json!("SUCCESS"), json!(0)] {
            let mut fields = base.clone();
            fields["outcome"] = outcome;
            assert_eq!(
                from_bytes(&serde_json::to_vec(&fields).expect("body")).outcome,
                AuditOutcome::Unknown
            );
        }
        let mut fields = base.clone();
        fields["device_id"] = json!(id(4));
        let event = from_bytes(&serde_json::to_vec(&fields).expect("body"));
        assert!(event.actor_account_id.is_none());
        assert!(event.actor_device_id.is_none());
        assert!(event.actor_browser_family_id.is_none());
        fields = base;
        fields["account_id"] = json!(id(0xab).to_string().to_uppercase());
        fields["organization_id"] = json!(Uuid::nil());
        let event = from_bytes(&serde_json::to_vec(&fields).expect("body"));
        assert!(event.actor_account_id.is_none());
        assert_eq!(event.actor_browser_family_id, Some(id(3)));
        assert!(event.resource.is_none());
    }

    #[test]
    fn malformed_transport_fails_the_read_instead_of_dropping_the_row() {
        for (sequence, previous, hash, time) in [
            (0, vec![0; 32], vec![1; 32], 1),
            (1, vec![0; 31], vec![1; 32], 1),
            (1, vec![0; 32], vec![1; 33], 1),
            (1, vec![0; 32], vec![1; 32], 0),
            (1, vec![0; 32], vec![1; 32], i64::MAX),
        ] {
            assert_eq!(
                project(id(1), sequence, previous, hash, time, Some(b"{}")),
                Err(Error::StorageUnavailable)
            );
        }
    }
}
