// SPDX-License-Identifier: AGPL-3.0-only
//! Independent request producer: the client owns application, certificate and SSH/SFTP use.

use scoplen_api::{
    access_request::{
        AccessRequestDecisionRequest, AccessRequestFields, AccessRequestListQuery,
        AccessRequestOutcome, AccessRequestPage, AccessRequestResource, AccessRequestStatus,
        AccessRequestView,
    },
    grant::GrantResource,
    organization::OrganizationListQuery,
};
use scoplen_model::validate_uuid_v7;

use super::super::{Actor, Reply, grant, list};
use super::{
    Descriptor, Duration, ExpectedOutcome, GrantFields, Https, MAX_DESCRIPTOR_BYTES, PHASES, Path,
    Prepared, Result, SSH_USER, Serialize, SimpleRule, Uuid, descriptor_json, exchange, fs,
    prepare_target, read_bounded, require_absent, rule, withdraw, write_private,
};

const REQUEST_SECONDS: u32 = 600;
const REQUEST_REASON: &str = "Temporary access for owned SSH and binary SFTP acceptance.";
const MAX_COMPLETION_BYTES: usize = 2_048;

#[derive(Serialize)]
struct RequestDescriptor<'a> {
    #[serde(flatten)]
    base: Descriptor<'a>,
    request_id: Option<Uuid>,
    request_duration_seconds: u32,
    request_reason: &'a str,
}

fn request_descriptor_json(name: &str, descriptor: &RequestDescriptor<'_>) -> Result<String> {
    descriptor_json(&descriptor.base)?;
    AccessRequestFields {
        host: descriptor.base.host_id,
        remote_user: SSH_USER.into(),
        duration_seconds: descriptor.request_duration_seconds,
        reason: descriptor.request_reason.into(),
    }
    .validate()
    .map_err(|_| "Request client input is invalid")?;
    if descriptor.request_id.is_some_and(|id| validate_uuid_v7(id).is_err())
        || !matches!(
            (name, descriptor.request_id, descriptor.base.expected_outcome),
            ("before", None, ExpectedOutcome::IssuanceDenied)
                | ("active", Some(_), ExpectedOutcome::SshSftp)
                | ("withdrawn", Some(_), ExpectedOutcome::IssuanceDenied)
        )
    {
        return Err("Request client phase context is invalid");
    }
    let value = serde_json::to_string(descriptor)
        .map_err(|_| "Request client descriptor encoding failed")?;
    if value.len() >= MAX_DESCRIPTOR_BYTES {
        return Err("Request client descriptor exceeds its bound");
    }
    Ok(value)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BeforeCompletion {
    request_id: String,
    host_id: String,
    remote_user: String,
    duration_seconds: u32,
    status: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveCompletion {
    request_id: String,
    status: String,
    ssh_sftp: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WithdrawnCompletion {
    request_id: String,
    status: String,
    issuance_denied: bool,
}

fn completion_id(source: &str) -> Result<Uuid> {
    let id = Uuid::parse_str(source).map_err(|_| "Request client completion id is invalid")?;
    if id.to_string() != source || validate_uuid_v7(id).is_err() {
        return Err("Request client completion id is invalid");
    }
    Ok(id)
}

fn completion(
    source: &str,
    name: &str,
    descriptor: &RequestDescriptor<'_>,
) -> Result<Option<Uuid>> {
    let Some(line) = source.strip_suffix('\n') else {
        return Ok(None);
    };
    if line.contains(['\n', '\r']) {
        return Err("Request client completion must be single-line JSON");
    }
    let id = match name {
        "before" => {
            let value: BeforeCompletion = serde_json::from_str(line)
                .map_err(|_| "Request client pending completion is invalid")?;
            if completion_id(&value.host_id)? != descriptor.base.host_id
                || value.remote_user != SSH_USER
                || value.duration_seconds != descriptor.request_duration_seconds
                || value.status != "pending"
            {
                return Err("Request client pending completion tuple differs");
            }
            completion_id(&value.request_id)?
        }
        "active" => {
            let value: ActiveCompletion = serde_json::from_str(line)
                .map_err(|_| "Request client active completion is invalid")?;
            if value.status != "approved" || !value.ssh_sftp {
                return Err("Request client active completion did not verify SSH and SFTP");
            }
            completion_id(&value.request_id)?
        }
        "withdrawn" => {
            let value: WithdrawnCompletion = serde_json::from_str(line)
                .map_err(|_| "Request client withdrawn completion is invalid")?;
            if value.status != "approved" || !value.issuance_denied {
                return Err("Request client withdrawn completion did not verify denial");
            }
            completion_id(&value.request_id)?
        }
        _ => return Err("Request client completion phase is invalid"),
    };
    if descriptor.request_id.is_some_and(|expected| expected != id) {
        return Err("Request client completion belongs to another request");
    }
    Ok(Some(id))
}

async fn phase(directory: &Path, name: &str, descriptor: &RequestDescriptor<'_>) -> Result<Uuid> {
    let complete = directory.join(format!("request-client-{name}.complete"));
    require_absent(&complete)?;
    write_private(
        &directory.join(format!("request-client-{name}.json")),
        &request_descriptor_json(name, descriptor)?,
    )?;
    write_private(&directory.join(format!("request-client-{name}.ready")), "ready")?;
    println!("Request client phase ready: {name}");
    tokio::time::timeout(Duration::from_secs(240), async {
        loop {
            match fs::symlink_metadata(&complete) {
                Ok(metadata) => {
                    if !metadata.is_file() {
                        return Err("Request client completion signal is invalid");
                    }
                    let signal = read_bounded(&complete, MAX_COMPLETION_BYTES)?;
                    if let Some(id) = completion(&signal, name, descriptor)? {
                        return Ok(id);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("could not inspect Request client completion signal"),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| "Request client phase exceeded its deadline; abandon this fixture")?
}

fn resource(reply: &Reply, id: Uuid) -> Result<AccessRequestResource> {
    let value = AccessRequestResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .map_err(|_| "Request client Resource is invalid")?;
    value.validate_for_id(id).map_err(|_| "Request client Resource id differs")?;
    Ok(value)
}

async fn get(
    https: &Https,
    actor: Actor<'_>,
    org: Uuid,
    id: Uuid,
) -> Result<AccessRequestResource> {
    resource(
        &exchange(
            https,
            actor,
            "GET",
            &format!("/api/v1/orgs/{org}/access-requests/{id}"),
            &[],
            &[],
            200,
        )
        .await?,
        id,
    )
}

fn validate_pending(
    current: &AccessRequestResource,
    id: Uuid,
    account: Uuid,
    membership: Uuid,
    expected: &AccessRequestFields,
) -> Result<()> {
    current.validate_for_id(id).map_err(|_| "Request client reviewed id differs")?;
    if current.requester_account_id != account
        || current.requester_membership_id != membership
        || current.fields != *expected
        || current.status != AccessRequestStatus::Pending
    {
        return Err("Request client original pending identity or input differs");
    }
    Ok(())
}

async fn review(
    https: &Https,
    actor: Actor<'_>,
    org: Uuid,
    owner: Uuid,
    id: Uuid,
) -> Result<AccessRequestResource> {
    let reply = exchange(
        https,
        actor,
        "GET",
        &format!("/api/v1/orgs/{org}/access-requests?view=approvals&limit=2"),
        &[],
        &[],
        200,
    )
    .await?;
    if reply.header("etag").is_some() {
        return Err("Request client approvals Page disclosed a Resource validator");
    }
    let page = AccessRequestPage::from_http_json(
        &reply.body,
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .map_err(|_| "Request client approvals Page is invalid")?;
    page.validate_for_query(
        owner,
        AccessRequestListQuery {
            view: AccessRequestView::Approvals,
            page: OrganizationListQuery { limit: 2, cursor: None },
        },
    )
    .map_err(|_| "Request client approvals Page context differs")?;
    if page.next_cursor.is_some() || page.items.len() != 1 || page.items[0].id != id {
        return Err("Request client approvals Page does not contain exactly the original request");
    }
    let current = get(https, actor, org, id).await?;
    if current != page.items[0] {
        return Err("Request client review changed after listing");
    }
    Ok(current)
}

async fn approve(
    https: &Https,
    actor: Actor<'_>,
    org: Uuid,
    owner: Uuid,
    original: &AccessRequestResource,
) -> Result<AccessRequestResource> {
    let decision = AccessRequestDecisionRequest { decision: AccessRequestOutcome::Approve };
    let body = decision.to_json().map_err(|_| "Request client approval input is invalid")?;
    let key = Uuid::now_v7().to_string();
    let approved = resource(
        &exchange(
            https,
            actor,
            "POST",
            &format!("/api/v1/orgs/{org}/access-requests/{}/decisions", original.id),
            &body,
            &[("If-Match", &original.etag), ("Idempotency-Key", &key)],
            200,
        )
        .await?,
        original.id,
    )?;
    approved
        .validate_for_decision(original, decision, owner)
        .map_err(|_| "Request client approval changed the reviewed input or actor")?;
    Ok(approved)
}

async fn current_grant(
    https: &Https,
    actor: Actor<'_>,
    org: Uuid,
    membership: Uuid,
    approved: &AccessRequestResource,
) -> Result<GrantResource> {
    let history = approved.grant.as_ref().ok_or("Request client approval has no Grant")?;
    let current = grant(
        &exchange(
            https,
            actor,
            "GET",
            &format!("/api/v1/orgs/{org}/grants/{}", history.id),
            &[],
            &[],
            200,
        )
        .await?,
    )?;
    current.validate_for_id(history.id).map_err(|_| "Request client current Grant id differs")?;
    current
        .validate_for_fields(&GrantFields {
            membership,
            host: approved.fields.host,
            remote_user: approved.fields.remote_user.clone(),
            valid_from: history.valid_from,
            valid_until: Some(history.valid_until),
        })
        .map_err(|_| "Request client current Grant differs from original finite approval")?;
    Ok(current)
}

pub(super) async fn prepare(
    https: &Https,
    directory: &Path,
    openssh_descriptor: &Path,
) -> Result<()> {
    for name in PHASES {
        for suffix in ["json", "ready", "complete"] {
            require_absent(&directory.join(format!("request-client-{name}.{suffix}")))?;
        }
    }
    let Prepared { owner, member, mut owner_browser, org, membership, host, profile } =
        prepare_target(https, openssh_descriptor).await?;
    rule(
        https,
        owner_browser.actor(),
        org,
        membership,
        SimpleRule::RequestAccess { hosts: vec![host.id] },
    )
    .await?;
    if !list(https, owner_browser.actor(), org).await?.is_empty() {
        return Err("Request client initial team unexpectedly contains a Grant");
    }
    let owner_password_file = directory.join("request-client-owner-password.txt");
    let member_password_file = directory.join("request-client-member-password.txt");
    super::super::super::write_browser_password(&owner_password_file, &owner.password)?;
    super::super::super::write_browser_password(&member_password_file, &member.password)?;
    let mut descriptor = RequestDescriptor {
        base: Descriptor {
            disposable: true,
            origin: &https.origin,
            ca_certificate: directory.join("ca.pem"),
            organization_id: org,
            host_id: host.id,
            profile_id: profile.id,
            owner_username: &owner.payload.username,
            owner_password_file,
            member_username: &member.payload.username,
            member_password_file,
            expected_outcome: ExpectedOutcome::IssuanceDenied,
            certificate_not_after: None,
        },
        request_id: None,
        request_duration_seconds: REQUEST_SECONDS,
        request_reason: REQUEST_REASON,
    };
    let id = phase(directory, PHASES[0], &descriptor).await?;
    owner_browser.refresh(https).await?;
    let original = review(https, owner_browser.actor(), org, owner.payload.account_id, id).await?;
    validate_pending(
        &original,
        id,
        member.payload.account_id,
        membership,
        &AccessRequestFields {
            host: host.id,
            remote_user: SSH_USER.into(),
            duration_seconds: REQUEST_SECONDS,
            reason: REQUEST_REASON.into(),
        },
    )?;
    let approved =
        approve(https, owner_browser.actor(), org, owner.payload.account_id, &original).await?;
    let granted = current_grant(https, owner_browser.actor(), org, membership, &approved).await?;
    if list(https, owner_browser.actor(), org).await? != [granted.clone()] {
        return Err("Request client approval did not create exactly one expected Grant");
    }
    descriptor.request_id = Some(id);
    descriptor.base.expected_outcome = ExpectedOutcome::SshSftp;
    descriptor.base.certificate_not_after = granted.fields.valid_until;
    phase(directory, PHASES[1], &descriptor).await?;
    owner_browser.refresh(https).await?;
    let current = current_grant(https, owner_browser.actor(), org, membership, &approved).await?;
    withdraw(https, owner_browser.actor(), org, &current).await?;
    if get(https, owner_browser.actor(), org, id).await? != approved
        || !list(https, owner_browser.actor(), org).await?.is_empty()
    {
        return Err("Request client withdrawal changed history or retained a Grant");
    }
    descriptor.base.expected_outcome = ExpectedOutcome::IssuanceDenied;
    descriptor.base.certificate_not_after = None;
    phase(directory, PHASES[2], &descriptor).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn descriptor() -> RequestDescriptor<'static> {
        let root = std::env::temp_dir();
        RequestDescriptor {
            base: Descriptor {
                disposable: true,
                origin: "https://localhost:18443",
                ca_certificate: root.join("ca.pem"),
                organization_id: Uuid::now_v7(),
                host_id: Uuid::now_v7(),
                profile_id: Uuid::now_v7(),
                owner_username: "synthetic-owner",
                owner_password_file: root.join("synthetic-owner.txt"),
                member_username: "synthetic-member",
                member_password_file: root.join("synthetic-member.txt"),
                expected_outcome: ExpectedOutcome::IssuanceDenied,
                certificate_not_after: None,
            },
            request_id: None,
            request_duration_seconds: REQUEST_SECONDS,
            request_reason: REQUEST_REASON,
        }
    }

    fn signal(value: &serde_json::Value) -> String {
        format!("{value}\n")
    }

    #[test]
    fn descriptor_keeps_original_fields_and_binds_phase_request_and_finite_cutoff() {
        let mut descriptor = descriptor();
        let value: serde_json::Value =
            serde_json::from_str(&request_descriptor_json("before", &descriptor).unwrap()).unwrap();
        let base: serde_json::Value =
            serde_json::from_str(&descriptor_json(&descriptor.base).unwrap()).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 15);
        for (key, expected) in base.as_object().unwrap() {
            assert_eq!(&value[key], expected);
        }
        assert_eq!(value["request_id"], serde_json::Value::Null);
        assert_eq!(value["request_duration_seconds"], REQUEST_SECONDS);
        assert_eq!(value["request_reason"], REQUEST_REASON);
        assert!(request_descriptor_json("active", &descriptor).is_err());
        descriptor.request_id = Some(Uuid::now_v7());
        assert!(request_descriptor_json("before", &descriptor).is_err());
        assert!(request_descriptor_json("withdrawn", &descriptor).is_ok());
        descriptor.base.expected_outcome = ExpectedOutcome::SshSftp;
        assert!(request_descriptor_json("active", &descriptor).is_err());
        descriptor.base.certificate_not_after = Some(1_800_000_600);
        assert!(request_descriptor_json("active", &descriptor).is_ok());
        assert!(request_descriptor_json("withdrawn", &descriptor).is_err());
        descriptor.request_id = Some(Uuid::new_v4());
        assert!(request_descriptor_json("active", &descriptor).is_err());
        descriptor.request_id = Some(Uuid::now_v7());
        descriptor.request_duration_seconds = 86_401;
        assert!(request_descriptor_json("active", &descriptor).is_err());
        descriptor.request_duration_seconds = REQUEST_SECONDS;
        descriptor.request_reason = " \t";
        assert!(request_descriptor_json("active", &descriptor).is_err());
    }

    #[test]
    fn pending_completion_waits_for_lf_and_rejects_changed_tuple_or_extra_fields() {
        let descriptor = descriptor();
        let id = Uuid::now_v7();
        let correct = json!({
            "request_id":id,"host_id":descriptor.base.host_id,"remote_user":SSH_USER,
            "duration_seconds":REQUEST_SECONDS,"status":"pending",
        });
        let encoded = signal(&correct);
        for prefix in encoded.char_indices().map(|(index, _)| &encoded[..index]) {
            assert_eq!(completion(prefix, "before", &descriptor).unwrap(), None);
        }
        assert_eq!(completion(&encoded, "before", &descriptor).unwrap(), Some(id));
        for (key, replacement) in [
            ("request_id", json!(Uuid::new_v4())),
            ("request_id", json!(id.to_string().replace('-', ""))),
            ("host_id", json!(Uuid::now_v7())),
            ("remote_user", json!("different")),
            ("duration_seconds", json!(REQUEST_SECONDS + 1)),
            ("status", json!("approved")),
            ("reason", json!(REQUEST_REASON)),
        ] {
            let mut changed = correct.clone();
            changed[key] = replacement;
            assert!(completion(&signal(&changed), "before", &descriptor).is_err());
        }
        let mut missing = correct.clone();
        missing.as_object_mut().unwrap().remove("host_id");
        assert!(completion(&signal(&missing), "before", &descriptor).is_err());
        let duplicate = encoded.replacen('{', "{\"status\":\"pending\",", 1);
        assert!(completion(&duplicate, "before", &descriptor).is_err());
        assert!(completion(&format!("{encoded}\n"), "before", &descriptor).is_err());
        assert!(completion("passed\n", "before", &descriptor).is_err());
    }

    #[test]
    fn terminal_completions_keep_approved_history_and_require_current_phase_evidence() {
        let mut descriptor = descriptor();
        let id = Uuid::now_v7();
        descriptor.request_id = Some(id);
        for (name, evidence) in [("active", "ssh_sftp"), ("withdrawn", "issuance_denied")] {
            let correct = json!({"request_id":id,"status":"approved",evidence:true});
            assert_eq!(completion(&signal(&correct), name, &descriptor).unwrap(), Some(id));
            for (key, replacement) in [
                ("request_id", json!(Uuid::now_v7())),
                ("status", json!("pending")),
                (evidence, json!(false)),
                ("unexpected", json!(true)),
            ] {
                let mut changed = correct.clone();
                changed[key] = replacement;
                assert!(completion(&signal(&changed), name, &descriptor).is_err());
            }
            let other = if name == "active" { "withdrawn" } else { "active" };
            assert!(completion(&signal(&correct), other, &descriptor).is_err());
        }
    }

    #[test]
    fn reviewed_pending_request_requires_original_requester_membership_and_exact_input() {
        let descriptor = descriptor();
        let fields = AccessRequestFields {
            host: descriptor.base.host_id,
            remote_user: SSH_USER.into(),
            duration_seconds: REQUEST_SECONDS,
            reason: REQUEST_REASON.into(),
        };
        let current = AccessRequestResource {
            id: Uuid::now_v7(),
            etag: "\"synthetic\"".into(),
            created_at: "2026-11-17T00:00:00Z".into(),
            updated_at: "2026-11-17T00:00:00Z".into(),
            requester_account_id: Uuid::now_v7(),
            requester_membership_id: Uuid::now_v7(),
            fields: fields.clone(),
            expires_at: "2026-11-18T00:00:00Z".into(),
            status: AccessRequestStatus::Pending,
            decision: None,
            grant: None,
        };
        let check = |value: &AccessRequestResource| {
            validate_pending(
                value,
                current.id,
                current.requester_account_id,
                current.requester_membership_id,
                &fields,
            )
        };
        assert!(check(&current).is_ok());
        let mut changed = current.clone();
        changed.requester_account_id = Uuid::now_v7();
        assert!(check(&changed).is_err());
        changed = current.clone();
        changed.requester_membership_id = Uuid::now_v7();
        assert!(check(&changed).is_err());
        changed = current.clone();
        changed.fields.reason.push(' ');
        assert!(check(&changed).is_err());
        changed = current.clone();
        changed.fields.remote_user.push(' ');
        assert!(check(&changed).is_err());
        changed = current.clone();
        changed.status = AccessRequestStatus::Cancelled;
        assert!(check(&changed).is_err());
    }
}
