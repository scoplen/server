// SPDX-License-Identifier: AGPL-3.0-only

use scoplen_api::certificate::{CertificateIssuanceRequest, CertificateTargets};
use scoplen_ca::{
    LocalUserCa, LocalUserCaError, UserCertificateContext, verify_stored_user_certificate,
};
use ssh_key::{Certificate, PublicKey, certificate::CertType};
use uuid::Uuid;

#[test]
fn encrypted_custody_binds_the_organization_authority_and_deployment_key() {
    let organization = Uuid::now_v7();
    let authority = Uuid::now_v7();
    let signer = LocalUserCa::generate().expect("OS-random CA");
    let second = LocalUserCa::generate().expect("independent CA");
    assert_ne!(signer.public_key().unwrap(), second.public_key().unwrap());
    assert_eq!(format!("{signer:?}"), "LocalUserCa([REDACTED])");
    let sealed = signer.seal(&[7; 32], organization, authority).expect("KMS wrapping");
    assert_eq!(sealed.len(), 73);
    let opened = LocalUserCa::open(&sealed, &[7; 32], organization, authority).expect("owner");
    assert_eq!(opened.public_key().unwrap(), signer.public_key().unwrap());
    for (key, org, ca) in [
        ([8; 32], organization, authority),
        ([7; 32], Uuid::now_v7(), authority),
        ([7; 32], organization, Uuid::now_v7()),
    ] {
        assert!(matches!(
            LocalUserCa::open(&sealed, &key, org, ca),
            Err(LocalUserCaError::KeyIntegrity)
        ));
    }
    let mut damaged = sealed;
    damaged[40] ^= 1;
    assert!(matches!(
        LocalUserCa::open(&damaged, &[7; 32], organization, authority),
        Err(LocalUserCaError::KeyIntegrity)
    ));
}

#[test]
fn real_user_certificate_has_exact_scoped_principals_and_initial_extensions() {
    let signer = LocalUserCa::generate().expect("CA");
    let subject = LocalUserCa::generate().expect("independent subject").public_key().unwrap();
    let hosts = vec![Uuid::now_v7(), Uuid::now_v7()];
    let request = CertificateIssuanceRequest::new(
        &subject,
        CertificateTargets::Hosts(hosts.clone()),
        "deploy",
        86_400,
    )
    .expect("D-88 request");
    let context = UserCertificateContext {
        organization: Uuid::now_v7(),
        account: Uuid::now_v7(),
        device: Uuid::now_v7(),
        certificate: Uuid::now_v7(),
        serial: u64::MAX,
        now_seconds: 1_800_000_000,
        authorization_not_after: None,
    };
    let line = signer.issue(&request, &context).expect("real signing");
    let public = signer.public_key().unwrap();
    let verify = |ca: &str, org, account, device, resource, serial| {
        verify_stored_user_certificate(&line, ca, org, account, device, resource, serial)
    };
    assert_eq!(
        verify(
            &public,
            context.organization,
            context.account,
            context.device,
            context.certificate,
            context.serial
        ),
        Ok(context.now_seconds + 1_800)
    );
    for (org, account, device, resource, serial) in [
        (Uuid::now_v7(), context.account, context.device, context.certificate, context.serial),
        (context.organization, Uuid::now_v7(), context.device, context.certificate, context.serial),
        (
            context.organization,
            context.account,
            Uuid::now_v7(),
            context.certificate,
            context.serial,
        ),
        (context.organization, context.account, context.device, Uuid::now_v7(), context.serial),
        (context.organization, context.account, context.device, context.certificate, 1),
    ] {
        assert!(verify(&public, org, account, device, resource, serial).is_err());
    }
    assert!(
        verify(
            &LocalUserCa::generate().unwrap().public_key().unwrap(),
            context.organization,
            context.account,
            context.device,
            context.certificate,
            context.serial
        )
        .is_err()
    );
    let certificate = Certificate::from_openssh(&line).expect("OpenSSH user certificate");
    certificate.verify_signature().expect("authentic signature");
    assert_eq!(certificate.cert_type(), CertType::User);
    assert_eq!(certificate.serial(), u64::MAX);
    assert_eq!(
        certificate.key_id(),
        format!(
            "spl:{}:{}:{}:{}",
            context.organization, context.account, context.device, context.certificate
        )
    );
    assert_eq!(certificate.public_key(), PublicKey::from_openssh(&subject).unwrap().key_data());
    assert_eq!(
        certificate.signature_key(),
        PublicKey::from_openssh(&signer.public_key().unwrap()).unwrap().key_data()
    );
    assert_eq!(
        certificate.valid_principals(),
        hosts
            .iter()
            .map(|host| format!("spl:{}:h:{host}:deploy", context.organization))
            .collect::<Vec<_>>()
    );
    assert_eq!(certificate.valid_after(), context.now_seconds - 60);
    assert_eq!(certificate.valid_before(), context.now_seconds + 1_800);
    assert!(certificate.critical_options().is_empty());
    assert_eq!(certificate.extensions().len(), 2);
    assert_eq!(certificate.extensions().get("permit-pty").map(String::as_str), Some(""));
    assert_eq!(
        certificate.extensions().get("org@scoplen.com"),
        Some(&context.organization.to_string())
    );
    assert!(!certificate.valid_principals().iter().any(|principal| principal == "deploy"));
}

#[test]
fn group_certificates_preserve_selection_and_short_requested_lifetimes() {
    let signer = LocalUserCa::generate().unwrap();
    let groups = vec![Uuid::now_v7(), Uuid::now_v7()];
    let request = CertificateIssuanceRequest::new(
        signer.public_key().unwrap(),
        CertificateTargets::HostGroups(groups.clone()),
        "operator",
        30,
    )
    .unwrap();
    let mut context = UserCertificateContext {
        organization: Uuid::now_v7(),
        account: Uuid::now_v7(),
        device: Uuid::now_v7(),
        certificate: Uuid::now_v7(),
        serial: 1,
        now_seconds: 1_800_000_000,
        authorization_not_after: None,
    };
    let cert = Certificate::from_openssh(&signer.issue(&request, &context).unwrap()).unwrap();
    assert_eq!(cert.valid_before(), context.now_seconds + 30);
    assert_eq!(
        cert.valid_principals(),
        groups
            .iter()
            .map(|group| format!("spl:{}:g:{group}:operator", context.organization))
            .collect::<Vec<_>>()
    );
    context.serial = 0;
    assert!(matches!(signer.issue(&request, &context), Err(LocalUserCaError::InvalidContext)));
}

#[test]
fn authorization_bound_caps_signed_expiry_without_changing_request_bytes() {
    let signer = LocalUserCa::generate().unwrap();
    let mut request = CertificateIssuanceRequest::new(
        signer.public_key().unwrap(),
        CertificateTargets::Hosts(vec![Uuid::now_v7()]),
        "deploy",
        86_400,
    )
    .unwrap();
    let mut context = UserCertificateContext {
        organization: Uuid::now_v7(),
        account: Uuid::now_v7(),
        device: Uuid::now_v7(),
        certificate: Uuid::now_v7(),
        serial: 1,
        now_seconds: 1_800_000_000,
        authorization_not_after: Some(1_800_000_090),
    };
    let original = request.to_json().unwrap();
    let issue = |request: &CertificateIssuanceRequest, context: &UserCertificateContext| {
        Certificate::from_openssh(&signer.issue(request, context).unwrap()).unwrap()
    };
    assert_eq!(issue(&request, &context).valid_before(), context.now_seconds + 90);
    assert_eq!(request.to_json().unwrap(), original);
    request.ttl_seconds = 30;
    assert_eq!(issue(&request, &context).valid_before(), context.now_seconds + 30);
    request.ttl_seconds = 86_400;
    context.authorization_not_after = Some(context.now_seconds + 7_200);
    assert_eq!(issue(&request, &context).valid_before(), context.now_seconds + 1_800);
    context.authorization_not_after = None;
    assert_eq!(issue(&request, &context).valid_before(), context.now_seconds + 1_800);
    for bound in [0, context.now_seconds - 1, context.now_seconds] {
        context.authorization_not_after = Some(bound);
        assert!(matches!(signer.issue(&request, &context), Err(LocalUserCaError::InvalidContext)));
    }
}
