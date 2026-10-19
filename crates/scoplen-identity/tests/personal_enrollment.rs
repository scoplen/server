// SPDX-License-Identifier: AGPL-3.0-only

use scoplen_api::{
    personal_enrollment::PersonalEnrollmentRequest,
    sync::{SyncAccountDeviceWrap, SyncAccountKeyBundleUpdate},
};
use scoplen_crypto::{
    DeviceCertificate, DeviceKemKeyPair, Ed25519SigningKey, P256SigningKey,
    PersonalEnrollmentArtifacts, PersonalEnrollmentContext,
};
use scoplen_identity::{PersonalEnrollmentVerificationError as Error, verify_personal_enrollment};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const ORIGIN: &str = "https://example.com";

fn id(last: u8) -> Uuid {
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, last])
}

fn account_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[1; 32]).expect("account key")
}

fn device_key() -> P256SigningKey {
    P256SigningKey::from_bytes(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ])
    .expect("device key")
}

fn sign_bundle(request: &mut PersonalEnrollmentRequest) {
    request.key_bundle_update.signature = account_key()
        .sign(&request.key_bundle_update.signature_input().expect("signature input"))
        .to_vec();
}

fn sign_proof(request: &mut PersonalEnrollmentRequest) {
    let bundle = request.key_bundle_update.to_cbor().expect("bundle CBOR");
    let certificate = request.device_certificate.encode().expect("certificate CBOR");
    let context = PersonalEnrollmentContext::new(
        ORIGIN,
        &request.invitation_token,
        request.account_id,
        request.personal_vault_id,
        PersonalEnrollmentArtifacts {
            account_signing_public_key: &request.account_signing_public_key,
            account_kem_public_key: &request.account_kem_public_key,
            key_bundle_update: &bundle,
            device_certificate: &certificate,
            wrapped_personal_vault_key: &request.wrapped_personal_vault_key,
        },
    )
    .expect("proof context");
    request.device_signature = context.sign(&device_key()).expect("device proof");
}

fn enrollment() -> PersonalEnrollmentRequest {
    let account_id = id(1);
    let device_id = id(2);
    let kem = DeviceKemKeyPair::from_private_bytes(&[2; 32]).expect("device KEM");
    let mut request = PersonalEnrollmentRequest {
        invitation_token: [3; 32],
        account_id,
        personal_vault_id: id(3),
        account_signing_public_key: account_key().public_key(),
        account_kem_public_key: [4; 32],
        key_bundle_update: SyncAccountKeyBundleUpdate {
            revision: 1,
            device_wraps: vec![SyncAccountDeviceWrap { device_id, wrapped_ark: vec![5] }],
            account_signing_key: vec![6],
            account_kem_key: vec![7],
            recovery_blob: vec![8],
            signature: vec![0; 64],
        },
        device_certificate: DeviceCertificate::issue(
            &account_key(),
            device_id,
            account_id,
            device_key().public_key_sec1(),
            kem.public_key().to_vec(),
            "first device".into(),
            "windows".into(),
            1,
        )
        .expect("certificate"),
        wrapped_personal_vault_key: vec![9],
        device_signature: [0; 64],
    };
    sign_bundle(&mut request);
    sign_proof(&mut request);
    request
}

#[test]
fn public_verifier_preserves_exact_artifacts_and_only_the_token_digest() {
    let original = enrollment();
    let submitted_bundle = original.key_bundle_update.to_cbor().expect("bundle CBOR");
    let submitted_certificate = original.device_certificate.encode().expect("certificate CBOR");
    let submitted_json = original.to_json().expect("JSON");
    let decoded = PersonalEnrollmentRequest::from_json(&submitted_json).expect("bounded JSON");
    let verified = verify_personal_enrollment(ORIGIN, &decoded).expect("all signatures verify");
    let expected_digest: [u8; 32] = Sha256::digest(original.invitation_token).into();
    assert_eq!(verified.invitation_token_digest(), &expected_digest);
    assert_eq!(verified.trusted_origin(), ORIGIN);
    assert_eq!(verified.account_id(), original.account_id);
    assert_eq!(verified.device_id(), original.device_certificate.device_id);
    assert_eq!(verified.personal_vault_id(), original.personal_vault_id);
    assert_eq!(verified.account_signing_public_key(), &original.account_signing_public_key);
    assert_eq!(verified.account_kem_public_key(), &original.account_kem_public_key);
    assert_eq!(verified.key_bundle_update(), &original.key_bundle_update);
    assert_eq!(verified.key_bundle_update_cbor(), submitted_bundle);
    assert_eq!(verified.device_certificate_cbor(), submitted_certificate);
    assert_eq!(verified.wrapped_personal_vault_key(), original.wrapped_personal_vault_key);
    assert_eq!(format!("{verified:?}"), "VerifiedPersonalEnrollment([REDACTED])");
}

#[test]
fn signature_failures_and_invalid_account_public_key_have_one_denial() {
    let baseline = enrollment();
    let mut changed = baseline.clone();
    changed.key_bundle_update.signature[0] ^= 1;
    assert!(matches!(verify_personal_enrollment(ORIGIN, &changed), Err(Error::Denied)));

    changed = baseline.clone();
    changed.device_certificate.signature[0] ^= 1;
    assert!(matches!(verify_personal_enrollment(ORIGIN, &changed), Err(Error::Denied)));

    changed = baseline.clone();
    changed.device_signature[0] ^= 1;
    assert!(matches!(verify_personal_enrollment(ORIGIN, &changed), Err(Error::Denied)));

    changed = baseline.clone();
    changed.account_signing_public_key = [0xff; 32];
    assert!(matches!(verify_personal_enrollment(ORIGIN, &changed), Err(Error::Denied)));

    changed = baseline;
    changed.device_certificate.signing_public_key = vec![0; 65];
    assert!(matches!(verify_personal_enrollment(ORIGIN, &changed), Err(Error::InvalidRequest)));
}

#[test]
fn every_mutable_binding_requires_a_fresh_possession_proof() {
    let baseline = enrollment();
    let mut changed = baseline.clone();
    changed.invitation_token[0] ^= 1;
    assert!(matches!(verify_personal_enrollment(ORIGIN, &changed), Err(Error::Denied)));

    changed = baseline.clone();
    changed.personal_vault_id = id(4);
    assert!(matches!(verify_personal_enrollment(ORIGIN, &changed), Err(Error::Denied)));

    changed = baseline.clone();
    changed.account_kem_public_key[0] ^= 1;
    assert!(matches!(verify_personal_enrollment(ORIGIN, &changed), Err(Error::Denied)));

    changed = baseline.clone();
    changed.key_bundle_update.recovery_blob[0] ^= 1;
    sign_bundle(&mut changed);
    assert!(matches!(verify_personal_enrollment(ORIGIN, &changed), Err(Error::Denied)));

    changed = baseline.clone();
    changed.device_certificate = DeviceCertificate::issue(
        &account_key(),
        baseline.device_certificate.device_id,
        baseline.account_id,
        device_key().public_key_sec1(),
        baseline.device_certificate.kem_public_key.clone(),
        "renamed device".into(),
        "windows".into(),
        1,
    )
    .expect("new valid certificate");
    assert!(matches!(verify_personal_enrollment(ORIGIN, &changed), Err(Error::Denied)));

    changed = baseline.clone();
    changed.wrapped_personal_vault_key[0] ^= 1;
    assert!(matches!(verify_personal_enrollment(ORIGIN, &changed), Err(Error::Denied)));

    assert!(matches!(
        verify_personal_enrollment("https://other.example", &baseline),
        Err(Error::Denied)
    ));
}

#[test]
fn mismatched_ids_are_denied_and_malformed_input_stays_separate() {
    let baseline = enrollment();
    let mut changed = baseline.clone();
    changed.account_id = id(4);
    assert!(matches!(verify_personal_enrollment(ORIGIN, &changed), Err(Error::Denied)));

    changed = baseline.clone();
    changed.key_bundle_update.device_wraps[0].device_id = id(5);
    sign_bundle(&mut changed);
    assert!(matches!(verify_personal_enrollment(ORIGIN, &changed), Err(Error::Denied)));

    changed = baseline.clone();
    changed.personal_vault_id = Uuid::nil();
    assert!(matches!(verify_personal_enrollment(ORIGIN, &changed), Err(Error::InvalidRequest)));

    changed = baseline.clone();
    changed.wrapped_personal_vault_key.clear();
    assert!(matches!(verify_personal_enrollment(ORIGIN, &changed), Err(Error::InvalidRequest)));

    assert!(matches!(
        verify_personal_enrollment("https://Example.com", &baseline),
        Err(Error::InvalidTrustedOrigin)
    ));
    let invalid_json = br#"{"invitation_token":"secret"}"#;
    assert!(PersonalEnrollmentRequest::from_json(invalid_json).is_err());
}

#[test]
fn opaque_wrap_limit_is_inclusive_and_error_text_is_redacted() {
    let mut request = enrollment();
    request.wrapped_personal_vault_key = vec![0xa5; 65_536];
    sign_proof(&mut request);
    let verified = verify_personal_enrollment(ORIGIN, &request).expect("exact limit is accepted");
    assert_eq!(verified.wrapped_personal_vault_key().len(), 65_536);

    request.wrapped_personal_vault_key.push(0xa5);
    let error = verify_personal_enrollment(ORIGIN, &request).expect_err("over limit");
    assert_eq!(error, Error::InvalidRequest);
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(!rendered.contains("example.com"));
        assert!(!rendered.contains("a5"));
        assert!(!rendered.contains("secret"));
    }
}
