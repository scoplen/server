// SPDX-License-Identifier: AGPL-3.0-only
//! Resident software authenticator; official `SoftPasskey` performs all key generation/signing.

use ciborium::value::Value;
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use webauthn_authenticator_rs::{
    AuthenticatorBackend, AuthenticatorBackendHashedClientData, WebauthnAuthenticator,
    error::WebauthnCError,
    prelude::{
        CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
        RequestChallengeResponse, Url,
    },
    softpasskey::SoftPasskey,
};
use webauthn_rs_core::proto::{
    AllowCredentials, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
};

#[derive(Default)]
pub struct ResidentPasskey {
    inner: SoftPasskey,
    resident: HashMap<String, (Vec<u8>, Vec<u8>)>,
}

impl ResidentPasskey {
    pub fn authenticator() -> WebauthnAuthenticator<Self> {
        WebauthnAuthenticator::new(Self { inner: SoftPasskey::new(true), resident: HashMap::new() })
    }
}

impl AuthenticatorBackend for ResidentPasskey {
    fn perform_register(
        &mut self,
        origin: Url,
        mut options: PublicKeyCredentialCreationOptions,
        timeout: u32,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        let rp = options.rp.id.clone();
        let user = options.user.id.as_ref().to_vec();
        // This wrapper supplies resident storage/selection missing from the base software token.
        // Production options and verifier state retain required residency and UV.
        if let Some(selection) = options.authenticator_selection.as_mut() {
            selection.require_resident_key = false;
        }
        let client_data = serde_json::to_vec(&serde_json::json!({
            "type":"webauthn.create", "origin":origin.origin().ascii_serialization(),
            "challenge": options.challenge
        }))
        .map_err(|_| WebauthnCError::Json)?;
        let mut result = AuthenticatorBackendHashedClientData::perform_register(
            &mut self.inner,
            Sha256::digest(&client_data).to_vec(),
            options,
            timeout,
        )?;
        result.response.client_data_json = client_data.into();
        self.resident.insert(rp, (result.raw_id.as_ref().to_vec(), user));
        // navigator.credentials.create applies the requested 'none' attestation privacy step.
        // Preserve exact authenticator data; no cryptographic verifier or signature is replaced.
        let mut attestation: Value =
            ciborium::de::from_reader(result.response.attestation_object.as_ref())
                .map_err(|_| WebauthnCError::Cbor)?;
        if let Value::Map(map) = &mut attestation {
            for (key, value) in map {
                if key == &Value::Text("fmt".into()) {
                    *value = Value::Text("none".into());
                } else if key == &Value::Text("attStmt".into()) {
                    *value = Value::Map(vec![]);
                }
            }
        }
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&attestation, &mut bytes).map_err(|_| WebauthnCError::Cbor)?;
        result.response.attestation_object = bytes.into();
        Ok(result)
    }

    fn perform_auth(
        &mut self,
        origin: Url,
        mut options: PublicKeyCredentialRequestOptions,
        timeout: u32,
    ) -> Result<PublicKeyCredential, WebauthnCError> {
        let (id, handle) = self.resident.get(&options.rp_id).ok_or(WebauthnCError::NotSupported)?;
        if options.allow_credentials.is_empty() {
            options.allow_credentials.push(AllowCredentials {
                type_: "public-key".into(),
                id: id.clone().into(),
                transports: None,
            });
        }
        let client_data = serde_json::to_vec(&serde_json::json!({
            "type":"webauthn.get", "origin":origin.origin().ascii_serialization(),
            "challenge": options.challenge
        }))
        .map_err(|_| WebauthnCError::Json)?;
        let mut result = AuthenticatorBackendHashedClientData::perform_auth(
            &mut self.inner,
            Sha256::digest(&client_data).to_vec(),
            options,
            timeout,
        )?;
        result.response.client_data_json = client_data.into();
        result.response.user_handle = Some(handle.clone().into());
        Ok(result)
    }
}

pub fn creation(value: &serde_json::Value) -> CreationChallengeResponse {
    serde_json::from_value(serde_json::json!({"publicKey": value}))
        .expect("public creation options")
}

pub fn authentication(value: &serde_json::Value) -> RequestChallengeResponse {
    serde_json::from_value(serde_json::json!({"publicKey": value})).expect("public login options")
}
