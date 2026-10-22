// SPDX-License-Identifier: AGPL-3.0-only
//! Deployment passkey policy and bounded adapters for the maintained `WebAuthn` verifier.

use std::{collections::BTreeSet, fmt, io::Cursor, time::Duration};

use ciborium::value::Value as Cbor;
use scoplen_crypto::validate_server_origin;
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Value, json};
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use webauthn_rs_core::{
    WebauthnCore,
    proto::{
        AttestationConveyancePreference, AttestationFormat, AuthenticationState, COSEAlgorithm,
        Credential, PublicKeyCredential, RegisterPublicKeyCredential, RegistrationState,
        UserVerificationPolicy,
    },
};

/// Maximum serialized server-only state or credential size.
pub const MAX_STATE_BYTES: usize = 32_768;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PasskeyError {
    #[error("server.public_host must be a DNS name with valid HTTPS for operator setup")]
    Configuration,
    #[error("operator passkey authentication denied")]
    Denied,
    #[error("operator passkey stored state is invalid")]
    State,
}

/// Only trusted configuration constructs this policy. It never accepts a request RP/origin.
pub struct OperatorPasskeyVerifier {
    origin: String,
    rp_id: String,
    core: WebauthnCore,
}

impl fmt::Debug for OperatorPasskeyVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperatorPasskeyVerifier")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved<T> {
    version: u8,
    purpose: String,
    origin: String,
    rp_id: String,
    library: T,
}

/// Options are public; `state` must remain exclusively in the server database.
pub struct PasskeyOptions {
    pub public_key: Value,
    pub state: Vec<u8>,
}

impl fmt::Debug for PasskeyOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasskeyOptions([REDACTED])")
    }
}

/// Constructible only after complete `WebAuthn` registration or authentication verification.
pub struct VerifiedOperatorCredential {
    credential: Credential,
}

impl fmt::Debug for VerifiedOperatorCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedOperatorCredential([REDACTED])")
    }
}

impl VerifiedOperatorCredential {
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        self.credential.cred_id.as_ref()
    }

    /// A versioned, bounded credential representation for server-side storage only.
    ///
    /// # Errors
    /// Returns a non-identifying integrity error if encoding exceeds the storage boundary.
    pub fn to_storage(&self, verifier: &OperatorPasskeyVerifier) -> Result<Vec<u8>, PasskeyError> {
        verifier.save("credential", &self.credential)
    }
}

impl OperatorPasskeyVerifier {
    /// # Errors
    /// Rejects a noncanonical HTTPS origin or an IP literal; device origins are unaffected.
    pub fn new(origin: &str) -> Result<Self, PasskeyError> {
        validate_server_origin(origin).map_err(|_| PasskeyError::Configuration)?;
        let url = Url::parse(origin).map_err(|_| PasskeyError::Configuration)?;
        let rp_id = url.domain().ok_or(PasskeyError::Configuration)?.to_owned();
        let core = WebauthnCore::new_unsafe_experts_only(
            "Scoplen",
            &rp_id,
            vec![url],
            Duration::from_secs(300),
            Some(false),
            Some(false),
        );
        Ok(Self { origin: origin.to_owned(), rp_id, core })
    }

    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// # Errors
    /// Requires a `UUIDv7` user handle and a positive lifetime of at most five minutes.
    pub fn registration_options(
        &self,
        operator_id: Uuid,
        lifetime_seconds: u32,
    ) -> Result<PasskeyOptions, PasskeyError> {
        if operator_id.get_version_num() != 7 || !(1..=300).contains(&lifetime_seconds) {
            return Err(PasskeyError::State);
        }
        let name = format!("operator:{operator_id}");
        let builder = self
            .core
            .new_challenge_register_builder(operator_id.as_bytes(), &name, "Deployment operator")
            .map_err(|_| PasskeyError::State)?
            .credential_algorithms(vec![COSEAlgorithm::ES256])
            .attestation(AttestationConveyancePreference::None)
            .require_resident_key(true)
            .user_verification_policy(UserVerificationPolicy::Required)
            .reject_synchronised_authenticators(false);
        let (options, state) =
            without_library_tracing(|| self.core.generate_challenge_register(builder))
                .map_err(|_| PasskeyError::State)?;
        let mut public_key =
            serde_json::to_value(options.public_key).map_err(|_| PasskeyError::State)?;
        public_key["timeout"] = json!(lifetime_seconds * 1_000);
        // The core owns security policy and state. This projection only removes unused metadata.
        retain_fields(
            &mut public_key,
            &[
                "rp",
                "user",
                "challenge",
                "pubKeyCredParams",
                "timeout",
                "excludeCredentials",
                "authenticatorSelection",
                "attestation",
            ],
        )?;
        public_key["excludeCredentials"] = json!([]);
        retain_fields(
            &mut public_key["authenticatorSelection"],
            &["residentKey", "requireResidentKey", "userVerification"],
        )?;
        Ok(PasskeyOptions { public_key, state: self.save("registration", &state)? })
    }

    /// # Errors
    /// Fails closed if the maintained verifier cannot create fresh authentication state.
    pub fn authentication_options(&self) -> Result<PasskeyOptions, PasskeyError> {
        let builder = self
            .core
            .new_challenge_authenticate_builder(vec![], Some(UserVerificationPolicy::Required))
            .map_err(|_| PasskeyError::State)?;
        let (options, state) =
            without_library_tracing(|| self.core.generate_challenge_authenticate(builder))
                .map_err(|_| PasskeyError::State)?;
        let mut public_key =
            serde_json::to_value(options.public_key).map_err(|_| PasskeyError::State)?;
        retain_fields(
            &mut public_key,
            &["challenge", "timeout", "rpId", "allowCredentials", "userVerification"],
        )?;
        Ok(PasskeyOptions { public_key, state: self.save("authentication", &state)? })
    }

    /// Verify exact transport bytes after the caller has consumed a live, correctly bound ceremony.
    ///
    /// # Errors
    /// Returns one denial for malformed embedded data, flags, keys, policy or attestation.
    pub fn verify_registration(
        &self,
        state: &[u8],
        credential_id: &[u8],
        client_data: &[u8],
        attestation: &[u8],
    ) -> Result<VerifiedOperatorCredential, PasskeyError> {
        let state: RegistrationState = self.restore("registration", state)?;
        check_len(credential_id, 1, 1_023)?;
        check_client_data(client_data, &self.origin)?;
        check_len(attestation, 1, 16_384)?;
        let value = parse_cbor(attestation)?;
        let Cbor::Map(map) = &value else {
            return Err(PasskeyError::Denied);
        };
        let fmt = cbor_member(map, "fmt").ok_or(PasskeyError::Denied)?;
        let statement = cbor_member(map, "attStmt").ok_or(PasskeyError::Denied)?;
        if fmt != &Cbor::Text("none".into()) || !matches!(statement, Cbor::Map(m) if m.is_empty()) {
            return Err(PasskeyError::Denied);
        }
        let Some(Cbor::Bytes(auth_data)) = cbor_member(map, "authData") else {
            return Err(PasskeyError::Denied);
        };
        check_authenticator_data(auth_data, true)?;
        let request: RegisterPublicKeyCredential = serde_json::from_value(json!({
            "id": encode_bytes(credential_id), "rawId": encode_bytes(credential_id), "type": "public-key",
            "response": {"clientDataJSON":encode_bytes(client_data), "attestationObject":encode_bytes(attestation)},
            "extensions": {}
        })).map_err(|_| PasskeyError::Denied)?;
        let credential =
            without_library_tracing(|| self.core.register_credential(&request, &state, None))
                .map_err(|_| PasskeyError::Denied)?;
        if credential.cred_id.as_ref() != credential_id
            || credential.cred.type_ != COSEAlgorithm::ES256
            || !credential.user_verified
            || (credential.backup_state && !credential.backup_eligible)
            || credential.attestation_format != AttestationFormat::None
        {
            return Err(PasskeyError::Denied);
        }
        Ok(VerifiedOperatorCredential { credential })
    }

    /// Verify against the current locked credential, not a snapshot from options issuance.
    ///
    /// # Errors
    /// Returns a generic denial on any assertion or immutable backup-eligibility mismatch.
    pub fn verify_authentication(
        &self,
        state: &[u8],
        credential: &[u8],
        request: &AssertionArtifacts<'_>,
    ) -> Result<VerifiedOperatorCredential, PasskeyError> {
        let mut state: AuthenticationState = self.restore("authentication", state)?;
        let mut credential: Credential = self.restore("credential", credential)?;
        check_len(request.credential_id, 1, 1_023)?;
        check_len(request.signature, 8, 72)?;
        check_client_data(request.client_data, &self.origin)?;
        check_authenticator_data(request.authenticator_data, false)?;
        if credential.cred_id.as_ref() != request.credential_id {
            return Err(PasskeyError::Denied);
        }
        let flags = request.authenticator_data[32];
        let backed_up = flags & 0x10 != 0;
        let eligible = flags & 0x08 != 0;
        if eligible != credential.backup_eligible {
            return Err(PasskeyError::Denied);
        }
        let observed_counter = u32::from_be_bytes(
            request.authenticator_data[33..37].try_into().map_err(|_| PasskeyError::Denied)?,
        );
        let old_counter = credential.counter;
        if !eligible
            && (old_counter != 0 || observed_counter != 0)
            && observed_counter <= old_counter
        {
            return Err(PasskeyError::Denied);
        }
        // Synced authenticators have no monotonic counter guarantee. Core still verifies the
        // original signed bytes; only its comparison baseline is relaxed by this explicit policy.
        if eligible {
            credential.counter = 0;
        }
        state.set_allowed_credentials(vec![credential.clone()]);
        let assertion: PublicKeyCredential = serde_json::from_value(json!({
            "id":encode_bytes(request.credential_id), "rawId":encode_bytes(request.credential_id), "type":"public-key",
            "response":{"clientDataJSON":encode_bytes(request.client_data), "authenticatorData":encode_bytes(request.authenticator_data),
            "signature":encode_bytes(request.signature), "userHandle":encode_bytes(request.user_handle)}, "extensions":{}
        })).map_err(|_| PasskeyError::Denied)?;
        let result =
            without_library_tracing(|| self.core.authenticate_credential(&assertion, &state))
                .map_err(|_| PasskeyError::Denied)?;
        if !result.user_verified() {
            return Err(PasskeyError::Denied);
        }
        credential.counter = old_counter.max(result.counter());
        credential.backup_state = backed_up;
        Ok(VerifiedOperatorCredential { credential })
    }

    fn save<T: Serialize>(&self, purpose: &str, library: &T) -> Result<Vec<u8>, PasskeyError> {
        let bytes = serde_json::to_vec(&Saved {
            version: 1,
            purpose: purpose.into(),
            origin: self.origin.clone(),
            rp_id: self.rp_id.clone(),
            library,
        })
        .map_err(|_| PasskeyError::State)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(PasskeyError::State);
        }
        Ok(bytes)
    }

    fn restore<T: for<'de> Deserialize<'de>>(
        &self,
        purpose: &str,
        bytes: &[u8],
    ) -> Result<T, PasskeyError> {
        if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES {
            return Err(PasskeyError::State);
        }
        unique_json(bytes).map_err(|_| PasskeyError::State)?;
        let saved: Saved<T> = serde_json::from_slice(bytes).map_err(|_| PasskeyError::State)?;
        if saved.version != 1
            || saved.purpose != purpose
            || saved.origin != self.origin
            || saved.rp_id != self.rp_id
        {
            return Err(PasskeyError::State);
        }
        Ok(saved.library)
    }
}

fn without_library_tracing<T>(operation: impl FnOnce() -> T) -> T {
    // The dependency emits submitted artifacts at trace level. Keep even RUST_LOG=trace from
    // disclosing them; the outer service records its own bounded, non-identifying audit.
    tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), operation)
}

/// Exact assertion artifacts; the caller must independently bind `user_handle` to its owner.
pub struct AssertionArtifacts<'a> {
    pub credential_id: &'a [u8],
    pub client_data: &'a [u8],
    pub authenticator_data: &'a [u8],
    pub signature: &'a [u8],
    pub user_handle: &'a [u8; 16],
}

fn retain_fields(value: &mut Value, fields: &[&str]) -> Result<(), PasskeyError> {
    value
        .as_object_mut()
        .ok_or(PasskeyError::State)?
        .retain(|key, _| fields.contains(&key.as_str()));
    Ok(())
}

fn encode_bytes(bytes: &[u8]) -> String {
    use webauthn_rs_core::proto::Base64UrlSafeData;
    serde_json::to_value(Base64UrlSafeData::from(bytes.to_vec()))
        .expect("byte string serializes")
        .as_str()
        .expect("byte string is JSON text")
        .to_owned()
}

fn check_len(bytes: &[u8], min: usize, max: usize) -> Result<(), PasskeyError> {
    if (min..=max).contains(&bytes.len()) { Ok(()) } else { Err(PasskeyError::Denied) }
}

fn check_client_data(bytes: &[u8], origin: &str) -> Result<(), PasskeyError> {
    check_len(bytes, 1, 4_096)?;
    unique_json(bytes)?;
    let json: Value = serde_json::from_slice(bytes).map_err(|_| PasskeyError::Denied)?;
    let map = json.as_object().ok_or(PasskeyError::Denied)?;
    if map.get("origin").and_then(Value::as_str) != Some(origin)
        || map.contains_key("topOrigin")
        || map.get("crossOrigin").is_some_and(|v| v != &Value::Bool(false))
    {
        return Err(PasskeyError::Denied);
    }
    Ok(())
}

fn cbor_member<'a>(map: &'a [(Cbor, Cbor)], key: &str) -> Option<&'a Cbor> {
    map.iter().find_map(|(k, v)| (k == &Cbor::Text(key.into())).then_some(v))
}

fn read_cbor(cursor: &mut Cursor<&[u8]>) -> Result<Cbor, PasskeyError> {
    let value: Cbor = ciborium::de::from_reader(cursor).map_err(|_| PasskeyError::Denied)?;
    check_cbor(&value, 0)?;
    Ok(value)
}

fn parse_cbor(bytes: &[u8]) -> Result<Cbor, PasskeyError> {
    let mut cursor = Cursor::new(bytes);
    let value = read_cbor(&mut cursor)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(PasskeyError::Denied);
    }
    Ok(value)
}

fn check_cbor(value: &Cbor, depth: usize) -> Result<(), PasskeyError> {
    if depth > 16 {
        return Err(PasskeyError::Denied);
    }
    match value {
        Cbor::Map(entries) => {
            for (index, (key, value)) in entries.iter().enumerate() {
                if entries[..index].iter().any(|(earlier, _)| earlier == key) {
                    return Err(PasskeyError::Denied);
                }
                check_cbor(key, depth + 1)?;
                check_cbor(value, depth + 1)?;
            }
        }
        Cbor::Array(items) => {
            for item in items {
                check_cbor(item, depth + 1)?;
            }
        }
        Cbor::Tag(_, inner) => check_cbor(inner, depth + 1)?,
        _ => {}
    }
    Ok(())
}

fn check_authenticator_data(bytes: &[u8], registration: bool) -> Result<(), PasskeyError> {
    check_len(bytes, 37, if registration { 16_384 } else { 4_096 })?;
    let flags = bytes[32];
    if flags & 5 != 5
        || (flags & 0x10 != 0 && flags & 0x08 == 0)
        || (flags & 0x40 != 0) != registration
    {
        return Err(PasskeyError::Denied);
    }
    let mut offset = 37;
    if registration {
        if bytes.len() < 55 {
            return Err(PasskeyError::Denied);
        }
        offset = 55 + usize::from(u16::from_be_bytes([bytes[53], bytes[54]]));
        if offset >= bytes.len() {
            return Err(PasskeyError::Denied);
        }
        let mut cursor = Cursor::new(&bytes[offset..]);
        if !matches!(read_cbor(&mut cursor)?, Cbor::Map(_)) {
            return Err(PasskeyError::Denied);
        }
        offset += usize::try_from(cursor.position()).map_err(|_| PasskeyError::Denied)?;
    }
    if flags & 0x80 != 0 {
        if !matches!(parse_cbor(&bytes[offset..])?, Cbor::Map(_)) {
            return Err(PasskeyError::Denied);
        }
    } else if offset != bytes.len() {
        return Err(PasskeyError::Denied);
    }
    Ok(())
}

struct UniqueJson;
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON without duplicate names")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut names = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !names.insert(key) {
                        return Err(de::Error::custom("duplicate JSON name"));
                    }
                    map.next_value::<UniqueJson>()?;
                }
                Ok(UniqueJson)
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                while seq.next_element::<UniqueJson>()?.is_some() {}
                Ok(UniqueJson)
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

fn unique_json(bytes: &[u8]) -> Result<(), PasskeyError> {
    serde_json::from_slice::<UniqueJson>(bytes).map(|_| ()).map_err(|_| PasskeyError::Denied)
}
