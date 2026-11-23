// SPDX-License-Identifier: AGPL-3.0-only
//! ES256 validation for the draft login's code-flow ID Token.

use std::borrow::Cow;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_crypto::{SecretBytes, SecretVec, p256_verify};
use serde::{Deserialize, Deserializer, de};
use sha2::{Digest as _, Sha256};

use super::DraftExchangeError as Error;

const ISSUED_AT_SKEW_SECONDS: i64 = 60;

pub(super) struct IdToken<'a> {
    header: Header,
    signing_input: &'a str,
    payload: &'a str,
    signature: [u8; 64],
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
    typ: Option<String>,
    #[serde(default, rename = "crit", deserialize_with = "reject_extension")]
    _critical: (),
    #[serde(default, rename = "b64", deserialize_with = "reject_extension")]
    _payload_encoding: (),
}

fn reject_extension<'de, D: Deserializer<'de>>(_: D) -> Result<(), D::Error> {
    Err(de::Error::custom("unsupported JOSE extension"))
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience<'a> {
    One(Cow<'a, str>),
    List(Vec<Cow<'a, str>>),
}

#[derive(Deserialize)]
struct Claims<'a> {
    #[serde(borrow)]
    iss: Cow<'a, str>,
    #[serde(borrow)]
    sub: Cow<'a, str>,
    #[serde(borrow)]
    aud: Audience<'a>,
    #[serde(borrow)]
    azp: Option<Cow<'a, str>>,
    #[serde(borrow)]
    nonce: Cow<'a, str>,
    #[serde(borrow)]
    at_hash: Option<Cow<'a, str>>,
    #[serde(borrow)]
    c_hash: Option<Cow<'a, str>>,
    exp: i64,
    iat: i64,
    nbf: Option<i64>,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: Option<String>,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    key_ops: Option<Vec<String>>,
    x: Option<String>,
    y: Option<String>,
}

impl Jwk {
    fn eligible(&self, kid: Option<&str>) -> bool {
        self.kty == "EC"
            && self.crv.as_deref() == Some("P-256")
            && self.alg.as_deref().is_none_or(|alg| alg == "ES256")
            && self.usage.as_deref().is_none_or(|usage| usage == "sig")
            && self.key_ops.as_ref().is_none_or(|ops| ops.iter().any(|op| op == "verify"))
            && kid.is_none_or(|kid| self.kid.as_deref() == Some(kid))
    }

    fn public_key(&self) -> Option<[u8; 65]> {
        let mut public_key = [0; 65];
        public_key[0] = 4;
        public_key[1..33].copy_from_slice(&decode_fixed::<32>(self.x.as_deref()?)?);
        public_key[33..].copy_from_slice(&decode_fixed::<32>(self.y.as_deref()?)?);
        Some(public_key)
    }
}

fn decode_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    let mut bytes = [0; N];
    (URL_SAFE_NO_PAD.decode_slice(value, &mut bytes).ok()? == N).then_some(bytes)
}

fn matches_hash(expected: &str, value: &[u8]) -> bool {
    let computed = Sha256::digest(value);
    decode_fixed::<16>(expected).is_some_and(|expected| {
        SecretBytes::from_slice(&computed[..16]) == Some(SecretBytes::new(expected))
    })
}

pub(super) struct ExpectedClaims<'a> {
    pub issuer: &'a str,
    pub client: &'a str,
    pub access_token: &'a str,
    pub code: &'a [u8],
    pub now: i64,
}

impl<'a> IdToken<'a> {
    pub(super) fn parse(compact: &'a str) -> Result<Self, Error> {
        let invalid = Error::InvalidIdentity;
        let (signing_input, signature) = compact.rsplit_once('.').ok_or(invalid)?;
        let (header, payload) = signing_input.split_once('.').ok_or(invalid)?;
        if payload.is_empty()
            || !payload
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_'))
        {
            return Err(invalid);
        }
        let header = URL_SAFE_NO_PAD.decode(header).map_err(|_| invalid)?;
        let header: Header = serde_json::from_slice(&header).map_err(|_| invalid)?;
        if header.alg != "ES256"
            || header.kid.as_ref().is_some_and(String::is_empty)
            || header.typ.as_deref().is_some_and(|typ| !typ.eq_ignore_ascii_case("JWT"))
        {
            return Err(invalid);
        }
        let signature = decode_fixed(signature).ok_or(invalid)?;
        Ok(Self { header, signing_input, payload, signature })
    }

    pub(super) fn verify(
        &self,
        jwks: &[u8],
        expected: &ExpectedClaims<'_>,
        matches_nonce: impl FnOnce(&SecretBytes<32>) -> bool,
    ) -> Result<(), Error> {
        let invalid = Error::InvalidIdentity;
        let set: JwkSet = serde_json::from_slice(jwks).map_err(|_| invalid)?;
        let mut keys = set.keys.iter().filter(|key| key.eligible(self.header.kid.as_deref()));
        let key = keys.next().and_then(Jwk::public_key).ok_or(invalid)?;
        if keys.next().is_some() {
            return Err(invalid);
        }
        p256_verify(&key, self.signing_input.as_bytes(), &self.signature).map_err(|_| invalid)?;
        let payload = SecretVec::new(URL_SAFE_NO_PAD.decode(self.payload).map_err(|_| invalid)?);
        let claims: Claims<'_> = serde_json::from_slice(payload.as_bytes()).map_err(|_| invalid)?;
        let client = match &claims.aud {
            Audience::One(client) => client,
            Audience::List(clients) => match clients.as_slice() {
                [client] => client,
                _ => return Err(invalid),
            },
        };
        if claims.iss != expected.issuer
            || client != expected.client
            || claims.azp.as_deref().is_some_and(|azp| azp != expected.client)
            || claims.sub.trim().is_empty()
            || claims.sub.len() > 255
            || !claims.sub.bytes().all(|byte| byte.is_ascii() && !byte.is_ascii_control())
            || claims.iat <= 0
            || claims.iat > expected.now.saturating_add(ISSUED_AT_SKEW_SECONDS)
            || claims.exp <= expected.now.max(claims.iat)
            || claims.nbf.is_some_and(|nbf| nbf > expected.now)
            || claims
                .at_hash
                .as_deref()
                .is_some_and(|hash| !matches_hash(hash, expected.access_token.as_bytes()))
            || claims.c_hash.as_deref().is_some_and(|hash| !matches_hash(hash, expected.code))
        {
            return Err(invalid);
        }
        match decode_fixed(&claims.nonce).map(SecretBytes::new) {
            Some(nonce) if matches_nonce(&nonce) => Ok(()),
            _ => Err(invalid),
        }
    }
}

#[cfg(test)]
mod tests {
    use scoplen_crypto::P256SigningKey;
    use serde_json::{Value, json};

    use super::*;

    fn sign(key: &P256SigningKey, header: &Value, claims: &Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let input = format!("{header}.{claims}");
        let signature = key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    #[test]
    fn id_token_verification_binds_signer_audience_nonce_and_time() {
        let key = P256SigningKey::from_bytes(&[7; 32]).unwrap();
        let wrong = P256SigningKey::from_bytes(&[9; 32]).unwrap();
        let sec1 = key.public_key_sec1();
        let jwk = json!({
            "kty":"EC", "crv":"P-256", "kid":"issuer-key", "alg":"ES256", "use":"sig", "key_ops":["verify"],
            "x":URL_SAFE_NO_PAD.encode(&sec1[1..33]), "y":URL_SAFE_NO_PAD.encode(&sec1[33..]),
        });
        let jwks = json!({"keys":[jwk]});
        let expected = ExpectedClaims {
            issuer: "https://identity.example.test/tenant/",
            client: "draft-client",
            access_token: "fixture-access-token",
            code: b"fixture-code",
            now: 10_000,
        };
        let nonce = SecretBytes::new([8; 32]);
        let header = json!({"alg":"ES256", "kid":"issuer-key", "typ":"JWT"});
        let claims = json!({
            "iss":expected.issuer, "sub":"opaque-human-subject", "aud":[expected.client],
            "iat":9_999, "exp":10_001, "nonce":URL_SAFE_NO_PAD.encode(nonce.as_bytes()),
            "at_hash":URL_SAFE_NO_PAD.encode(&Sha256::digest(expected.access_token.as_bytes())[..16]),
            "c_hash":URL_SAFE_NO_PAD.encode(&Sha256::digest(expected.code)[..16]),
        });
        let verify = |header: &Value, claims: &Value, signer, jwks: &Value| {
            let compact = sign(signer, header, claims);
            IdToken::parse(&compact)?.verify(
                &serde_json::to_vec(jwks).unwrap(),
                &expected,
                |actual| actual == &nonce,
            )
        };
        assert_eq!(verify(&header, &claims, &key, &jwks), Ok(()));
        assert_eq!(verify(&header, &claims, &wrong, &jwks), Err(Error::InvalidIdentity));
        let duplicates = json!({"keys":[jwk, jwk]});
        assert_eq!(verify(&header, &claims, &key, &duplicates), Err(Error::InvalidIdentity));
        for (claim, invalid_value) in [
            ("iss", json!("https://identity.example.test/other/")),
            ("aud", json!([expected.client, "extra"])),
            ("azp", json!("another-client")),
            ("sub", json!(" ")),
            ("exp", json!(expected.now)),
            ("iat", json!(expected.now + 61)),
            ("nbf", json!(expected.now + 1)),
            ("nonce", json!(URL_SAFE_NO_PAD.encode([0; 32]))),
            ("at_hash", json!(URL_SAFE_NO_PAD.encode([0; 16]))),
            ("c_hash", json!(URL_SAFE_NO_PAD.encode([0; 16]))),
        ] {
            let mut changed = claims.clone();
            changed[claim] = invalid_value;
            assert_eq!(
                verify(&header, &changed, &key, &jwks),
                Err(Error::InvalidIdentity),
                "{claim}"
            );
        }
        for (field, invalid_value) in [
            ("alg", json!("HS256")),
            ("kid", json!("unknown")),
            ("typ", json!("at+jwt")),
            ("crit", json!(["extension"])),
            ("b64", json!(false)),
        ] {
            let mut changed = header.clone();
            changed[field] = invalid_value;
            assert_eq!(
                verify(&changed, &claims, &key, &jwks),
                Err(Error::InvalidIdentity),
                "{field}"
            );
        }
    }
}
