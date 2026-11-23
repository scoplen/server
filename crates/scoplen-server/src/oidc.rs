// SPDX-License-Identifier: AGPL-3.0-only
//! Human OIDC discovery for the local diagnostic and trusted Organization login tests.

use scoplen_api::auth_connection_draft::callback::IssuerIdentification;
use serde::Deserialize;
use url::{Origin, Url};

mod exchange;
mod id_token;
#[cfg(test)]
pub(crate) mod provider_test;
mod trust;
pub use exchange::{DraftExchangeError, verify_claimed_draft_login};
pub use trust::{DiscoveryError, TrustedIssuer};

/// Endpoints and issuer identification accepted for a single draft login attempt.
pub struct ProviderMetadata {
    /// Same-origin absolute authorization endpoint for the browser.
    pub authorization_endpoint: String,
    /// Same-origin absolute token endpoint for the confidential exchange.
    pub token_endpoint: String,
    /// Same-origin absolute `UserInfo` endpoint advertised by the issuer.
    pub userinfo_endpoint: String,
    /// Same-origin absolute JWKS endpoint for verification.
    pub jwks_uri: String,
    /// Issuer identification mode advertised by the provider.
    pub issuer_identification: IssuerIdentification,
}

/// Check the human sign-in capabilities for the operator's read-only diagnostic.
///
/// # Errors
/// Returns a fixed diagnostic for invalid metadata, issuer mismatch or missing capabilities.
pub fn check_discovery(body: &[u8], issuer: &str) -> Result<(), &'static str> {
    parse_discovery(body)?.check(issuer, None)
}

fn parse_discovery(body: &[u8]) -> Result<Discovery, &'static str> {
    serde_json::from_slice(body).map_err(
        |_| "invalid discovery document; check its JSON, field types and required endpoints.",
    )
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    response_types_supported: Vec<String>,
    grant_types_supported: Option<Vec<String>>,
    #[serde(default = "default_token_auth_methods")]
    token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    scopes_supported: Vec<String>,
    #[serde(default)]
    subject_types_supported: Vec<String>,
    #[serde(default)]
    id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    authorization_response_iss_parameter_supported: bool,
}

fn default_token_auth_methods() -> Vec<String> {
    vec!["client_secret_basic".to_owned()]
}

fn https_url(value: &str) -> Option<Url> {
    if value.bytes().any(|b| b.is_ascii_control() || b == b' ' || b == b'\\') {
        return None;
    }
    let (_, tail) = value.split_once("://")?;
    let authority = tail.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let url = Url::parse(value).ok()?;
    (url.scheme() == "https"
        && url.has_host()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none())
    .then_some(url)
}

impl Discovery {
    fn check(
        &self,
        expected_issuer: &str,
        expected_origin: Option<&Origin>,
    ) -> Result<(), &'static str> {
        if self.issuer != expected_issuer {
            return Err("issuer mismatch; use the exact issuer configured by the instance.");
        }
        for endpoint in [
            &self.authorization_endpoint,
            &self.token_endpoint,
            &self.userinfo_endpoint,
            &self.jwks_uri,
        ] {
            let url = https_url(endpoint).ok_or(
                "an advertised endpoint is invalid; require absolute HTTPS endpoints without credentials or fragments.",
            )?;
            if expected_origin
                .is_some_and(|origin| url.origin() != *origin || url.query().is_some())
            {
                return Err(
                    "advertised endpoints must use the issuer's HTTPS origin without a query.",
                );
            }
        }
        if self
            .grant_types_supported
            .as_ref()
            .is_some_and(|grants| !grants.iter().any(|g| g == "authorization_code"))
        {
            return Err("the instance does not advertise the authorization code grant.");
        }
        for (values, expected, reason) in [
            (
                &self.token_endpoint_auth_methods_supported,
                "client_secret_basic",
                "the instance must support client_secret_basic for confidential web clients.",
            ),
            (
                &self.response_types_supported,
                "code",
                "the instance must advertise the code response type.",
            ),
            (
                &self.code_challenge_methods_supported,
                "S256",
                "the instance must advertise S256 PKCE.",
            ),
            (
                &self.scopes_supported,
                "openid",
                "the instance must advertise the openid scope for human login.",
            ),
            (
                &self.subject_types_supported,
                "public",
                "the instance must advertise public human subjects.",
            ),
            (
                &self.id_token_signing_alg_values_supported,
                "ES256",
                "the instance must advertise ES256 ID tokens.",
            ),
        ] {
            if !values.iter().any(|v| v == expected) {
                return Err(reason);
            }
        }
        Ok(())
    }

    fn into_metadata(self) -> ProviderMetadata {
        ProviderMetadata {
            authorization_endpoint: self.authorization_endpoint,
            token_endpoint: self.token_endpoint,
            userinfo_endpoint: self.userinfo_endpoint,
            jwks_uri: self.jwks_uri,
            issuer_identification: if self.authorization_response_iss_parameter_supported {
                IssuerIdentification::ResponseParameter
            } else {
                IssuerIdentification::ExclusiveCallback
            },
        }
    }
}
