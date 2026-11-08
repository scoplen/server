// SPDX-License-Identifier: AGPL-3.0-only
//! Organization-owned local user-CA custody and scoped SSH certificate signing.

#![forbid(unsafe_code)]

mod local_user;

pub use local_user::{
    DEFAULT_USER_CERTIFICATE_TTL_SECONDS, LocalUserCa, LocalUserCaError, UserCertificateContext,
};
