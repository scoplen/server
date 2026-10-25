// SPDX-License-Identifier: AGPL-3.0-only
//! Identity verification for independently authenticated deployment Operators.

#![forbid(unsafe_code)]

pub mod operator_passkeys;

/// The identity contract implemented by this crate.
pub const COMPONENT: &str = "identity";
