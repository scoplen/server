// SPDX-License-Identifier: AGPL-3.0-only
//! Positive unsigned credential generations use the same fixed-width storage on both stores.

pub(crate) fn decode(bytes: &[u8]) -> Option<u64> {
    let generation = u64::from_be_bytes(bytes.try_into().ok()?);
    (generation > 0).then_some(generation)
}
