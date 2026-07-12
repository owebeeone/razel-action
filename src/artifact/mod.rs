//! The artifact vocabulary of the ratified artifact-model / action-demand-chain lockdown
//! (`RazelV4ArtifactModelLockdown.md` §2, RATIFIED 2026-07-06): the positional `ACTION` node key
//! (`GeneratingActionKey`), the artifact identity (`ArtifactRef`/`ArtifactProducer`) + its metadata-only
//! value (`ArtifactValue`), the `TARGET_COMPLETION` node, the shared pure `derived_outputs` fn (the R8
//! demand-time duplicate-output conflict pass), and the two host-injected materializer seams
//! (`InputResolver`, `BlobStore`). This module is the `artifact-model` row's vocabulary — when that row
//! promotes it can move to its own `razel-artifact` crate mechanically (lockdown §3).
//!
//! Frozen-unless-thawed (lockdown §6): the key shapes, their canonical encodes, the §2 demand chain, and
//! the two seam signatures. Codec discipline is the house rule: length-framed u64-BE, lossless
//! `decode(encode(k)) == k`, fail-closed decode (typed `Error::Invalid`, `checked_add`, trailing-bytes
//! rejection), tag-encoded sentinels (ADR-0010 discipline) — and the CT identity has ONE encoding
//! (`ConfiguredTargetKey::encode` / `razel_analysis::decode_ct_key`), never a second channel.
//!
//! Carved across cohesion submodules ([`codec`], [`keys`], [`seams`], [`nodes`]); this spine re-exports
//! the whole surface so every `crate::artifact::X` path (and `lib.rs`'s `pub use artifact::{…}`) resolves
//! unchanged.

mod codec;
mod keys;
mod nodes;
mod seams;

pub use keys::*;
pub use nodes::*;
pub use seams::*;
pub(crate) use codec::*;

#[cfg(test)]
pub(crate) mod testctx;
#[cfg(test)]
mod tests;
