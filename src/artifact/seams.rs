//! The host-injected materializer seams: `InputResolver` (+ the v1 `SameTargetOrSourceResolver`) and
//! `BlobStore` (+ the v1 `InMemoryBlobStore`) — carved out of `artifact.rs`.

use super::{ArtifactProducer, ArtifactRef, GeneratingActionKey};
use razel_analysis::{ConfiguredTarget, ConfiguredTargetKey};
use razel_core::{Digest, Error};
use std::collections::HashMap;
use std::sync::Mutex;

// ──────────────── the materializer seams (host-injected — compile walls at inception; E/G) ────────────────

/// Input materialization is a GRAPH lookup, never a disk lookup (decision E): maps one template input path
/// to its producer reference. Fail-closed: an unknown/absolute form is a typed error, NEVER a skipped edge
/// or a fabricated empty input (the Absorb shape §0 forbids).
pub trait InputResolver: Send + Sync {
    fn resolve(&self, owner: &ConfiguredTargetKey, ct: &ConfiguredTarget, input_path: &str) -> Result<ArtifactRef, Error>;
}

/// The v1 resolver policy (lockdown §3, extended by the files-chaining slice): a path matching a sibling
/// action's declared output → `Derived{own ct, idx}`; a path matching a DIRECT dep's declared output (the
/// owner CT's `dep_outputs` chaining map, stamped at analysis from the deps' `{providers, actions}`) →
/// `Derived{producer ct, idx}` — "my inputs are my dep's outputs", the Bazel providers-carry-DerivedArtifacts
/// shape with the map riding the CT VALUE (no key reshape); any other root-relative forward path → `Source`
/// (fail-closed at the `FILE` node: a path that is neither a source file on disk nor a mapped output is a
/// typed `NotFound` there, never absorbed); unknown forms (empty, absolute, up-level) → typed `Unsupported`.
pub struct SameTargetOrSourceResolver;
impl InputResolver for SameTargetOrSourceResolver {
    fn resolve(&self, owner: &ConfiguredTargetKey, ct: &ConfiguredTarget, input_path: &str) -> Result<ArtifactRef, Error> {
        if input_path.is_empty() || input_path.starts_with('/') || input_path.split('/').any(|seg| seg == "..") {
            return Err(Error::Unsupported {
                what: "input path form",
                detail: format!(
                    "cannot resolve input '{}' of //{}:{}: only root-relative forward paths are supported (v1 SameTargetOrSource policy)",
                    input_path, owner.package, owner.name
                ),
            });
        }
        // (1) a sibling action's declared output (same target — the pre-chaining v1 policy, kept first:
        // within one target the declaring action is the authority).
        for (idx, tmpl) in ct.actions.iter().enumerate() {
            if tmpl.outputs.iter().any(|o| o == input_path) {
                return Ok(ArtifactRef {
                    exec_path: input_path.to_string(),
                    producer: ArtifactProducer::Derived(GeneratingActionKey {
                        owner: owner.clone(),
                        action_index: idx as u32,
                    }),
                });
            }
        }
        // (2) a DIRECT dep's declared output — the files-chaining map (analysis stamped exec_path →
        // {producer CT, action index}; the producer CT key carries the threaded configuration, so the
        // Derived ref names the exact analyzed dep node the engine already holds).
        if let Some(d) = ct.dep_outputs.iter().find(|d| d.exec_path == input_path) {
            return Ok(ArtifactRef {
                exec_path: input_path.to_string(),
                producer: ArtifactProducer::Derived(GeneratingActionKey {
                    owner: d.producer_ct.clone(),
                    action_index: d.action_index,
                }),
            });
        }
        Ok(ArtifactRef { exec_path: input_path.to_string(), producer: ArtifactProducer::Source })
    }
}

/// The ONE bytes home (decision G / R5): an in-memory CAS in v1 (an on-disk/remote CAS later is a seam-impl
/// swap with ZERO value-shape churn). Node values stay metadata-only — bytes NEVER enter a `NodeValue`.
pub trait BlobStore: Send + Sync {
    fn put(&self, bytes: &[u8]) -> Digest;
    /// Absent = a typed error, never empty bytes (no Absorb).
    fn get(&self, digest: &Digest) -> Result<Vec<u8>, Error>;
}

/// The v1 in-memory CAS.
pub struct InMemoryBlobStore {
    map: Mutex<HashMap<Digest, Vec<u8>>>,
}
impl InMemoryBlobStore {
    pub fn new() -> Self {
        Self { map: Mutex::new(HashMap::new()) }
    }
}
impl Default for InMemoryBlobStore {
    fn default() -> Self {
        Self::new()
    }
}
impl BlobStore for InMemoryBlobStore {
    fn put(&self, bytes: &[u8]) -> Digest {
        let d = Digest::of(bytes);
        self.map.lock().unwrap().insert(d, bytes.to_vec());
        d
    }
    fn get(&self, digest: &Digest) -> Result<Vec<u8>, Error> {
        match self.map.lock().unwrap().get(digest) {
            Some(b) => Ok(b.clone()),
            // MUTANT: a missing digest is absorbed into EMPTY BYTES instead of a typed NotFound — the
            // exact "just pass empty content" Absorb shape §0 forbids. `blobstore_missing_digest_fails_closed`
            // goes red.
            None if cfg!(feature = "mutant_blobstore_get_defaults") => Ok(Vec::new()),
            None => Err(Error::NotFound { what: "blob".into(), detail: digest.to_hex() }),
        }
    }
}

// RESERVED, NOT BUILT (decision G / R4): disk staging behind the strategy —
// `stage(sorted {exec-root-relative path → digest}, &dyn BlobStore) → exec root` — the (mapping, metadata)
// pair IS Bazel's frozen no-I/O expander signature (`SpawnInputExpander`). It is strategy-PRIVATE: no
// engine contract ever sees a `HostPath` (REQ-PATHENV-007). Building it belongs to the os-system row's
// reconcile + a real local strategy (lockdown §6.5), invisible to every surface frozen here.

