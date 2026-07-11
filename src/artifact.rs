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

use crate::ARTIFACT;
use crate::TARGET_COMPLETION;
use razel_analysis::{decode_ct_key, ConfiguredTarget, ConfiguredTargetKey};
use razel_core::{Digest, Error, Key, KindId, NodeKey, Value, ValuePolicy};
use razel_engine_api::{ComputeResult, Demand, DemandContext, NodeFunction};
use razel_ids::RootRelativePath;
use razel_os_api::{HostPath, System};
use razel_source::{join_root, FileKey, FileValue};
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ──────────────── GeneratingActionKey — the POSITIONAL `ACTION` node key (decision B / R1) ────────────────

/// The `ACTION` (KindId 60) node key: **positional** — the declaring analysis node + the action's position
/// in its declared-action list (declaration order, deterministic). Bazel's `ActionLookupData{owner, index}`.
/// Positional keys dirty-in-place: an analysis edit changes the CT value, the SAME `ACTION{owner,idx}` node
/// recomputes, and unchanged outputs cut off downstream — a content node-key can never grow input edges
/// (the §0 bootstrap paradox) and churns keys per input edit. The frozen 8-dim [`crate::ActionKey`] is NOT
/// this key: it is the in-node content FINGERPRINT, computed inside `compute()` after inputs resolve
/// (the `RazelV4ActionKeyLockdown.md` thaw amendment, 2026-07-06).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct GeneratingActionKey {
    /// The declaring analysis node (razel's `ActionLookupKey`).
    pub owner: ConfiguredTargetKey,
    /// Position in `ConfiguredTarget.actions` (declaration order, deterministic).
    pub action_index: u32,
}
impl Key for GeneratingActionKey {
    fn kind(&self) -> KindId {
        crate::ACTION
    }
    /// Canonical encode (lockdown §2): the owner CT-key canonical bytes, length-framed — the ONE encoding
    /// of CT identity, no second channel — then the u32-BE index. Fail-closed decode below; an old
    /// content-encoded ACTION byte string decodes to a typed `Error::Invalid`, never an alias.
    fn encode(&self) -> Vec<u8> {
        let owner = self.owner.encode();
        let mut b = Vec::with_capacity(8 + owner.len() + 4);
        b.extend_from_slice(&(owner.len() as u64).to_be_bytes());
        b.extend_from_slice(&owner);
        b.extend_from_slice(&self.action_index.to_be_bytes());
        b
    }
}

/// A fail-closed byte cursor shared by this module's decoders (and the fingerprint decoder in `lib.rs`).
/// Malformed input is a typed `Error::Invalid` — `checked_add` (no overflow panic), bounds-checked takes.
pub(crate) struct Cur<'a> {
    b: &'a [u8],
    i: usize,
    what: &'static str,
}
impl<'a> Cur<'a> {
    pub(crate) fn new(b: &'a [u8], what: &'static str) -> Self {
        Self { b, i: 0, what }
    }
    pub(crate) fn err(&self, detail: &str) -> Error {
        Error::Invalid { what: self.what.into(), detail: detail.into() }
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.i.checked_add(n).ok_or_else(|| self.err("length overflow"))?;
        if end > self.b.len() {
            return Err(self.err("truncated"));
        }
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        let raw = self.take(8)?;
        let arr: [u8; 8] = raw.try_into().map_err(|_| self.err("bad u64"))?;
        Ok(u64::from_be_bytes(arr))
    }
    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        let raw = self.take(4)?;
        let arr: [u8; 4] = raw.try_into().map_err(|_| self.err("bad u32"))?;
        Ok(u32::from_be_bytes(arr))
    }
    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>, Error> {
        let n = self.u64()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    pub(crate) fn str(&mut self) -> Result<String, Error> {
        String::from_utf8(self.bytes()?).map_err(|_| self.err("non-utf8"))
    }
    pub(crate) fn finish(&self) -> Result<(), Error> {
        if self.i != self.b.len() {
            return Err(self.err("trailing bytes"));
        }
        Ok(())
    }
}

/// Decode the length-framed owner CT key + verify the frame is the CANONICAL encoding (re-encode must be
/// byte-identical) — the "ONE encoding of CT identity" rule: a padded/non-canonical frame can never alias.
fn take_owner(c: &mut Cur<'_>) -> Result<ConfiguredTargetKey, Error> {
    let n = c.u64()? as usize;
    let owner_bytes = c.take(n)?;
    let owner = decode_ct_key(owner_bytes)?;
    if owner.encode() != owner_bytes {
        return Err(c.err("non-canonical owner CT-key frame"));
    }
    Ok(owner)
}

/// Decode an `ACTION` node-key's canonical bytes. Fail-closed: malformed/truncated/trailing input — and in
/// particular a PRE-RE-KEY content-encoded (8-dim `ActionKey`) byte string — is a typed `Error::Invalid`,
/// never a panic, never an alias of a positional key.
pub fn decode_generating_action_key(bytes: &[u8]) -> Result<GeneratingActionKey, Error> {
    let mut c = Cur::new(bytes, "ACTION key");
    let owner = take_owner(&mut c)?;
    let action_index = c.u32()?;
    c.finish()?;
    Ok(GeneratingActionKey { owner, action_index })
}

// ──────────────── ArtifactRef / ArtifactProducer / ArtifactValue (decisions A + C) ────────────────

/// Who produces an artifact's content. Derived-artifact identity is exec-path + PRODUCING-ACTION reference,
/// stamped at analysis — never a content address (the content does not exist until the producer runs; R3).
///
/// RESERVED (R6): `TreeChild { parent, rel }` — the tree-artifact child, whose key composes from the parent
/// (`parent.exec_path + rel`, inherited owner; Bazel `Artifact.java:1182-1194`). Reserved as a fail-closed
/// CONSTRUCTOR path ([`ArtifactProducer::tree_child`]) + a reserved codec tag (2) — trees land later as a
/// constructor seam, never a key-schema change. Middlemen are NEVER reserved (deleted from Bazel).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum ArtifactProducer {
    /// A workspace source file — the ARTIFACT node delegates to `FILE` (invalidation) + `sys.read` (bytes),
    /// the razel-load pattern (decision G).
    Source,
    /// The stamped generating action (owner + index).
    Derived(GeneratingActionKey),
}
impl ArtifactProducer {
    /// RESERVED constructor (R6), fail-closed: tree artifacts are deferred wholesale. When they land, this
    /// constructor composes the child key from its parent (exec_path + rel, inherited owner) — until then it
    /// is a typed `Unsupported`, never a fabricated producer.
    pub fn tree_child(_parent: &ArtifactRef, _rel: &str) -> Result<ArtifactProducer, Error> {
        Err(Error::Unsupported {
            what: "tree artifacts",
            detail: "TreeChild is a reserved constructor (lockdown R6): tree artifacts are deferred; codec tag 2 is reserved".into(),
        })
    }
}

/// The artifact identity (decision A): BOTH the value-level reference analysis stamps and the `ARTIFACT`
/// node key (KindId 61). Content addressing lives at the VALUE/digest layer, never here.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ArtifactRef {
    pub exec_path: String,
    pub producer: ArtifactProducer,
}
impl Key for ArtifactRef {
    fn kind(&self) -> KindId {
        ARTIFACT
    }
    /// Canonical encode: exec_path frame, then the producer tag — `0` = Source, `1` = Derived followed by
    /// the `GeneratingActionKey` frames (self-delimiting), `2` = RESERVED TreeChild (decode fails closed).
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&(self.exec_path.len() as u64).to_be_bytes());
        b.extend_from_slice(self.exec_path.as_bytes());
        match &self.producer {
            ArtifactProducer::Source => b.push(0),
            ArtifactProducer::Derived(g) => {
                b.push(1);
                b.extend_from_slice(&g.encode());
            }
        }
        b
    }
}

/// Decode an `ARTIFACT` node-key's canonical bytes. Fail-closed; the reserved TreeChild tag (2) is a typed
/// `Error::Invalid` until trees land — never a silently-different producer.
pub fn decode_artifact_ref(bytes: &[u8]) -> Result<ArtifactRef, Error> {
    let mut c = Cur::new(bytes, "ARTIFACT key");
    let exec_path = c.str()?;
    let producer = match c.take(1)?[0] {
        0 => ArtifactProducer::Source,
        1 => {
            let owner = take_owner(&mut c)?;
            let action_index = c.u32()?;
            ArtifactProducer::Derived(GeneratingActionKey { owner, action_index })
        }
        2 => return Err(c.err("reserved TreeChild producer tag (R6): tree artifacts are deferred")),
        t => {
            return Err(Error::Invalid {
                what: "ARTIFACT key".into(),
                detail: format!("bad producer tag {t}"),
            })
        }
    };
    c.finish()?;
    Ok(ArtifactRef { exec_path, producer })
}

/// `ARTIFACT` value: metadata ONLY — the one `{exec_path, digest}` entry (never bytes, never host paths;
/// R5). Comparable ⇒ the frozen engine's `value_eq` pruning gives per-output early cutoff (decision C).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ArtifactValue {
    pub exec_path: String,
    pub digest: Digest,
}
impl Value for ArtifactValue {
    fn policy(&self) -> ValuePolicy {
        ValuePolicy { comparable: true, always_dirty: false, shareable: true, serializable: true, process_local: false }
    }
    fn value_eq(&self, other: &dyn Value) -> bool {
        other.as_any().downcast_ref::<ArtifactValue>().is_some_and(|o| o == self)
    }
    fn content_digest(&self) -> Digest {
        let mut b = Vec::new();
        b.extend_from_slice(&(self.exec_path.len() as u64).to_be_bytes());
        b.extend_from_slice(self.exec_path.as_bytes());
        b.extend_from_slice(self.digest.to_hex().as_bytes());
        Digest::of(&b)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ──────────────── TARGET_COMPLETION (KindId 62; decision D / R7) ────────────────

/// The output-selection dimension (Bazel's `TopLevelArtifactContext` dim) — in the key from commit 1 (R7),
/// tag-encoded with ONE v1 sentinel value. Output groups / test completion later are NEW keys (new tags),
/// never a re-key.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum OutputSelection {
    Default,
}

/// `TARGET_COMPLETION` key: the configured target + the output selection.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct TargetCompletionKey {
    pub ct: ConfiguredTargetKey,
    pub outputs: OutputSelection,
}
impl Key for TargetCompletionKey {
    fn kind(&self) -> KindId {
        TARGET_COMPLETION
    }
    /// Canonical encode: the CT-key canonical bytes (length-framed, the ONE CT encoding) + the selection
    /// tag (`0` = Default — the fixed v1 sentinel; any future selection is a DIFFERENT key).
    fn encode(&self) -> Vec<u8> {
        let ct = self.ct.encode();
        let mut b = Vec::with_capacity(8 + ct.len() + 1);
        b.extend_from_slice(&(ct.len() as u64).to_be_bytes());
        b.extend_from_slice(&ct);
        match self.outputs {
            OutputSelection::Default => b.push(0),
        }
        b
    }
}

/// Decode a `TARGET_COMPLETION` node-key's canonical bytes (fail-closed; unknown selection tag rejected).
pub fn decode_target_completion_key(bytes: &[u8]) -> Result<TargetCompletionKey, Error> {
    let mut c = Cur::new(bytes, "TARGET_COMPLETION key");
    let ct = take_owner(&mut c)?;
    let outputs = match c.take(1)?[0] {
        0 => OutputSelection::Default,
        t => {
            return Err(Error::Invalid {
                what: "TARGET_COMPLETION key".into(),
                detail: format!("bad output-selection tag {t}"),
            })
        }
    };
    c.finish()?;
    Ok(TargetCompletionKey { ct, outputs })
}

/// `TARGET_COMPLETION` value: a sentinel — the dep requests ARE the build (Bazel `TargetCompletionValue`,
/// "just a sentinel").
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TargetCompletionValue;
impl Value for TargetCompletionValue {
    fn policy(&self) -> ValuePolicy {
        ValuePolicy { comparable: true, always_dirty: false, shareable: true, serializable: true, process_local: false }
    }
    fn value_eq(&self, other: &dyn Value) -> bool {
        other.as_any().downcast_ref::<TargetCompletionValue>().is_some()
    }
    fn content_digest(&self) -> Digest {
        Digest::of(b"TARGET_COMPLETION sentinel")
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

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

// ──────────────── derived_outputs — the shared pure fn (decisions A/D, R8) ────────────────

/// Per template idx, per declared output → the stamped [`ArtifactRef`], in declaration order. A duplicate
/// exec-path across the CT's actions is a typed `Error::Conflict` (v1-strict; `Actions.java:268-278` analog
/// — shareable-action tolerance is a later additive relaxation). Runs at demand time in v1 (R8); promoting
/// the call site to CT-construction time is the `action-graph` row's work — the fn is the same either way.
pub fn derived_outputs(owner: &ConfiguredTargetKey, ct: &ConfiguredTarget) -> Result<Vec<ArtifactRef>, Error> {
    let mut seen: HashMap<&str, (usize, usize)> = HashMap::new(); // exec_path -> (template idx, out position)
    let mut refs: Vec<ArtifactRef> = Vec::new();
    for (idx, tmpl) in ct.actions.iter().enumerate() {
        for o in &tmpl.outputs {
            if let Some((prev_idx, prev_pos)) = seen.insert(o.as_str(), (idx, refs.len())) {
                if cfg!(feature = "mutant_dup_output_last_writer_wins") {
                    // MUTANT: last writer WINS — the earlier producer is silently dropped instead of a
                    // typed conflict. `duplicate_output_conflict_fail_closed` (unit + over the root) reds.
                    refs.remove(prev_pos);
                    // re-anchor recorded positions after the removal (mutant-only bookkeeping).
                    for v in seen.values_mut() {
                        if v.1 > prev_pos {
                            v.1 -= 1;
                        }
                    }
                } else {
                    return Err(Error::Conflict {
                        what: "duplicate declared output".into(),
                        detail: format!(
                            "//{}:{}: '{}' is declared by action #{} and action #{}",
                            owner.package, owner.name, o, prev_idx, idx
                        ),
                    });
                }
            }
            refs.push(ArtifactRef {
                exec_path: o.clone(),
                producer: ArtifactProducer::Derived(GeneratingActionKey { owner: owner.clone(), action_index: idx as u32 }),
            });
        }
    }
    Ok(refs)
}

/// Downcast a CONFIGURED_TARGET dep value (shared by the three node functions).
pub(crate) fn as_configured_target(v: &razel_core::NodeValue) -> Result<&ConfiguredTarget, Error> {
    v.as_any().downcast_ref::<ConfiguredTarget>().ok_or_else(|| Error::Invalid {
        what: "CONFIGURED_TARGET dep".into(),
        detail: "not a ConfiguredTarget".into(),
    })
}

// ──────────────── ARTIFACT node function — a pure identity projection, nothing more (decision C) ────────────────

/// `ARTIFACT`: project ONE `{exec_path, digest}` entry out of the producer. `Source` requests `FILE`
/// (the invalidation edge) + reads bytes via `sys` into the blob store (the razel-load pattern, decision G);
/// `Derived` requests its generating `ACTION` and projects the named output (absent = typed error). It
/// fabricates NOTHING — every digest it serves came from a producer it demanded this pass.
pub struct ArtifactFn {
    blobs: Arc<dyn BlobStore>,
    sys: Arc<dyn System>,
    root: HostPath,
}
impl ArtifactFn {
    pub fn new(blobs: Arc<dyn BlobStore>, sys: Arc<dyn System>, root: HostPath) -> Self {
        Self { blobs, sys, root }
    }
}
impl NodeFunction for ArtifactFn {
    fn compute(&self, key: &NodeKey, ctx: &mut dyn DemandContext) -> ComputeResult {
        let aref = match decode_artifact_ref(key.canonical()) {
            Ok(r) => r,
            Err(e) => return ComputeResult::Error(e),
        };
        if cfg!(feature = "mutant_artifact_projection_fabricates_digest") {
            // MUTANT: yield a digest WITHOUT requesting the producer — the projection is severed from the
            // graph (no edge, fabricated content identity). `artifact_is_a_pure_projection_of_its_producer`
            // and `derived_input_materializes_from_producer` red (a consumer's blobs.get on the fabricated
            // digest fails closed — the CAS never held such bytes).
            return ComputeResult::Ready(Arc::new(ArtifactValue {
                exec_path: aref.exec_path,
                digest: Digest::of(b"FABRICATED"),
            }));
        }
        match &aref.producer {
            ArtifactProducer::Source => {
                // The FILE dep is the invalidation edge; bytes enter the ONE home via sys.read + blobs.put.
                let rel = RootRelativePath(aref.exec_path.clone());
                let file_key = NodeKey::from_key(&FileKey(rel.clone()));
                let fv = match ctx.request(&file_key) {
                    Demand::Missing => return ComputeResult::Missing { recorded_dep_keys: vec![file_key] },
                    Demand::Ready(v) => v,
                };
                match fv.as_any().downcast_ref::<FileValue>() {
                    Some(f) if f.exists => {}
                    Some(_) => {
                        // A source artifact whose file does not exist is KNOWN absence — fail-closed at the
                        // FILE node (decision E), never an empty input.
                        return ComputeResult::Error(Error::NotFound {
                            what: "source artifact".into(),
                            detail: aref.exec_path.clone(),
                        });
                    }
                    None => {
                        return ComputeResult::Error(Error::Invalid {
                            what: "FILE value".into(),
                            detail: "source-artifact dep was not a FileValue".into(),
                        })
                    }
                }
                let bytes = match self.sys.read(&join_root(&self.root, &rel)) {
                    Ok(b) => b,
                    Err(e) => {
                        return ComputeResult::Error(Error::Invalid {
                            what: "read source artifact".into(),
                            detail: format!("{}: {e:?}", aref.exec_path),
                        })
                    }
                };
                let digest = self.blobs.put(&bytes);
                ComputeResult::Ready(Arc::new(ArtifactValue { exec_path: aref.exec_path, digest }))
            }
            ArtifactProducer::Derived(g) => {
                let action_key = NodeKey::from_key(g);
                let av = match ctx.request(&action_key) {
                    Demand::Missing => return ComputeResult::Missing { recorded_dep_keys: vec![action_key] },
                    Demand::Ready(v) => v,
                };
                let action = match av.as_any().downcast_ref::<crate::ActionValue>() {
                    Some(a) => a,
                    None => {
                        return ComputeResult::Error(Error::Invalid {
                            what: "ACTION dep".into(),
                            detail: "not an ActionValue".into(),
                        })
                    }
                };
                match action.output(&aref.exec_path) {
                    Some(od) => ComputeResult::Ready(Arc::new(ArtifactValue { exec_path: aref.exec_path.clone(), digest: od.digest })),
                    // A declared-artifact-without-a-generating-output is the ADR-0012 gate: typed, never empty.
                    None => ComputeResult::Error(Error::Invalid {
                        what: "derived artifact projection".into(),
                        detail: format!(
                            "producer //{}:{} action #{} did not produce '{}'",
                            g.owner.package, g.owner.name, g.action_index, aref.exec_path
                        ),
                    }),
                }
            }
        }
    }
}

// ──────────────── TARGET_COMPLETION node function (decision D) ────────────────

/// `TARGET_COMPLETION`: request the CT, derive the default-output `ArtifactRef`s via the ONE shared pure
/// fn (conflict pass runs HERE at demand time, R8), request them as one dep group, and publish the
/// sentinel — the dep requests ARE the build. Demand flows top-down from completion; the CT never demands
/// its actions (the Bazel phase split).
pub struct TargetCompletionFn;
impl NodeFunction for TargetCompletionFn {
    fn compute(&self, key: &NodeKey, ctx: &mut dyn DemandContext) -> ComputeResult {
        let tck = match decode_target_completion_key(key.canonical()) {
            Ok(k) => k,
            Err(e) => return ComputeResult::Error(e),
        };
        let OutputSelection::Default = tck.outputs; // ONE v1 selection; new selections are NEW keys (R7).
        let ct_key = NodeKey::from_key(&tck.ct);
        let ctv = match ctx.request(&ct_key) {
            Demand::Missing => return ComputeResult::Missing { recorded_dep_keys: vec![ct_key] },
            Demand::Ready(v) => v,
        };
        let ct = match as_configured_target(&ctv) {
            Ok(c) => c,
            Err(e) => return ComputeResult::Error(e),
        };
        let refs = match derived_outputs(&tck.ct, ct) {
            Ok(r) => r,
            Err(e) => return ComputeResult::Error(e),
        };
        if cfg!(feature = "mutant_completion_skips_artifact_demand") {
            // MUTANT (the headline's red driver): publish the sentinel WITHOUT requesting the outputs —
            // nothing builds as a consequence of completion. `action_runs_as_graph_consequence_of_target_output`
            // (and the unit `target_completion_requests_ct_then_its_artifact_group`) go red.
            return ComputeResult::Ready(Arc::new(TargetCompletionValue));
        }
        let artifact_keys: Vec<NodeKey> = refs.iter().map(NodeKey::from_key).collect();
        let demands = ctx.request_group(&artifact_keys);
        let mut missing: Vec<NodeKey> = Vec::new();
        for (i, d) in demands.into_iter().enumerate() {
            match d {
                Demand::Missing => missing.push(artifact_keys[i].clone()),
                Demand::Ready(v) => {
                    if v.as_any().downcast_ref::<ArtifactValue>().is_none() {
                        return ComputeResult::Error(Error::Invalid {
                            what: "ARTIFACT dep".into(),
                            detail: "not an ArtifactValue".into(),
                        });
                    }
                }
            }
        }
        if !missing.is_empty() {
            return ComputeResult::Missing { recorded_dep_keys: missing };
        }
        ComputeResult::Ready(Arc::new(TargetCompletionValue))
    }
}

// ──────────────── shared test context (crate-internal) ────────────────

#[cfg(test)]
pub(crate) mod testctx {
    use razel_core::{Key, NodeKey, NodeValue, Value};
    use razel_engine_api::{Demand, DemandContext};
    use std::collections::HashMap;
    use std::sync::Arc;

    /// A map-backed `DemandContext` for node-function unit tests: serves the values it was given, reports
    /// `Missing` otherwise, and RECORDS every requested key (so tests can assert the demand edges exist).
    pub(crate) struct MapCtx {
        served: HashMap<NodeKey, NodeValue>,
        pub(crate) requested: Vec<NodeKey>,
    }
    impl MapCtx {
        pub(crate) fn new() -> Self {
            Self { served: HashMap::new(), requested: Vec::new() }
        }
        pub(crate) fn serve<K: Key, V: Value>(mut self, k: &K, v: V) -> Self {
            self.served.insert(NodeKey::from_key(k), Arc::new(v));
            self
        }
    }
    impl DemandContext for MapCtx {
        fn request(&mut self, key: &NodeKey) -> Demand {
            self.requested.push(key.clone());
            match self.served.get(key) {
                Some(v) => Demand::Ready(v.clone()),
                None => Demand::Missing,
            }
        }
        fn request_group(&mut self, keys: &[NodeKey]) -> Vec<Demand> {
            keys.iter().map(|k| self.request(k)).collect()
        }
        fn register_dep(&mut self, _key: &NodeKey) {}
    }
}

#[cfg(test)]
mod tests {
    use super::testctx::MapCtx;
    use super::*;
    use crate::{ActionValue, OutputDigest};
    use razel_bzl_api::ActionTemplate;

    fn owner(pkg: &str, name: &str) -> ConfiguredTargetKey {
        ConfiguredTargetKey {
            package: pkg.into(),
            name: name.into(),
            configuration: None,
            exec_platform: None,
            rule_transition: None,
        }
    }
    fn tmpl(mnemonic: &str, inputs: &[&str], outputs: &[&str]) -> ActionTemplate {
        ActionTemplate {
            mnemonic: mnemonic.into(),
            argv: vec!["x".into()],
            env: Vec::new(),
            inputs: inputs.iter().map(|s| s.to_string()).collect(),
            outputs: outputs.iter().map(|s| s.to_string()).collect(),
        }
    }
    fn ct(actions: Vec<ActionTemplate>) -> ConfiguredTarget {
        ConfiguredTarget { providers: Vec::new(), actions, dep_outputs: Vec::new() }
    }
    fn gak(pkg: &str, name: &str, idx: u32) -> GeneratingActionKey {
        GeneratingActionKey { owner: owner(pkg, name), action_index: idx }
    }

    // ── codec gates (lockdown §4): round-trip lossless, fail closed, no content-key aliasing ──

    #[test]
    fn generating_action_key_round_trips() {
        let k = GeneratingActionKey {
            owner: ConfiguredTargetKey {
                package: "app/sub".into(),
                name: "t".into(),
                configuration: Some("opt".into()),
                exec_platform: None,
                rule_transition: None,
            },
            action_index: 3,
        };
        let decoded = decode_generating_action_key(&k.encode()).expect("well-formed key decodes");
        assert_eq!(decoded, k, "decode(encode(k)) == k");
        assert_eq!(decoded.encode(), k.encode(), "re-encode is byte-identical");
    }

    #[test]
    fn artifact_ref_round_trips() {
        let src = ArtifactRef { exec_path: "app/in.txt".into(), producer: ArtifactProducer::Source };
        assert_eq!(decode_artifact_ref(&src.encode()).unwrap(), src, "Source ref round-trips");
        let der = ArtifactRef { exec_path: "app/out.txt".into(), producer: ArtifactProducer::Derived(gak("app", "t", 1)) };
        assert_eq!(decode_artifact_ref(&der.encode()).unwrap(), der, "Derived ref round-trips");
        // Same exec_path, different producer → DISTINCT keys (owner is identity-bearing for derived; R3).
        let other_owner = ArtifactRef { exec_path: "app/out.txt".into(), producer: ArtifactProducer::Derived(gak("app", "u", 1)) };
        assert_ne!(der.encode(), other_owner.encode(), "the producer is identity-bearing");
        assert_ne!(der.encode(), src.encode(), "Source vs Derived at one path are distinct keys");
    }

    #[test]
    fn target_completion_key_round_trips() {
        let k = TargetCompletionKey { ct: owner("app", "t"), outputs: OutputSelection::Default };
        let decoded = decode_target_completion_key(&k.encode()).expect("well-formed key decodes");
        assert_eq!(decoded, k);
        assert_eq!(decoded.encode(), k.encode());
    }

    #[test]
    fn new_key_codecs_fail_closed() {
        // Truncation anywhere is a typed Invalid, never a panic.
        let good = gak("app", "t", 0).encode();
        for cut in 0..good.len() {
            assert!(matches!(decode_generating_action_key(&good[..cut]), Err(Error::Invalid { .. })),
                "ACTION key truncated at {cut} must fail closed");
        }
        // Trailing bytes rejected on all three codecs.
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(matches!(decode_generating_action_key(&trailing), Err(Error::Invalid { .. })));
        let mut art = ArtifactRef { exec_path: "p".into(), producer: ArtifactProducer::Source }.encode();
        art.push(0);
        assert!(matches!(decode_artifact_ref(&art), Err(Error::Invalid { .. })));
        let mut tc = TargetCompletionKey { ct: owner("a", "t"), outputs: OutputSelection::Default }.encode();
        tc.push(0);
        assert!(matches!(decode_target_completion_key(&tc), Err(Error::Invalid { .. })));
        // A huge declared length is a typed error (checked_add), never an overflow panic.
        assert!(matches!(decode_generating_action_key(&[0xff; 12]), Err(Error::Invalid { .. })));
        assert!(matches!(decode_artifact_ref(&[0xff; 12]), Err(Error::Invalid { .. })));
        // A bad producer tag / selection tag is typed.
        let mut bad_tag = ArtifactRef { exec_path: "p".into(), producer: ArtifactProducer::Source }.encode();
        let tag_at = bad_tag.len() - 1;
        bad_tag[tag_at] = 7;
        assert!(matches!(decode_artifact_ref(&bad_tag), Err(Error::Invalid { .. })));
        let mut bad_sel = TargetCompletionKey { ct: owner("a", "t"), outputs: OutputSelection::Default }.encode();
        let sel_at = bad_sel.len() - 1;
        bad_sel[sel_at] = 9;
        assert!(matches!(decode_target_completion_key(&bad_sel), Err(Error::Invalid { .. })));
        // A NON-CANONICAL owner frame (padded, then length-adjusted) can never alias.
        let owner_bytes = owner("a", "t").encode();
        let mut padded = Vec::new();
        padded.extend_from_slice(&((owner_bytes.len() + 1) as u64).to_be_bytes());
        padded.extend_from_slice(&owner_bytes);
        padded.push(0); // pad byte inside the owner frame
        padded.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(decode_generating_action_key(&padded), Err(Error::Invalid { .. })),
            "a non-canonical owner frame must fail closed, never alias");
    }

    #[test]
    fn content_encoded_action_bytes_do_not_alias_positional() {
        // THE §4 codec gate: a pre-re-key CONTENT-encoded ACTION byte string (the frozen 8-dim ActionKey
        // encode) decodes to a typed Error::Invalid — never a positional key alias.
        let content_key = crate::ActionKey::new(
            "Compile",
            vec!["cc".into(), "-o".into(), "out".into()],
            [("CC".to_string(), "gcc".to_string())].into(),
            vec![],
            vec![crate::ActionInput { path: "in".into(), content: b"data".to_vec() }],
            vec!["out".into()],
            None,
            std::collections::BTreeMap::new(),
        );
        match decode_generating_action_key(&content_key.encode()) {
            Err(Error::Invalid { .. }) => {}
            Ok(k) => panic!("a content-encoded ACTION byte string must NOT alias a positional key (got owner //{}:{})",
                k.owner.package, k.owner.name),
            Err(e) => panic!("expected a typed Invalid, got {e:?}"),
        }
    }

    #[test]
    fn tree_child_constructor_fails_closed() {
        // R6: the reserved TreeChild constructor path is fail-closed (typed Unsupported), and the reserved
        // codec tag (2) is rejected — trees are a constructor seam later, never a schema change.
        let parent = ArtifactRef { exec_path: "app/tree".into(), producer: ArtifactProducer::Derived(gak("app", "t", 0)) };
        assert!(matches!(ArtifactProducer::tree_child(&parent, "child.txt"), Err(Error::Unsupported { .. })));
        let mut bytes = ArtifactRef { exec_path: "p".into(), producer: ArtifactProducer::Source }.encode();
        let tag_at = bytes.len() - 1;
        bytes[tag_at] = 2;
        assert!(matches!(decode_artifact_ref(&bytes), Err(Error::Invalid { .. })),
            "the reserved TreeChild tag must fail closed until trees land");
    }

    // ── resolver (decision E, v1 policy) ──

    #[test]
    fn resolver_maps_sibling_output_to_derived_else_source() {
        let o = owner("app", "t");
        let c = ct(vec![tmpl("Gen", &["app/in.txt"], &["app/mid.txt"]), tmpl("Pack", &["app/mid.txt"], &["app/out.txt"])]);
        let r = SameTargetOrSourceResolver;
        // a sibling action's declared output → Derived with the DECLARING action's index.
        let mid = r.resolve(&o, &c, "app/mid.txt").unwrap();
        assert_eq!(mid.producer, ArtifactProducer::Derived(gak("app", "t", 0)));
        // anything else root-relative → Source.
        let src = r.resolve(&o, &c, "app/in.txt").unwrap();
        assert_eq!(src.producer, ArtifactProducer::Source);
    }

    #[test]
    fn resolver_maps_dep_output_to_producer_via_chaining_map() {
        // The files-chaining slice: an input path matching a DIRECT dep's declared output (the owner CT's
        // dep_outputs map, stamped at analysis) resolves to Derived{producer_ct, idx} — the dep's action,
        // NOT the owner's, and NOT Source. The producer CT carries its threaded configuration.
        use razel_analysis::DepOutput;
        let o = owner("app", "bin");
        let dep_ct = ConfiguredTargetKey {
            package: "app".into(),
            name: "lib".into(),
            configuration: Some("host".into()),
            exec_platform: None,
            rule_transition: None,
        };
        let mut c = ct(vec![tmpl("Link", &["app/main.rs", "app/liblib.rlib"], &["app/bin"])]);
        c.dep_outputs =
            vec![DepOutput { exec_path: "app/liblib.rlib".into(), producer_ct: dep_ct.clone(), action_index: 0 }];
        let r = SameTargetOrSourceResolver;
        // the dep's rlib → Derived on the DEP's generating action (config-carrying owner).
        let rlib = r.resolve(&o, &c, "app/liblib.rlib").unwrap();
        assert_eq!(
            rlib.producer,
            ArtifactProducer::Derived(GeneratingActionKey { owner: dep_ct, action_index: 0 }),
            "a dep output must resolve to ITS producing action via the chaining map"
        );
        // the source file still → Source (the map does not swallow non-matching paths).
        assert_eq!(r.resolve(&o, &c, "app/main.rs").unwrap().producer, ArtifactProducer::Source);
        // a SIBLING output shadows the map only for paths the owner itself declares — the owner's own
        // output stays owner-derived.
        assert_eq!(r.resolve(&o, &c, "app/bin").unwrap().producer, ArtifactProducer::Derived(gak("app", "bin", 0)));
    }

    #[test]
    fn unresolvable_input_fails_closed_at_the_resolver() {
        // Lockdown §4 `unresolvable_input_fails_closed` (the resolver half): unknown forms are typed
        // Unsupported — NEVER a skipped edge or empty content.
        let o = owner("app", "t");
        let c = ct(vec![tmpl("M", &[], &["app/o"])]);
        let r = SameTargetOrSourceResolver;
        for bad in ["/etc/passwd", "../up.txt", "a/../b.txt", ""] {
            assert!(matches!(r.resolve(&o, &c, bad), Err(Error::Unsupported { .. })),
                "input form '{bad}' must fail closed");
        }
    }

    // ── blob store (decision G / R5) ──

    #[test]
    fn blobstore_missing_digest_fails_closed() {
        // `mutant_blobstore_get_defaults` regresses this: a missing digest would come back as EMPTY BYTES
        // (the Absorb shape) instead of a typed NotFound.
        let store = InMemoryBlobStore::new();
        let d = store.put(b"bytes");
        assert_eq!(store.get(&d).unwrap(), b"bytes".to_vec(), "put→get round-trips");
        let absent = Digest::of(b"never stored");
        assert!(matches!(store.get(&absent), Err(Error::NotFound { .. })),
            "a missing digest must be a typed NotFound, never empty bytes");
    }

    // ── derived_outputs (decisions A/D, R8) ──

    #[test]
    fn derived_outputs_stamps_declaration_order() {
        let o = owner("app", "t");
        let c = ct(vec![tmpl("Gen", &[], &["app/mid.txt"]), tmpl("Pack", &[], &["app/out.txt"])]);
        let refs = derived_outputs(&o, &c).unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].exec_path, "app/mid.txt");
        assert_eq!(refs[0].producer, ArtifactProducer::Derived(gak("app", "t", 0)));
        assert_eq!(refs[1].exec_path, "app/out.txt");
        assert_eq!(refs[1].producer, ArtifactProducer::Derived(gak("app", "t", 1)));
    }

    #[test]
    fn duplicate_output_conflict_fail_closed() {
        // Lockdown §4: two templates declaring the same exec path → typed conflict, never
        // last-writer-wins (`mutant_dup_output_last_writer_wins` regresses exactly this).
        let o = owner("app", "t");
        let c = ct(vec![tmpl("A", &[], &["app/dup.txt"]), tmpl("B", &[], &["app/dup.txt"])]);
        match derived_outputs(&o, &c) {
            Err(Error::Conflict { .. }) => {}
            Ok(refs) => panic!("a duplicate declared output must be a typed Conflict, got {} refs", refs.len()),
            Err(e) => panic!("expected Conflict, got {e:?}"),
        }
    }

    // ── ARTIFACT: a pure identity projection (decision C) ──

    #[test]
    fn artifact_is_a_pure_projection_of_its_producer() {
        // `mutant_artifact_projection_fabricates_digest` regresses BOTH halves: the digest would be
        // fabricated and the producer never requested.
        let g = gak("app", "t", 0);
        let aref = ArtifactRef { exec_path: "app/out.txt".into(), producer: ArtifactProducer::Derived(g.clone()) };
        let d = Digest::of(b"produced-bytes");
        let f = ArtifactFn::new(
            Arc::new(InMemoryBlobStore::new()),
            Arc::new(razel_os_api::conformance::FakeSystem::default()),
            HostPath::new("/w"),
        );
        // (1) with the producer NOT served: the projection must DEMAND it (Missing on the ACTION key).
        let mut cold = MapCtx::new();
        match f.compute(&NodeKey::from_key(&aref), &mut cold) {
            ComputeResult::Missing { recorded_dep_keys } => {
                assert_eq!(recorded_dep_keys, vec![NodeKey::from_key(&g)], "the ARTIFACT must request its producer");
            }
            ComputeResult::Ready(_) => panic!("the ARTIFACT must not publish a digest without requesting its producer"),
            _ => panic!("expected Missing"),
        }
        // (2) with the producer served: the value is the ONE projected {exec_path, digest} entry.
        let mut warm = MapCtx::new().serve(
            &g,
            ActionValue { exit_code: 0, outputs: vec![OutputDigest { path: "app/out.txt".into(), digest: d }] },
        );
        match f.compute(&NodeKey::from_key(&aref), &mut warm) {
            ComputeResult::Ready(v) => {
                let a = v.as_any().downcast_ref::<ArtifactValue>().unwrap();
                assert_eq!(a.digest, d, "the digest is PROJECTED from the producer's value, never fabricated");
                assert_eq!(a.exec_path, "app/out.txt");
                assert_eq!(warm.requested, vec![NodeKey::from_key(&g)], "exactly the producer edge");
            }
            _ => panic!("expected Ready"),
        }
        // (3) a projected path ABSENT from the producer's outputs is a typed error, never empty.
        let ghost = ArtifactRef { exec_path: "app/ghost.txt".into(), producer: ArtifactProducer::Derived(g.clone()) };
        let mut warm2 = MapCtx::new().serve(
            &g,
            ActionValue { exit_code: 0, outputs: vec![OutputDigest { path: "app/out.txt".into(), digest: d }] },
        );
        assert!(matches!(f.compute(&NodeKey::from_key(&ghost), &mut warm2), ComputeResult::Error(Error::Invalid { .. })),
            "an output absent from the producer's value must fail closed");
    }

    // ── TARGET_COMPLETION: the dep requests ARE the build (decision D) ──

    #[test]
    fn target_completion_requests_ct_then_its_artifact_group() {
        // `mutant_completion_skips_artifact_demand` regresses this: the sentinel would be published
        // WITHOUT the artifact group — nothing builds as a consequence of completion.
        let o = owner("app", "t");
        let tck = TargetCompletionKey { ct: o.clone(), outputs: OutputSelection::Default };
        let f = TargetCompletionFn;
        // (1) cold: the CT is requested first.
        let mut cold = MapCtx::new();
        match f.compute(&NodeKey::from_key(&tck), &mut cold) {
            ComputeResult::Missing { recorded_dep_keys } => {
                assert_eq!(recorded_dep_keys, vec![NodeKey::from_key(&o)]);
            }
            _ => panic!("expected Missing on the CT"),
        }
        // (2) CT served: the default outputs' ARTIFACT nodes are requested as one group.
        let c = ct(vec![tmpl("Gen", &[], &["app/out.txt"])]);
        let expected_artifact = ArtifactRef { exec_path: "app/out.txt".into(), producer: ArtifactProducer::Derived(gak("app", "t", 0)) };
        let mut with_ct = MapCtx::new().serve(&o, c.clone());
        match f.compute(&NodeKey::from_key(&tck), &mut with_ct) {
            ComputeResult::Missing { recorded_dep_keys } => {
                assert_eq!(recorded_dep_keys, vec![NodeKey::from_key(&expected_artifact)],
                    "completion must DEMAND the output artifacts — the dep requests ARE the build");
            }
            ComputeResult::Ready(_) => panic!("the sentinel must not be published without requesting the outputs"),
            _ => panic!("expected Missing on the artifact group"),
        }
        // (3) everything served: the sentinel.
        let mut full = MapCtx::new()
            .serve(&o, c)
            .serve(&expected_artifact, ArtifactValue { exec_path: "app/out.txt".into(), digest: Digest::of(b"x") });
        match f.compute(&NodeKey::from_key(&tck), &mut full) {
            ComputeResult::Ready(v) => {
                assert!(v.as_any().downcast_ref::<TargetCompletionValue>().is_some(), "the value is the sentinel");
            }
            _ => panic!("expected Ready"),
        }
    }
}
