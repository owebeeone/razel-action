//! The frozen artifact-model node keys — `GeneratingActionKey`, `ArtifactRef`, `TargetCompletionKey` —
//! and their canonical, fail-closed encode/decode, moved verbatim (carved out of `artifact.rs`).

use super::Cur;
use crate::{ARTIFACT, TARGET_COMPLETION};
use razel_analysis::{decode_ct_key, ConfiguredTargetKey};
use razel_core::{Digest, Error, Key, KindId, Value, ValuePolicy};
use std::any::Any;
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
