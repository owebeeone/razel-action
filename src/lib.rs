//! `razel-action` — the `ACTION` execution node-kind (Milestone C / #5), `KindId(60)`. Runs ONE declared action
//! via the `SpawnStrategy` seam and yields the produced outputs. Keyed by the action's CONTENT fingerprint —
//! the EIGHT ratified dimensions (mnemonic + argv + declared-only env + tools + input identities&digests +
//! declared outputs + exec_platform + exec_properties; ADR-0012 + `RazelV4ActionKeyLockdown.md`, frozen) — so
//! the node re-runs only when that key changes — the content key IS the cache + incrementality.
//!
//! ## Input-artifact modeling choice (the minimal cut — read this)
//! The action carries its inputs' content DIRECTLY in the key (in-memory artifacts), so `ACTION` is a
//! content-keyed LEAF: `compute` requests no other node and rebuilds the exact `SpawnRequest` from the key alone.
//! Rationale + consequences:
//!   * The canonical key encoding INLINES each input's `(path, content-bytes)`, so changing an input's bytes is
//!     a DISTINCT key → a re-run, with NO separate dependency edge. This is the spec's "minimal cut: the action
//!     carries its inputs' content directly in the key/request" — we do NOT build a filesystem artifact
//!     materializer (deferred) and do NOT depend on generic input nodes. Inlining (rather than a digest) keeps
//!     the key LOSSLESS: `decode(encode(k)) == k`, so `compute` can rebuild the exact bytes the strategy needs.
//!   * Determinism: the key sorts env + inputs and length-frames every field, so two actions are equal iff their
//!     content is equal regardless of declaration order (early-cutoff friendly).
//! The cost: the key (and thus the engine's key store) carries the FULL input content the analysis phase already
//! resolved, not a digest + a live edge to each input's producer. That is the deferred artifact-model surface:
//! when it lands, the ACTION node becomes non-leaf — it depends on each input's producer node, folds the
//! producer's output DIGEST into the key, and the strategy fetches bytes from the CAS rather than the key
//! inlining them. The struct shapes don't move; only the key encoding swaps bytes→digest. See "Integrator
//! wiring" at the bottom.
//!
//! Fail-closed (#1 rule): a declared output the strategy did not produce is `Error(Unsupported/Invalid)` via the
//! shared `razel_exec_api::validate_outputs` — never a silent empty value, and independent of the exit code
//! (ADR-0012). A malformed key decodes to a typed `Error`, never a panic on valid-shaped input.

use razel_bzl_api::ActionTemplate;
use razel_core::{Digest, Error, Key, KindId, NodeKey, Value, ValuePolicy};
use razel_engine_api::{ComputeResult, DemandContext, DemandEngine, NodeFunction};
use razel_exec_api::{validate_outputs, ExecError, InputArtifact, SpawnRequest, SpawnResult, SpawnStrategy};
use std::any::Any;
use std::collections::BTreeMap;
use std::sync::Arc;

pub const ACTION: KindId = KindId(60);

// ──────────────── the action's content (the analysis output an `ActionTemplate` projects into) ────────────────

/// One declared input: its LOGICAL (exec-relative) path + its content bytes. Carried by value (the minimal-cut
/// in-memory artifact model). The KEY INLINES `(path, content)` losslessly, so the key both (a) changes when the
/// content changes and (b) lets `compute` rebuild the exact `SpawnRequest` bytes from the key alone. (The
/// deferred artifact model swaps the inlined bytes for the producer's output digest — see the crate-level note.)
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ActionInput {
    pub path: String,
    pub content: Vec<u8>,
}

/// The execution-platform reference folded into the key (ADR-0012 lockdown decision C / R2): the platform's
/// LABEL **and** its RESOLVED content digest — mirroring Bazel `PlatformInfo.addTo`, which folds both, so a
/// platform target edited under an unchanged label is a DIFFERENT key. Label-only is not Bazel-compatible.
/// `resolved_digest` is carried as opaque digest bytes (e.g. `Digest::of(platform_content)` output) rather than
/// `razel_core::Digest`, because the key must decode LOSSLESSLY and `Digest` exposes no from-bytes constructor.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ExecPlatformRef {
    pub label: String,
    pub resolved_digest: Vec<u8>,
}

/// `ACTION` key — the action's CONTENT fingerprint, the EIGHT ratified dimensions (ADR-0012 +
/// `RazelV4ActionKeyLockdown.md` §2, frozen-unless-thawed): mnemonic + argv (ordered — argv order is semantic) +
/// env (sorted by name — order is NOT semantic) + tools (sorted by path, same `(path, content)` shape as inputs)
/// + inputs (sorted by path, each `(path, content)` INLINED) + declared outputs (sorted, deduped) +
/// exec_platform (`None` = host assumed) + exec_properties (merged map, sorted). Two actions share a key IFF
/// every one of these is equal → the node re-runs exactly when one changes (the cache + incrementality), and
/// `compute` rebuilds the exact request from the key (lossless ⇒ no separate byte channel).
///
/// v1 sentinels (ADR-0010 discipline): `tools` empty (count frame 0), `exec_platform` `None` (tag 0),
/// `exec_properties` empty (count frame 0) — so minimal-cut keys are byte-stable forever and any future
/// non-empty value is a *different* key, never a silent alias.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ActionKey {
    pub mnemonic: String,
    pub argv: Vec<String>,
    /// Declared env only (REQ-PATHENV-008) — `BTreeMap` is sorted, so the key is order-insensitive in env.
    /// This is the ONE env map: the same values are fed verbatim to the `SpawnRequest` (no second channel);
    /// inherited host values (PATH etc.) never enter unless declared (lockdown decision E / R4).
    pub env: BTreeMap<String, String>,
    /// NEW (dim 4) — the tool subset of inputs, keyed by the SAME `(path, content)` shape (decision B / R1);
    /// sorted by path in `new`. Discipline: `tools ⊆ inputs` semantics — a marker slot, never a second digest
    /// of the same file. v1 sentinel: empty. (Tool runfiles are IN SCOPE for the contract but SCOPED OUT of the
    /// minimal cut: when a tool carries runfiles, it enters as ONE synthetic runfiles-tree entry in this same
    /// vec — additive, no struct change.)
    pub tools: Vec<ActionInput>,
    /// Sorted by path in `new`; each input's `(path, content bytes)` is INLINED in the key (lossless minimal
    /// cut — not a digest; see the crate-level note), so the key changes when an input's bytes change.
    pub inputs: Vec<ActionInput>,
    /// Declared outputs the strategy MUST produce (sorted, deduped in `new`).
    pub outputs: Vec<String>,
    /// NEW (dim 7) — the execution platform, folded centrally as presence + label + resolved content
    /// (decision C / R2). `None` = host assumed. v1 sentinel: `None` (tag 0).
    pub exec_platform: Option<ExecPlatformRef>,
    /// NEW (dim 8) — the merged per-exec-group properties map (platform < target precedence), canonically
    /// sorted by construction (`BTreeMap`, decision D). v1 sentinel: empty (count frame 0).
    pub exec_properties: BTreeMap<String, String>,
}
impl ActionKey {
    /// Build a key with the canonicalization the kind guarantees: tools + inputs sorted by path, outputs
    /// sorted+deduped, env/exec_properties sorted by construction (`BTreeMap`).
    pub fn new(
        mnemonic: impl Into<String>,
        argv: Vec<String>,
        env: BTreeMap<String, String>,
        mut tools: Vec<ActionInput>,
        mut inputs: Vec<ActionInput>,
        mut outputs: Vec<String>,
        exec_platform: Option<ExecPlatformRef>,
        exec_properties: BTreeMap<String, String>,
    ) -> ActionKey {
        tools.sort_by(|a, b| a.path.cmp(&b.path));
        inputs.sort_by(|a, b| a.path.cmp(&b.path));
        outputs.sort();
        outputs.dedup();
        ActionKey { mnemonic: mnemonic.into(), argv, env, tools, inputs, outputs, exec_platform, exec_properties }
    }

    /// The `SpawnRequest` this action runs as — the bytes the strategy needs. The key (above) INLINES these same
    /// bytes losslessly, so this is rebuilt straight from the key (a pure function of the key, no hidden state).
    fn to_request(&self) -> SpawnRequest {
        SpawnRequest::new(
            self.mnemonic.clone(),
            self.argv.clone(),
            self.env.clone(),
            self.inputs.iter().map(|i| InputArtifact { path: i.path.clone(), content: i.content.clone() }).collect(),
            self.outputs.clone(),
        )
    }
}

// ───── canonical encode: length-framed so no field can bleed into the next; input content bytes INLINED (lossless) ─────
fn enc_str(b: &mut Vec<u8>, s: &str) {
    b.extend_from_slice(&(s.len() as u64).to_be_bytes());
    b.extend_from_slice(s.as_bytes());
}
fn enc_bytes(b: &mut Vec<u8>, bytes: &[u8]) {
    b.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    b.extend_from_slice(bytes);
}

impl Key for ActionKey {
    fn kind(&self) -> KindId {
        ACTION
    }
    /// The canonical encoding, FROZEN at the ADR-0012 widening (`RazelV4ActionKeyLockdown.md` §2): the spike's
    /// five frames byte-identical in their original order — `mnemonic, argv, env, inputs, outputs` — then the
    /// three new frames APPENDED: `tools` (count frame, per-entry path + content), `exec_platform` (presence
    /// tag 0/1 + label frame + digest frame), `exec_properties` (count frame + sorted `(k,v)` frames). Appending
    /// centrally after the definitional frames mirrors Bazel `ActionKeyComputer`'s discipline.
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        enc_str(&mut b, &self.mnemonic);
        b.extend_from_slice(&(self.argv.len() as u64).to_be_bytes());
        for a in &self.argv {
            enc_str(&mut b, a);
        }
        b.extend_from_slice(&(self.env.len() as u64).to_be_bytes());
        for (k, v) in &self.env {
            enc_str(&mut b, k);
            enc_str(&mut b, v);
        }
        b.extend_from_slice(&(self.inputs.len() as u64).to_be_bytes());
        for i in &self.inputs {
            enc_str(&mut b, &i.path);
            // MUTANT: omit the input's content from the key → an input edit yields the SAME key → a stale re-use
            // (the cache returns the previous output for changed inputs). The "key changes with inputs" test reds.
            if !cfg!(feature = "mutant_action_ignores_inputs_in_key") {
                enc_bytes(&mut b, &i.content);
            }
        }
        b.extend_from_slice(&(self.outputs.len() as u64).to_be_bytes());
        for o in &self.outputs {
            enc_str(&mut b, o);
        }
        // ── the three widened frames (appended AFTER the spike's five — frozen ordering, see doc above) ──
        // MUTANT: omit the tools frame → two actions differing ONLY in a tool (version swap, gcc-12→gcc-13)
        // COLLIDE to the same key and the cache silently serves the WRONG output — the §0 under-keying trap.
        // `action_key_changes_for_tools` reds.
        if !cfg!(feature = "mutant_action_key_drops_tools") {
            b.extend_from_slice(&(self.tools.len() as u64).to_be_bytes());
            for t in &self.tools {
                enc_str(&mut b, &t.path);
                enc_bytes(&mut b, &t.content);
            }
        }
        // MUTANT: omit the exec dims (presence tag + properties frame) → the "same" action on a different exec
        // platform / with different exec_properties keys identically (wrong-cache-hit). `action_key_changes_for_exec` reds.
        if !cfg!(feature = "mutant_action_key_drops_exec_dims") {
            match &self.exec_platform {
                None => b.push(0), // the fixed v1 sentinel: a future non-null platform is a DIFFERENT key
                Some(p) => {
                    b.push(1);
                    enc_str(&mut b, &p.label);
                    enc_bytes(&mut b, &p.resolved_digest);
                }
            }
            b.extend_from_slice(&(self.exec_properties.len() as u64).to_be_bytes());
            for (k, v) in &self.exec_properties {
                enc_str(&mut b, k);
                enc_str(&mut b, v);
            }
        }
        b
    }
}

// ──────────────── value: the action's result (outputs → digest + the exit status) ────────────────

/// One produced output, recorded by LOGICAL path + content digest (NOT the raw bytes — the value is an identity,
/// the CAS holds bytes; deferred). The actual bytes flow through the strategy/request; the value is the cacheable
/// summary the engine compares for early cutoff.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OutputDigest {
    pub path: String,
    pub digest: Digest,
}

/// `ACTION` value: the exit code + the produced outputs as `(path -> Digest)`, name-sorted (deterministic →
/// early cutoff applies: an action whose inputs change but whose outputs are byte-identical cuts off here).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ActionValue {
    pub exit_code: i32,
    pub outputs: Vec<OutputDigest>,
}
impl ActionValue {
    pub fn output(&self, path: &str) -> Option<&OutputDigest> {
        self.outputs.iter().find(|o| o.path == path)
    }
    /// Project a `SpawnResult` into the cacheable value (digesting each output's content). Sorts by path.
    fn from_spawn(res: &SpawnResult) -> ActionValue {
        let mut outputs: Vec<OutputDigest> =
            res.outputs.iter().map(|o| OutputDigest { path: o.path.clone(), digest: Digest::of(&o.content) }).collect();
        outputs.sort_by(|a, b| a.path.cmp(&b.path));
        ActionValue { exit_code: res.status.code, outputs }
    }
}
impl Value for ActionValue {
    fn policy(&self) -> ValuePolicy {
        ValuePolicy { comparable: true, always_dirty: false, shareable: true, serializable: true, process_local: false }
    }
    fn value_eq(&self, other: &dyn Value) -> bool {
        other.as_any().downcast_ref::<ActionValue>().is_some_and(|o| o == self)
    }
    fn content_digest(&self) -> Digest {
        let mut b = Vec::new();
        b.extend_from_slice(&self.exit_code.to_be_bytes());
        b.extend_from_slice(&(self.outputs.len() as u64).to_be_bytes());
        for o in &self.outputs {
            enc_str(&mut b, &o.path);
            enc_bytes(&mut b, o.digest.to_hex().as_bytes());
        }
        Digest::of(&b)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ──────────────── decode (fail-closed: a malformed key is a typed Error, never a panic) ────────────────

struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    fn err(detail: &str) -> Error {
        Error::Invalid { what: "ACTION key".into(), detail: detail.into() }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        // checked_add: a malformed key with a huge length must be a typed error, never an overflow panic.
        let end = self.i.checked_add(n).ok_or_else(|| Self::err("length overflow"))?;
        if end > self.b.len() {
            return Err(Self::err("truncated"));
        }
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    fn u64(&mut self) -> Result<u64, Error> {
        let raw = self.take(8)?;
        let arr: [u8; 8] = raw.try_into().map_err(|_| Self::err("bad u64"))?;
        Ok(u64::from_be_bytes(arr))
    }
    fn bytes(&mut self) -> Result<Vec<u8>, Error> {
        let n = self.u64()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn str(&mut self) -> Result<String, Error> {
        String::from_utf8(self.bytes()?).map_err(|_| Self::err("non-utf8"))
    }
}

/// Decode an `ACTION` node-key's canonical bytes back to an `ActionKey`. The encode INLINES input content
/// losslessly, so decode recovers the EXACT `ActionKey` (`decode(encode(k)) == k`): `compute` rebuilds the exact
/// `SpawnRequest` bytes from the key with no separate byte channel. Fail-closed: a malformed/truncated key is a
/// typed `Error::Invalid`, never a panic — and a PRE-WIDENING five-frame byte string is `Error::Invalid` too
/// (its widened frames are missing → "truncated"), never a silent alias of a widened key with empty dims.
fn decode_action_key(bytes: &[u8]) -> Result<ActionKey, Error> {
    let mut c = Cur::new(bytes);
    let mnemonic = c.str()?;
    let argc = c.u64()? as usize;
    let mut argv = Vec::with_capacity(argc);
    for _ in 0..argc {
        argv.push(c.str()?);
    }
    let envc = c.u64()? as usize;
    let mut env = BTreeMap::new();
    for _ in 0..envc {
        let k = c.str()?;
        let v = c.str()?;
        env.insert(k, v);
    }
    let inc = c.u64()? as usize;
    let mut inputs = Vec::with_capacity(inc);
    for _ in 0..inc {
        let path = c.str()?;
        // Under the input-omitting mutant the content field is absent from encode; tolerate both so decode stays
        // total + symmetric with the active encoding (the round-trip property must hold under the mutant too).
        let content = if cfg!(feature = "mutant_action_ignores_inputs_in_key") { Vec::new() } else { c.bytes()? };
        inputs.push(ActionInput { path, content });
    }
    let outc = c.u64()? as usize;
    let mut outputs = Vec::with_capacity(outc);
    for _ in 0..outc {
        outputs.push(c.str()?);
    }
    // ── the three widened frames (symmetric with encode; frame-absent under each drop-mutant so decode stays
    // total over the active encoding) ──
    let tools = if cfg!(feature = "mutant_action_key_drops_tools") {
        Vec::new()
    } else {
        let tc = c.u64()? as usize;
        let mut tools = Vec::with_capacity(tc);
        for _ in 0..tc {
            let path = c.str()?;
            let content = c.bytes()?;
            tools.push(ActionInput { path, content });
        }
        tools
    };
    let (exec_platform, exec_properties) = if cfg!(feature = "mutant_action_key_drops_exec_dims") {
        (None, BTreeMap::new())
    } else {
        let exec_platform = match c.take(1)?[0] {
            0 => None,
            1 => {
                let label = c.str()?;
                let resolved_digest = c.bytes()?;
                Some(ExecPlatformRef { label, resolved_digest })
            }
            t => return Err(Error::Invalid { what: "ACTION key".into(), detail: format!("bad exec_platform tag {t}") }),
        };
        let pc = c.u64()? as usize;
        let mut exec_properties = BTreeMap::new();
        for _ in 0..pc {
            let k = c.str()?;
            let v = c.str()?;
            exec_properties.insert(k, v);
        }
        (exec_platform, exec_properties)
    };
    if c.i != c.b.len() {
        return Err(Cur::err("trailing bytes"));
    }
    Ok(ActionKey { mnemonic, argv, env, tools, inputs, outputs, exec_platform, exec_properties })
}

// ──────────────── node function: build request → strategy.spawn → validate outputs → value ────────────────

fn map_exec(e: ExecError) -> Error {
    match e {
        ExecError::OutputNotProduced { mnemonic, path } => {
            // A declared OUTPUT the action didn't produce is an Invalid action result (per the crate spec) —
            // NOT InputMissing, which razel-core reserves for a missing declared INPUT at a read boundary.
            Error::Invalid { what: "declared action output not produced".into(), detail: format!("{mnemonic}: {path}") }
        }
        ExecError::MissingInput { mnemonic, path } => {
            Error::InputMissing { what: "declared action input".into(), detail: format!("{mnemonic}: {path}") }
        }
        ExecError::SpawnFailed { mnemonic, detail } => {
            Error::Invalid { what: "spawn".into(), detail: format!("{mnemonic}: {detail}") }
        }
        ExecError::Unsupported { what, detail } => Error::Unsupported { what, detail },
        // `ExecError` is #[non_exhaustive]: a future variant must surface LOUD, never be swallowed silently.
        other => Error::Invalid { what: "exec".into(), detail: format!("{other:?}") },
    }
}

/// `ACTION`: run a declared action via the injected `SpawnStrategy`. A content-keyed LEAF (requests no other
/// node — see the input-modeling note at the top). The strategy is the FAN-OUT seam: this never names a concrete
/// strategy (local/sandbox/remote/fake are impls behind `Arc<dyn SpawnStrategy>`, constructor-injected exactly
/// like `razel-source`'s `Arc<dyn System>`).
pub struct ActionFn {
    strategy: Arc<dyn SpawnStrategy>,
}
impl ActionFn {
    pub fn new(strategy: Arc<dyn SpawnStrategy>) -> Self {
        Self { strategy }
    }
}
impl NodeFunction for ActionFn {
    fn compute(&self, key: &NodeKey, _ctx: &mut dyn DemandContext) -> ComputeResult {
        // The key IS the action content; build the request straight from it (a pure function of the key).
        let ak = match decode_action_key(key.canonical()) {
            Ok(k) => k,
            Err(e) => return ComputeResult::Error(e),
        };
        let req = ak.to_request();

        if cfg!(feature = "mutant_exec_hardcodes_output") {
            // MUTANT: fabricate the outputs instead of calling the strategy → the seam is bypassed (a hardcoded
            // "subprocess"). The output content is NOT the strategy's, so a test pinning the strategy's content
            // (or asserting the strategy was invoked) goes RED. This is the "bypasses the strategy" mutant.
            let outputs = req
                .outputs
                .iter()
                .map(|p| OutputDigest { path: p.clone(), digest: Digest::of(b"HARDCODED") })
                .collect();
            return ComputeResult::Ready(Arc::new(ActionValue { exit_code: 0, outputs }));
        }

        let res = match self.strategy.spawn(&req) {
            Ok(r) => r,
            Err(e) => return ComputeResult::Error(map_exec(e)),
        };
        // Fail-closed: every declared output MUST be present, even on exit zero (ADR-0012). One validator, shared
        // with the exec-api conformance, so the node and a strategy impl can't drift on the rule.
        if let Err(e) = validate_outputs(&ak.mnemonic, &req, &res) {
            return ComputeResult::Error(map_exec(e));
        }
        ComputeResult::Ready(Arc::new(ActionValue::from_spawn(&res)))
    }
}

/// Register the `ACTION` node-kind on an engine, injecting the chosen `SpawnStrategy`. The composition root
/// (`razel-host`) calls this with its concrete engine + strategy (fake in tests, local/sandbox/remote in prod) —
/// mirrors `register_source_kinds(engine, sys, root)`. `razel-action` never names a concrete strategy.
pub fn register_action_kinds(engine: &mut dyn DemandEngine, strategy: Arc<dyn SpawnStrategy>) {
    engine.register(ACTION, Box::new(ActionFn::new(strategy)));
}

/// Convert an analysis-emitted [`ActionTemplate`] into an executable [`ActionKey`]. The template carries input
/// PATHS; the caller resolves each to content (the artifact-materializer seam — deferred; pass `[]` for the
/// input-free actions of the minimal cut). Pure: the key is a function of the template + the resolved bytes, so
/// equal (template, inputs) → equal key → engine cutoff. The widened dims default to their v1 sentinels
/// (R3 reserve-the-key-now: tools empty, exec_platform `None`, exec_properties empty) — when analysis later
/// populates them, values fill the already-frozen frames; the layout never moves, no consumer re-encodes.
pub fn action_key_from_template(t: &ActionTemplate, inputs: Vec<ActionInput>) -> ActionKey {
    ActionKey::new(
        t.mnemonic.clone(),
        t.argv.clone(),
        t.env.iter().cloned().collect(),
        Vec::new(),
        inputs,
        t.outputs.clone(),
        None,
        BTreeMap::new(),
    )
}

// ───────────────────────────────────────────────────────────────────────────────────────────────────────────
// Integrator wiring (NOT built here — for the track editing razel-analysis / the CT value):
//   * `razel_bzl_api::ActionTemplate { mnemonic, argv, env, inputs, outputs }` is the codec-neutral action the
//     analysis phase emits via `ctx.actions`. To turn one into an `ActionKey`, the analysis/host layer must
//     supply each input's CONTENT (resolved from the input's `FILE`/generating-action output) — `ActionTemplate`
//     carries input PATHS (`Vec<String>`), this kind needs `ActionInput{path,content}`. That resolution (path →
//     content/digest) is the deferred artifact-materializer seam; wire it where the CONFIGURED_TARGET value gains
//     its actions (RazelV4Phase45Plan C1/C3).
//   * When that lands, the ACTION node can become non-leaf: depend on each input's producer node and fold the
//     producer's output DIGEST into the key (the key field is already `(path, digest)`), so input content need
//     not be inlined. The change is additive — `ActionKey`/`ActionFn` shapes don't move.
// ───────────────────────────────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use razel_engine_api::Demand;
    use razel_exec_api::conformance::{fake_output_content, DroppingStrategy, FakeStrategy};

    // A mock DemandContext that records nothing and returns Missing — ACTION is a leaf, so compute never asks.
    struct NoDeps;
    impl DemandContext for NoDeps {
        fn request(&mut self, _k: &NodeKey) -> Demand {
            Demand::Missing
        }
        fn request_group(&mut self, keys: &[NodeKey]) -> Vec<Demand> {
            keys.iter().map(|_| Demand::Missing).collect()
        }
        fn register_dep(&mut self, _k: &NodeKey) {}
    }

    fn akey(mnemonic: &str, argv: &[&str], inputs: &[(&str, &[u8])], outputs: &[&str]) -> ActionKey {
        ActionKey::new(
            mnemonic,
            argv.iter().map(|s| s.to_string()).collect(),
            BTreeMap::new(),
            Vec::new(),
            inputs.iter().map(|(p, c)| ActionInput { path: p.to_string(), content: c.to_vec() }).collect(),
            outputs.iter().map(|s| s.to_string()).collect(),
            None,
            BTreeMap::new(),
        )
    }

    fn tool(path: &str, content: &[u8]) -> ActionInput {
        ActionInput { path: path.to_string(), content: content.to_vec() }
    }

    fn run(strategy: Arc<dyn SpawnStrategy>, key: &ActionKey) -> ComputeResult {
        let f = ActionFn::new(strategy);
        f.compute(&NodeKey::from_key(key), &mut NoDeps)
    }

    #[test]
    fn action_executes_and_produces_expected_output() {
        // The headline C4 contract: an action runs via a fake SpawnStrategy and produces the expected output.
        let key = akey("Touch", &["cat", "in"], &[("in", b"hello")], &["out/o"]);
        let val = match run(Arc::new(FakeStrategy), &key) {
            ComputeResult::Ready(v) => v,
            other => panic!("action must execute and be Ready, got {:?}", debug_result(&other)),
        };
        let av = val.as_any().downcast_ref::<ActionValue>().expect("value is an ActionValue");
        assert_eq!(av.exit_code, 0);
        // The output digest must be the FAKE strategy's deterministic content for this request — proving the
        // node ran the strategy (not a fabricated output) AND digested the strategy's bytes.
        let req = key.to_request();
        let expected = Digest::of(&fake_output_content(&req, "out/o"));
        assert_eq!(av.output("out/o").expect("declared output present").digest, expected,
            "the value must carry the digest of the STRATEGY's produced content");
    }

    #[test]
    fn action_key_changes_with_inputs_argv_env_and_is_stable_otherwise() {
        let base = akey("M", &["a"], &[("in", b"v1")], &["o"]);
        // Stable: an identical action (same content, different declaration order of inputs) → SAME key.
        let reordered = ActionKey::new(
            "M",
            vec!["a".into()],
            BTreeMap::new(),
            Vec::new(),
            vec![ActionInput { path: "in".into(), content: b"v1".to_vec() }],
            vec!["o".into()],
            None,
            BTreeMap::new(),
        );
        assert_eq!(base.encode(), reordered.encode(), "the same action content must be a stable key");

        // Input content change → distinct key (this is the incrementality property the mutant attacks).
        let input_changed = akey("M", &["a"], &[("in", b"v2")], &["o"]);
        assert_ne!(base.encode(), input_changed.encode(), "changing an input's content must change the key");

        // argv change → distinct key.
        let argv_changed = akey("M", &["b"], &[("in", b"v1")], &["o"]);
        assert_ne!(base.encode(), argv_changed.encode(), "changing argv must change the key");

        // env change → distinct key.
        let mut env_changed = base.clone();
        env_changed.env.insert("K".into(), "V".into());
        assert_ne!(base.encode(), env_changed.encode(), "changing env must change the key");

        // outputs change → distinct key.
        let out_changed = akey("M", &["a"], &[("in", b"v1")], &["o", "o2"]);
        assert_ne!(base.encode(), out_changed.encode(), "changing declared outputs must change the key");
    }

    // builder for keys exercising the three widened dims (lockdown §4 gates construct keys DIRECTLY — R3).
    fn wkey(
        tools: &[(&str, &[u8])],
        exec_platform: Option<ExecPlatformRef>,
        exec_properties: &[(&str, &str)],
    ) -> ActionKey {
        ActionKey::new(
            "M",
            vec!["a".into()],
            BTreeMap::new(),
            tools.iter().map(|(p, c)| tool(p, c)).collect(),
            vec![],
            vec!["o".into()],
            exec_platform,
            exec_properties.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        )
    }

    #[test]
    fn action_key_changes_for_tools() {
        // Lockdown §4 gate: a tool difference is a DISTINCT key — the §0 wrong-cache-hit guard. Under
        // mutant_action_key_drops_tools the tools frame vanishes and every distinct-key assertion here collides.
        let base = wkey(&[("bin/gcc-12", b"cc-v12")], None, &[]);

        // no-tools vs one-tool → distinct (the count-0 sentinel vs a populated frame).
        let no_tools = wkey(&[], None, &[]);
        assert_ne!(no_tools.encode(), base.encode(), "adding a tool entry must change the key");

        // tool CONTENT change (the gcc-12 → gcc-13 version swap with the same path) → distinct.
        let content_changed = wkey(&[("bin/gcc-12", b"cc-v13")], None, &[]);
        assert_ne!(base.encode(), content_changed.encode(), "changing a tool's content must change the key");

        // tool PATH rename (same content) → distinct.
        let renamed = wkey(&[("bin/gcc-13", b"cc-v12")], None, &[]);
        assert_ne!(base.encode(), renamed.encode(), "renaming a tool's path must change the key");

        // adding a second tool → distinct.
        let added = wkey(&[("bin/gcc-12", b"cc-v12"), ("bin/ld", b"ld")], None, &[]);
        assert_ne!(base.encode(), added.encode(), "adding a tool must change the key");

        // declaration ORDER is NOT semantic: `new` sorts tools by path → the same set is a stable key.
        let ab = wkey(&[("bin/gcc-12", b"cc-v12"), ("bin/ld", b"ld")], None, &[]);
        let ba = wkey(&[("bin/ld", b"ld"), ("bin/gcc-12", b"cc-v12")], None, &[]);
        assert_eq!(ab.encode(), ba.encode(), "tool declaration order must NOT change the key (sorted by path)");
    }

    #[test]
    fn action_key_changes_for_exec() {
        // Lockdown §4 gate: exec_platform / exec_properties differences are DISTINCT keys. Under
        // mutant_action_key_drops_exec_dims both frames vanish and these collide.
        let host = wkey(&[], None, &[]);
        let plat = ExecPlatformRef { label: "//platforms:linux_x86".into(), resolved_digest: b"pdig-1".to_vec() };

        // None (host assumed) vs Some(ref) → distinct (the presence tag).
        let on_plat = wkey(&[], Some(plat.clone()), &[]);
        assert_ne!(host.encode(), on_plat.encode(), "None vs Some(exec_platform) must be distinct keys");

        // label differs (same resolved digest) → distinct.
        let other_label =
            wkey(&[], Some(ExecPlatformRef { label: "//platforms:linux_arm".into(), resolved_digest: b"pdig-1".to_vec() }), &[]);
        assert_ne!(on_plat.encode(), other_label.encode(), "a different platform label must be a distinct key");

        // resolved digest differs (same label — the platform target EDITED under an unchanged label) → distinct.
        let other_digest =
            wkey(&[], Some(ExecPlatformRef { label: "//platforms:linux_x86".into(), resolved_digest: b"pdig-2".to_vec() }), &[]);
        assert_ne!(on_plat.encode(), other_digest.encode(),
            "editing platform content under an unchanged label must change the key (resolved digest is folded)");

        // adding an exec_properties pair → distinct.
        let with_prop = wkey(&[], None, &[("dockerImage", "img:1")]);
        assert_ne!(host.encode(), with_prop.encode(), "adding an exec_properties pair must change the key");

        // changing a property VALUE → distinct.
        let prop_changed = wkey(&[], None, &[("dockerImage", "img:2")]);
        assert_ne!(with_prop.encode(), prop_changed.encode(), "changing an exec_properties value must change the key");

        // property insertion order is NOT semantic (BTreeMap sorts): same map either way → stable key.
        let kv = wkey(&[], None, &[("a", "1"), ("b", "2")]);
        let vk = wkey(&[], None, &[("b", "2"), ("a", "1")]);
        assert_eq!(kv.encode(), vk.encode(), "exec_properties insertion order must NOT change the key (sorted)");
    }

    #[test]
    fn host_absolute_path_not_in_action_identity() {
        // REQ-PATHENV-007 (lockdown §4, decision E): the ambient host environment — PATH, HOME, any absolute
        // host path in them — has NO channel into the key. Enforced STRUCTURALLY, not by ambient perturbation:
        // `tools/raw_os.py` (empty allowlist) forbids this crate from naming `std::env` at all, so no ambient
        // value can reach key construction — a prior version of this test mutated the process env to prove it
        // and was itself the wall's first catch (also a parallel-test race hazard). What remains testable
        // here: the key is a pure function of its declared surface (byte-identical reconstruction), and the
        // ambient env never reaches the spawn (the request env is the declared map verbatim). Any future
        // env-inheritance channel must add gates keeping inherited NAMES in the key and resolved host VALUES
        // out of identity.
        let declared: BTreeMap<String, String> = [("CC".to_string(), "gcc".to_string())].into();
        let build = || {
            ActionKey::new("M", vec!["a".into()], declared.clone(), vec![], vec![], vec!["o".into()], None, BTreeMap::new())
        };
        assert_eq!(build().encode(), build().encode(),
            "the key must be a pure function of its declared surface (byte-identical reconstruction)");
        // ...and the ambient values never reach the spawn either: the request env is the declared map verbatim.
        assert_eq!(build().to_request().env, declared, "host env must not leak into the SpawnRequest env");
    }

    #[test]
    fn effective_action_env_in_action_key() {
        // REQ-PATHENV-008 (lockdown §4, R4): the effective env is ONE map from ONE source — exactly the declared
        // env map, encoded in the key AND fed verbatim to the SpawnRequest (no second env channel).
        let declared: BTreeMap<String, String> = [("CC".to_string(), "gcc".to_string()), ("OPT".to_string(), "2".to_string())].into();
        let key = ActionKey::new("M", vec!["a".into()], declared.clone(), vec![], vec![], vec!["o".into()], None, BTreeMap::new());
        // key-env == spawn-env == the declared map (and the key round-trips it losslessly).
        assert_eq!(key.env, declared, "the key's env dimension is the declared map");
        assert_eq!(key.to_request().env, declared, "the spawn env IS the key env (one source, no second channel)");
        assert_eq!(decode_action_key(&key.encode()).unwrap().env, declared, "the encoded key carries the same map");
        // changing a declared VALUE → distinct key (the value, not just the name, is in identity).
        let mut bumped = key.clone();
        bumped.env.insert("OPT".into(), "3".into());
        assert_ne!(key.encode(), bumped.encode(), "changing a declared env value must change the key");
    }

    // The spike's five-frame encoding (pre-widening layout), byte-exact — used to prove (a) the five frames are
    // UNCHANGED under the widening and (b) an old five-frame byte string decodes FAIL-CLOSED, never an alias.
    fn encode_legacy_five_frames(k: &ActionKey) -> Vec<u8> {
        let mut b = Vec::new();
        enc_str(&mut b, &k.mnemonic);
        b.extend_from_slice(&(k.argv.len() as u64).to_be_bytes());
        for a in &k.argv {
            enc_str(&mut b, a);
        }
        b.extend_from_slice(&(k.env.len() as u64).to_be_bytes());
        for (kk, v) in &k.env {
            enc_str(&mut b, kk);
            enc_str(&mut b, v);
        }
        b.extend_from_slice(&(k.inputs.len() as u64).to_be_bytes());
        for i in &k.inputs {
            enc_str(&mut b, &i.path);
            enc_bytes(&mut b, &i.content);
        }
        b.extend_from_slice(&(k.outputs.len() as u64).to_be_bytes());
        for o in &k.outputs {
            enc_str(&mut b, o);
        }
        b
    }

    #[test]
    fn legacy_five_frame_key_is_fail_closed_and_frames_are_stable() {
        // A key with EMPTY inputs so the input-content mutant can't perturb the five-frame prefix comparison.
        let key = ActionKey::new(
            "Compile",
            vec!["cc".into(), "-o".into(), "out".into()],
            [("CC".to_string(), "gcc".to_string())].into(),
            vec![],
            vec![],
            vec!["out".into()],
            None,
            BTreeMap::new(),
        );
        let legacy = encode_legacy_five_frames(&key);
        let widened = key.encode();
        // (a) The spike's five frames are byte-identical and the new frames are strictly APPENDED (§2 freeze).
        assert!(widened.len() > legacy.len(), "the widened encoding must append sentinel frames");
        assert_eq!(&widened[..legacy.len()], &legacy[..],
            "the five spike frames must be byte-identical under the widening (frozen prefix)");
        // (b) FAIL-CLOSED: the old five-frame byte string is a VALID PREFIX of the new layout — the decoder
        // must reject the short input as a typed Invalid, NEVER decode it as a key with empty widened dims.
        match decode_action_key(&legacy) {
            Err(Error::Invalid { .. }) => {}
            Ok(k) => panic!("a pre-widening five-frame key must NOT alias a widened key (decoded {:?})", k.mnemonic),
            Err(e) => panic!("expected a typed Invalid, got {e:?}"),
        }
    }

    #[test]
    fn action_re_run_uses_strategy_not_a_fabricated_output() {
        // mutant_exec_hardcodes_output regresses this: the value's digest would be Digest::of(b"HARDCODED"),
        // not the strategy's content → assertion fails (red under the mutant, green otherwise).
        let key = akey("M", &["x"], &[], &["o"]);
        let val = match run(Arc::new(FakeStrategy), &key) {
            ComputeResult::Ready(v) => v,
            other => panic!("expected Ready, got {:?}", debug_result(&other)),
        };
        let av = val.as_any().downcast_ref::<ActionValue>().unwrap();
        let req = key.to_request();
        let strategy_digest = Digest::of(&fake_output_content(&req, "o"));
        assert_eq!(av.output("o").unwrap().digest, strategy_digest, "the output must come from the strategy");
        assert_ne!(av.output("o").unwrap().digest, Digest::of(b"HARDCODED"),
            "the output must NOT be a fabricated/hardcoded value (the strategy must be invoked)");
    }

    #[test]
    fn missing_declared_output_is_fail_closed() {
        // A strategy that drops a required output → the node fails closed (never an empty/partial value), even
        // though the strategy exited zero.
        let key = akey("Touch", &["c"], &[], &["out/keep", "out/missing"]);
        let strategy = Arc::new(DroppingStrategy { drop: "out/missing".into() });
        match run(strategy, &key) {
            ComputeResult::Error(Error::Invalid { .. }) => {}
            other => panic!("a missing declared output must fail closed, got {:?}", debug_result(&other)),
        }
    }

    #[test]
    fn action_key_round_trips() {
        let key = akey("Mn", &["a", "b"], &[("p/in", b"data")], &["p/out1", "p/out2"]);
        let decoded = decode_action_key(&key.encode()).expect("a well-formed key must decode");
        // The encode is LOSSLESS (inputs inlined), so decode recovers the EXACT key — including input bytes.
        assert_eq!(decoded, key, "decode(encode(k)) == k (lossless: compute rebuilds the exact request)");
        assert_eq!(decoded.encode(), key.encode(), "re-encoding a decoded key must be byte-identical");

        // The WIDENED layout round-trips too: all three new dims populated (lockdown §4 codec extension).
        let full = ActionKey::new(
            "Mn",
            vec!["a".into()],
            [("E".to_string(), "v".to_string())].into(),
            vec![tool("bin/cc", b"cc-bytes"), tool("bin/ld", b"ld-bytes")],
            vec![ActionInput { path: "p/in".into(), content: b"data".to_vec() }],
            vec!["p/out".into()],
            Some(ExecPlatformRef { label: "//p:linux".into(), resolved_digest: b"pdig".to_vec() }),
            [("dockerImage".to_string(), "img:1".to_string())].into(),
        );
        let decoded = decode_action_key(&full.encode()).expect("a fully-populated widened key must decode");
        assert_eq!(decoded, full, "the widened key must round-trip losslessly (tools + exec dims included)");
        assert_eq!(decoded.encode(), full.encode(), "re-encoding a decoded widened key must be byte-identical");
    }

    #[test]
    fn malformed_key_is_fail_closed() {
        assert!(matches!(decode_action_key(b"\x00\x00"), Err(Error::Invalid { .. })),
            "a truncated/garbage key must be a typed Invalid, never a panic");
        // A length field of u64::MAX must be a typed error, never an arithmetic-overflow panic (checked_add).
        assert!(matches!(decode_action_key(&[0xff; 8]), Err(Error::Invalid { .. })),
            "a huge declared length must fail closed, never panic on overflow");

        // The widened layout keeps the discipline (re-asserted over the new frames):
        let key = wkey(&[("bin/cc", b"cc")], Some(ExecPlatformRef { label: "//p:l".into(), resolved_digest: b"d".to_vec() }),
            &[("k", "v")]);
        let good = key.encode();
        // trailing-bytes rejection is preserved.
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(matches!(decode_action_key(&trailing), Err(Error::Invalid { .. })),
            "a widened key with trailing bytes must fail closed");
        // truncation anywhere inside the appended frames is a typed error, never a panic or an alias.
        for cut in 1..good.len() {
            assert!(matches!(decode_action_key(&good[..cut]), Err(Error::Invalid { .. })),
                "a key truncated at byte {cut} must fail closed");
        }
        // a bad exec_platform presence tag (neither 0 nor 1) is a typed error.
        let empty = wkey(&[], None, &[]).encode();
        let mut bad_tag = empty.clone();
        let tag_at = empty.len() - 8 - 1; // ... [tools count 8][TAG 1][props count 8]
        assert_eq!(bad_tag[tag_at], 0, "sanity: the None sentinel tag byte");
        bad_tag[tag_at] = 7;
        assert!(matches!(decode_action_key(&bad_tag), Err(Error::Invalid { .. })),
            "a bad exec_platform tag must be a typed Invalid");
    }

    // small helper so panics in tests show the variant without ActionValue needing Debug on the trait object
    fn debug_result(r: &ComputeResult) -> &'static str {
        match r {
            ComputeResult::Ready(_) => "Ready",
            ComputeResult::Missing { .. } => "Missing",
            ComputeResult::Error(_) => "Error",
            ComputeResult::Reset { .. } => "Reset",
        }
    }
}
