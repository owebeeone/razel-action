//! `razel-action` — the `ACTION` execution node-kind (Milestone C / #5), `KindId(60)`. Runs ONE declared action
//! via the `SpawnStrategy` seam and yields the produced outputs. Keyed by the action's CONTENT fingerprint
//! (mnemonic + argv + declared-only env + input identities&digests + declared outputs), so the node re-runs only
//! when that key changes — the content key IS the cache + incrementality (ADR-0012's action-identity direction).
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

/// `ACTION` key — the action's CONTENT fingerprint. `encode()` is the canonical, deterministic, LOSSLESS
/// encoding: mnemonic + argv (ordered — argv order is semantic) + env (sorted by name — order is NOT semantic) +
/// inputs (sorted by path, each `(path, content)` INLINED) + declared outputs (sorted, deduped). Two actions
/// share a key IFF every one of these is equal → the node re-runs exactly when one changes (the cache +
/// incrementality), and `compute` rebuilds the exact request from the key (lossless ⇒ no separate byte channel).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ActionKey {
    pub mnemonic: String,
    pub argv: Vec<String>,
    /// Declared env only (REQ-PATHENV-008) — `BTreeMap` is sorted, so the key is order-insensitive in env.
    pub env: BTreeMap<String, String>,
    /// Sorted by path in `new`; each input contributes its content DIGEST to the key (not raw bytes).
    pub inputs: Vec<ActionInput>,
    /// Declared outputs the strategy MUST produce (sorted, deduped in `new`).
    pub outputs: Vec<String>,
}
impl ActionKey {
    /// Build a key with the canonicalization the kind guarantees: inputs sorted by path, outputs sorted+deduped.
    pub fn new(
        mnemonic: impl Into<String>,
        argv: Vec<String>,
        env: BTreeMap<String, String>,
        mut inputs: Vec<ActionInput>,
        mut outputs: Vec<String>,
    ) -> ActionKey {
        inputs.sort_by(|a, b| a.path.cmp(&b.path));
        outputs.sort();
        outputs.dedup();
        ActionKey { mnemonic: mnemonic.into(), argv, env, inputs, outputs }
    }

    /// The `SpawnRequest` this action runs as. The bytes the strategy needs travel here; the key (above) used the
    /// digests. Built fresh from the key so the request is a pure function of the key (no hidden state).
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

// ───── canonical encode: length-framed so no field can bleed into the next; digests, not bytes, for inputs ─────
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
        if self.i + n > self.b.len() {
            return Err(Self::err("truncated"));
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
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
/// typed `Error::Invalid`, never a panic.
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
    if c.i != c.b.len() {
        return Err(Cur::err("trailing bytes"));
    }
    Ok(ActionKey { mnemonic, argv, env, inputs, outputs })
}

// ──────────────── node function: build request → strategy.spawn → validate outputs → value ────────────────

fn map_exec(e: ExecError) -> Error {
    match e {
        ExecError::OutputNotProduced { mnemonic, path } => {
            Error::InputMissing { what: "declared action output".into(), detail: format!("{mnemonic}: {path}") }
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
    }

    fn akey(mnemonic: &str, argv: &[&str], inputs: &[(&str, &[u8])], outputs: &[&str]) -> ActionKey {
        ActionKey::new(
            mnemonic,
            argv.iter().map(|s| s.to_string()).collect(),
            BTreeMap::new(),
            inputs.iter().map(|(p, c)| ActionInput { path: p.to_string(), content: c.to_vec() }).collect(),
            outputs.iter().map(|s| s.to_string()).collect(),
        )
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
            vec![ActionInput { path: "in".into(), content: b"v1".to_vec() }],
            vec!["o".into()],
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
            ComputeResult::Error(Error::InputMissing { .. }) => {}
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
    }

    #[test]
    fn malformed_key_is_fail_closed() {
        assert!(matches!(decode_action_key(b"\x00\x00"), Err(Error::Invalid { .. })),
            "a truncated/garbage key must be a typed Invalid, never a panic");
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
