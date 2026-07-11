//! `razel-action` — the execution node-kinds of the ratified artifact-model / action-demand-chain lockdown
//! (`RazelV4ArtifactModelLockdown.md`, RATIFIED 2026-07-06): `ACTION` (KindId 60), `ARTIFACT` (61) and
//! `TARGET_COMPLETION` (62), plus the artifact vocabulary + materializer seams in [`artifact`].
//!
//! ## The demand chain (lockdown §2, decision D — Bazel's mechanism over the FROZEN engine)
//! `TARGET_COMPLETION{ct, Default}` requests `CONFIGURED_TARGET(ct)`, derives the default-output
//! `ArtifactRef`s ([`derived_outputs`] — the R8 conflict pass), and requests them as one dep group (its
//! value is a sentinel — the dep requests ARE the build). Each `ARTIFACT` requests its producer (`FILE`
//! for source, `ACTION{owner,idx}` for derived) and projects the ONE `{exec_path, digest}` entry. Each
//! `ACTION` requests `CONFIGURED_TARGET(owner)` for `actions[index]` (the `getAction(index)` analog — a
//! real edge, so analysis edits dirty executed actions automatically), resolves each template input path
//! via the [`InputResolver`] seam, requests the inputs' `ARTIFACT` nodes as a group, fetches bytes from
//! the [`BlobStore`] by digest, and only then spawns. Every "not yet available" is `Demand::Missing` →
//! `ComputeResult::Missing` (the frozen restart contract); the CT never demands its actions — demand
//! flows top-down from completion (the Bazel phase split).
//!
//! ## Keys vs the fingerprint (the `RazelV4ActionKeyLockdown.md` THAW AMENDMENT, ratified 2026-07-06)
//! The `ACTION` NODE key is **positional** — [`GeneratingActionKey`]`{owner, action_index}` (Bazel
//! `ActionLookupData`) — so the node dirties IN PLACE on analysis/input edits and the engine's
//! minimal-invalidation + early-cutoff accounting fires for the one phase v3 died in. The frozen 8-dim
//! [`ActionKey`] struct + canonical encode survive BYTE-IDENTICAL, re-homed as the in-node content
//! FINGERPRINT (the cache identity + conformance/golden fingerprint), computed inside `compute()` after
//! inputs resolve — `action_key_from_template` is its production call site. A content node-key cannot
//! grow input edges (the lockdown §0 bootstrap paradox); the fingerprint no longer names an engine node.
//!
//! Fail-closed (#1 rule): a declared output the strategy did not produce is a typed error via the shared
//! `razel_exec_api::validate_outputs` (both directions, independent of the exit code, ADR-0012); an
//! unresolvable input, an out-of-range action index, a projection the producer lacks, and a missing blob
//! digest are all typed errors — never a fabricated empty value (the Absorb shape). Malformed keys decode
//! to typed `Error`s, never panics.

use razel_core::{Digest, Error, KindId, NodeKey, Value, ValuePolicy};
use razel_engine_api::{ComputeResult, Demand, DemandContext, DemandEngine, NodeFunction};
use razel_exec_api::{validate_outputs, ExecError, SpawnResult, SpawnStrategy};
use razel_os_api::{HostPath, System};
use std::any::Any;
#[cfg(feature = "mutant_action_skips_input_artifact_edges")]
use std::collections::HashMap;
#[cfg(feature = "mutant_action_skips_input_artifact_edges")]
use std::sync::Mutex;
use std::sync::Arc;

pub mod artifact;
pub mod fingerprint;
pub use artifact::{
    decode_artifact_ref, decode_generating_action_key, decode_target_completion_key, derived_outputs,
    ArtifactFn, ArtifactProducer, ArtifactRef, ArtifactValue, BlobStore, GeneratingActionKey,
    InMemoryBlobStore, InputResolver, OutputSelection, SameTargetOrSourceResolver, TargetCompletionFn,
    TargetCompletionKey, TargetCompletionValue,
};
pub use fingerprint::{action_key_from_template, ActionInput, ActionKey, ExecPlatformRef};
use artifact::as_configured_target;

pub const ACTION: KindId = KindId(60);
pub const ARTIFACT: KindId = KindId(61);
pub const TARGET_COMPLETION: KindId = KindId(62);

// The 8-dim fingerprint vocabulary (ActionKey/ActionInput/ExecPlatformRef + the frozen encode) lives in
// [`fingerprint`]; the artifact vocabulary (keys, seams, projections) in [`artifact`]. This file keeps the
// ACTION node function, its value, and the kind registration.

// ───── canonical encode helpers: length-framed so no field can bleed into the next (lossless);
// shared with the fingerprint module (the ONE framing discipline) ─────
pub(crate) fn enc_str(b: &mut Vec<u8>, s: &str) {
    b.extend_from_slice(&(s.len() as u64).to_be_bytes());
    b.extend_from_slice(s.as_bytes());
}
pub(crate) fn enc_bytes(b: &mut Vec<u8>, bytes: &[u8]) {
    b.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    b.extend_from_slice(bytes);
}

// ──────────────── value: the action's result (outputs → digest + the exit status) ────────────────

/// One produced output, recorded by LOGICAL path + content digest (NOT the raw bytes — the value is an
/// identity, the `BlobStore` holds bytes; R5). The value is the cacheable summary the engine compares for
/// early cutoff.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OutputDigest {
    pub path: String,
    pub digest: Digest,
}

/// `ACTION` value: the exit code + the produced outputs as `(path -> Digest)`, name-sorted (deterministic →
/// early cutoff applies: an action whose inputs change but whose outputs are byte-identical cuts off here).
/// UNCHANGED by the re-key (lockdown §2) — already the Bazel `ActionExecutionValue` shape, metadata-only.
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

// ──────────────── node function: CT → templates → resolve → materialize → fingerprint → spawn ────────────────

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

/// `ACTION`: run ONE declared action as a GRAPH CONSEQUENCE — keyed positionally by
/// [`GeneratingActionKey`], non-leaf per the §2 chain. The strategy stays the FAN-OUT seam (local/sandbox/
/// remote/fake behind `Arc<dyn SpawnStrategy>`, constructor-injected); the resolver and blob store are the
/// two materializer seams (host-injected compile walls, decisions E/G).
pub struct ActionFn {
    strategy: Arc<dyn SpawnStrategy>,
    resolver: Arc<dyn InputResolver>,
    blobs: Arc<dyn BlobStore>,
    /// MUTANT channel (`mutant_action_skips_input_artifact_edges`): a node-local digest memo that lets the
    /// mutant materialize WITHOUT re-declaring the ARTIFACT edges. Never present in a real build.
    #[cfg(feature = "mutant_action_skips_input_artifact_edges")]
    input_memo: Mutex<HashMap<NodeKey, Digest>>,
}
impl ActionFn {
    pub fn new(strategy: Arc<dyn SpawnStrategy>, resolver: Arc<dyn InputResolver>, blobs: Arc<dyn BlobStore>) -> Self {
        Self {
            strategy,
            resolver,
            blobs,
            #[cfg(feature = "mutant_action_skips_input_artifact_edges")]
            input_memo: Mutex::new(HashMap::new()),
        }
    }
}
impl NodeFunction for ActionFn {
    fn compute(&self, key: &NodeKey, ctx: &mut dyn DemandContext) -> ComputeResult {
        // (1) the positional key (decision B). Fail-closed: a pre-re-key CONTENT-encoded byte string is a
        // typed Invalid, never an alias.
        let gak = match decode_generating_action_key(key.canonical()) {
            Ok(k) => k,
            Err(e) => return ComputeResult::Error(e),
        };
        // (2) the owning CT — a REAL edge (the getAction(index) analog): an analysis edit dirties this
        // node automatically; the action body is re-fetched from the owner by index every pass.
        let ct_key = NodeKey::from_key(&gak.owner);
        let ctv = match ctx.request(&ct_key) {
            Demand::Missing => return ComputeResult::Missing { recorded_dep_keys: vec![ct_key] },
            Demand::Ready(v) => v,
        };
        let ct = match as_configured_target(&ctv) {
            Ok(c) => c,
            Err(e) => return ComputeResult::Error(e),
        };
        // (3) actions[index] — a typed error if out of range (never a silent no-op).
        let tmpl = match ct.actions.get(gak.action_index as usize) {
            Some(t) => t.clone(),
            None => {
                return ComputeResult::Error(Error::Invalid {
                    what: "ACTION index".into(),
                    detail: format!(
                        "//{}:{} declares {} action(s); index {} is out of range",
                        gak.owner.package, gak.owner.name, ct.actions.len(), gak.action_index
                    ),
                })
            }
        };
        // (4) resolve each template input path → ArtifactRef via the seam (fail-closed, decision E).
        let mut refs: Vec<ArtifactRef> = Vec::with_capacity(tmpl.inputs.len());
        let mut absorbed: Vec<ActionInput> = Vec::new(); // stays empty except under the absorb MUTANT
        for p in &tmpl.inputs {
            match self.resolver.resolve(&gak.owner, ct, p) {
                Ok(r) => refs.push(r),
                Err(_e) if cfg!(feature = "mutant_input_resolver_absorbs_unknown") => {
                    // MUTANT: the unresolvable input is ABSORBED into a fabricated EMPTY input with no
                    // edge — the exact "just pass empty content for unresolved inputs" shape the lockdown
                    // §0 forbids. `unresolvable_input_fails_closed` (unit + over the root) reds.
                    absorbed.push(ActionInput { path: p.clone(), content: Vec::new() });
                }
                Err(e) => return ComputeResult::Error(e),
            }
        }
        // (5) request the inputs' ARTIFACT nodes as ONE group; the edge currency is {exec_path → digest}.
        let artifact_keys: Vec<NodeKey> = refs.iter().map(NodeKey::from_key).collect();
        let mut pairs: Vec<(String, Digest)> = Vec::with_capacity(refs.len());
        #[cfg(feature = "mutant_action_skips_input_artifact_edges")]
        let memo_hit = {
            // MUTANT: materialize from a node-local memo instead of re-requesting the ARTIFACT nodes —
            // the edges are not re-declared this pass, so the engine DROPS them (REQ-ENGINE-005) and an
            // input edit invalidates nothing (stale bytes served). `input_edit_reruns_downstream_action`
            // reds.
            let memo = self.input_memo.lock().unwrap();
            if !artifact_keys.is_empty() && artifact_keys.iter().all(|k| memo.contains_key(k)) {
                for (i, k) in artifact_keys.iter().enumerate() {
                    pairs.push((refs[i].exec_path.clone(), memo[k]));
                }
                true
            } else {
                false
            }
        };
        #[cfg(not(feature = "mutant_action_skips_input_artifact_edges"))]
        let memo_hit = false;
        if !memo_hit {
            let demands = ctx.request_group(&artifact_keys);
            let mut missing: Vec<NodeKey> = Vec::new();
            for (i, d) in demands.into_iter().enumerate() {
                match d {
                    Demand::Missing => missing.push(artifact_keys[i].clone()),
                    Demand::Ready(v) => match v.as_any().downcast_ref::<ArtifactValue>() {
                        Some(a) => {
                            if a.exec_path != refs[i].exec_path {
                                return ComputeResult::Error(Error::Invalid {
                                    what: "ARTIFACT dep".into(),
                                    detail: format!(
                                        "value path '{}' does not match the requested ref '{}'",
                                        a.exec_path, refs[i].exec_path
                                    ),
                                });
                            }
                            pairs.push((a.exec_path.clone(), a.digest));
                        }
                        None => {
                            return ComputeResult::Error(Error::Invalid {
                                what: "ARTIFACT dep".into(),
                                detail: "not an ArtifactValue".into(),
                            })
                        }
                    },
                }
            }
            if !missing.is_empty() {
                return ComputeResult::Missing { recorded_dep_keys: missing };
            }
            #[cfg(feature = "mutant_action_skips_input_artifact_edges")]
            {
                let mut memo = self.input_memo.lock().unwrap();
                for (i, k) in artifact_keys.iter().enumerate() {
                    memo.insert(k.clone(), pairs[i].1);
                }
            }
        }
        // (6) materialize bytes from the ONE home (fail-closed: an absent digest is a typed error, never
        // empty — no Absorb).
        let mut inputs = absorbed;
        for (path, digest) in &pairs {
            let content = match self.blobs.get(digest) {
                Ok(b) => b,
                Err(e) => return ComputeResult::Error(e),
            };
            inputs.push(ActionInput { path: path.clone(), content });
        }
        // (7) the frozen 8-dim fingerprint — `action_key_from_template`'s PRODUCTION call site (inputs now
        // real). The canonical encode bytes are the cache identity, computed at the exact seam the action
        // cache will occupy (Bazel's checkCacheAndExecuteIfNeeded slot); v1 has no AC yet, so it re-spawns
        // on same-fingerprint recomputes (correct-but-slower, lockdown §6.3) while downstream ARTIFACT
        // consumers still cut off via `value_eq`.
        let ak = action_key_from_template(&tmpl, inputs);
        let _cache_fingerprint: Vec<u8> = ak.encode();
        let req = ak.to_request();

        if cfg!(feature = "mutant_exec_hardcodes_output") {
            // MUTANT: fabricate the outputs instead of calling the strategy → the seam is bypassed (a
            // hardcoded "subprocess"). The output content is NOT the strategy's, so a test pinning the
            // strategy's content goes RED. This is the "bypasses the strategy" mutant.
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
        // Fail-closed: every declared output MUST be present and no undeclared output admitted, even on
        // exit zero (ADR-0012). One validator, shared with the exec-api conformance, so the node and a
        // strategy impl can't drift on the rule.
        if let Err(e) = validate_outputs(&ak.mnemonic, &req, &res) {
            return ComputeResult::Error(map_exec(e));
        }
        // (8) outputs' bytes → the ONE home; the published value stays metadata-only (digests, R5).
        for o in &res.outputs {
            self.blobs.put(&o.content);
        }
        ComputeResult::Ready(Arc::new(ActionValue::from_spawn(&res)))
    }
}

/// Register the execution node-kinds — `ACTION` + `ARTIFACT` + `TARGET_COMPLETION` — on an engine,
/// injecting the chosen `SpawnStrategy`, the `InputResolver`, the `BlobStore` and the OS seam (`sys` +
/// `root`, the ARTIFACT Source arm's byte channel). The composition root (`razel-host`) calls this with
/// its concrete impls (fake strategy in tests, local/sandbox/remote in prod) — `razel-action` never names
/// a concrete strategy, resolver policy is swappable behind the seam, and node values stay metadata-only.
pub fn register_action_kinds(
    engine: &mut dyn DemandEngine,
    strategy: Arc<dyn SpawnStrategy>,
    resolver: Arc<dyn InputResolver>,
    blobs: Arc<dyn BlobStore>,
    sys: Arc<dyn System>,
    root: HostPath,
) {
    engine.register(ACTION, Box::new(ActionFn::new(strategy, resolver, blobs.clone())));
    engine.register(ARTIFACT, Box::new(ArtifactFn::new(blobs, sys, root)));
    engine.register(TARGET_COMPLETION, Box::new(TargetCompletionFn));
}

#[cfg(test)]
mod tests {
    use super::artifact::testctx::MapCtx;
    use super::*;
    use razel_analysis::{ConfiguredTarget, ConfiguredTargetKey};
    use razel_bzl_api::ActionTemplate;
    use razel_exec_api::conformance::{fake_output_content, DroppingStrategy, FakeStrategy};
    use razel_exec_api::{InputArtifact, SpawnRequest};
    use std::collections::BTreeMap;

    // ── the positional exam harness: a CT served from a map ctx; a fresh blob store per exam ──

    fn owner(pkg: &str, name: &str) -> ConfiguredTargetKey {
        ConfiguredTargetKey {
            package: pkg.into(),
            name: name.into(),
            configuration: None,
            exec_platform: None,
            rule_transition: None,
        }
    }
    fn template(mnemonic: &str, argv: &[&str], inputs: &[&str], outputs: &[&str]) -> ActionTemplate {
        ActionTemplate {
            mnemonic: mnemonic.into(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            env: Vec::new(),
            inputs: inputs.iter().map(|s| s.to_string()).collect(),
            outputs: outputs.iter().map(|s| s.to_string()).collect(),
        }
    }
    struct Exam {
        blobs: Arc<InMemoryBlobStore>,
        f: ActionFn,
    }
    fn exam(strategy: Arc<dyn SpawnStrategy>) -> Exam {
        let blobs = Arc::new(InMemoryBlobStore::new());
        Exam { blobs: blobs.clone(), f: ActionFn::new(strategy, Arc::new(SameTargetOrSourceResolver), blobs) }
    }
    fn gak(pkg: &str, name: &str, idx: u32) -> GeneratingActionKey {
        GeneratingActionKey { owner: owner(pkg, name), action_index: idx }
    }
    fn req_of(mnemonic: &str, argv: &[&str], inputs: &[(&str, &[u8])], outputs: &[&str]) -> SpawnRequest {
        SpawnRequest::new(
            mnemonic,
            argv.iter().map(|s| s.to_string()).collect(),
            BTreeMap::new(),
            inputs.iter().map(|(p, c)| InputArtifact { path: p.to_string(), content: c.to_vec() }).collect(),
            outputs.iter().map(|s| s.to_string()).collect(),
        )
    }

    #[test]
    fn action_executes_and_produces_expected_output() {
        // The headline node contract under the POSITIONAL key: ACTION{owner,0} fetches its template from
        // the CT, materializes its input off the graph (ARTIFACT digest → BlobStore bytes), runs the fake
        // strategy, and digests the strategy's bytes. The test constructs NO content node-key.
        let ex = exam(Arc::new(FakeStrategy));
        let o = owner("app", "t");
        let ct = ConfiguredTarget { providers: vec![], dep_outputs: vec![], actions: vec![template("Touch", &["cat", "in"], &["in"], &["out/o"])] };
        let in_digest = ex.blobs.put(b"hello");
        let in_ref = ArtifactRef { exec_path: "in".into(), producer: ArtifactProducer::Source };
        let mut ctx = MapCtx::new()
            .serve(&o, ct)
            .serve(&in_ref, ArtifactValue { exec_path: "in".into(), digest: in_digest });
        let val = match ex.f.compute(&NodeKey::from_key(&gak("app", "t", 0)), &mut ctx) {
            ComputeResult::Ready(v) => v,
            other => panic!("action must execute and be Ready, got {:?}", debug_result(&other)),
        };
        let av = val.as_any().downcast_ref::<ActionValue>().expect("value is an ActionValue");
        assert_eq!(av.exit_code, 0);
        // The output digest must be the FAKE strategy's deterministic content for the MATERIALIZED request
        // — proving the node ran the strategy AND the input bytes came off the graph.
        let expected_req = req_of("Touch", &["cat", "in"], &[("in", b"hello")], &["out/o"]);
        let expected = Digest::of(&fake_output_content(&expected_req, "out/o"));
        assert_eq!(av.output("out/o").expect("declared output present").digest, expected,
            "the value must carry the digest of the STRATEGY's produced content over the MATERIALIZED input");
        // ...and the produced bytes landed in the ONE home (readable by consumers via digest).
        assert_eq!(
            ex.blobs.get(&expected).expect("output bytes stored"),
            fake_output_content(&expected_req, "out/o"),
            "output bytes must be stored in the BlobStore under their digest"
        );
    }

    #[test]
    fn action_requests_owner_ct_then_input_artifacts() {
        // The §2 demand chain, edge by edge: pass 1 requests the OWNER CT (the getAction(index) analog);
        // with the CT served, pass 2 requests the inputs' ARTIFACT nodes as one group.
        let ex = exam(Arc::new(FakeStrategy));
        let key = NodeKey::from_key(&gak("app", "t", 0));
        let mut cold = MapCtx::new();
        match ex.f.compute(&key, &mut cold) {
            ComputeResult::Missing { recorded_dep_keys } => {
                assert_eq!(recorded_dep_keys, vec![NodeKey::from_key(&owner("app", "t"))], "the owner CT is the first edge");
            }
            other => panic!("expected Missing on the CT, got {:?}", debug_result(&other)),
        }
        let ct = ConfiguredTarget { providers: vec![], dep_outputs: vec![], actions: vec![template("M", &["x"], &["in"], &["o"])] };
        let in_ref = ArtifactRef { exec_path: "in".into(), producer: ArtifactProducer::Source };
        let mut with_ct = MapCtx::new().serve(&owner("app", "t"), ct);
        match ex.f.compute(&key, &mut with_ct) {
            ComputeResult::Missing { recorded_dep_keys } => {
                assert_eq!(recorded_dep_keys, vec![NodeKey::from_key(&in_ref)],
                    "the resolved input's ARTIFACT node is the second edge");
            }
            other => panic!("expected Missing on the input group, got {:?}", debug_result(&other)),
        }
    }

    #[test]
    fn action_index_out_of_range_fails_closed() {
        let ex = exam(Arc::new(FakeStrategy));
        let ct = ConfiguredTarget { providers: vec![], dep_outputs: vec![], actions: vec![template("M", &["x"], &[], &["o"])] };
        let mut ctx = MapCtx::new().serve(&owner("app", "t"), ct);
        match ex.f.compute(&NodeKey::from_key(&gak("app", "t", 5)), &mut ctx) {
            ComputeResult::Error(Error::Invalid { .. }) => {}
            other => panic!("an out-of-range action index must fail closed, got {:?}", debug_result(&other)),
        }
    }

    #[test]
    fn unresolvable_input_fails_closed() {
        // Lockdown §4: a path the resolver cannot map (absolute here) is a typed error at the ACTION node —
        // NEVER empty content or a skipped edge. `mutant_input_resolver_absorbs_unknown` regresses this
        // (the action would run with a fabricated empty input and return Ready).
        let ex = exam(Arc::new(FakeStrategy));
        let ct = ConfiguredTarget { providers: vec![], dep_outputs: vec![], actions: vec![template("M", &["x"], &["/etc/passwd"], &["o"])] };
        let mut ctx = MapCtx::new().serve(&owner("app", "t"), ct);
        match ex.f.compute(&NodeKey::from_key(&gak("app", "t", 0)), &mut ctx) {
            ComputeResult::Error(Error::Unsupported { .. }) => {}
            other => panic!("an unresolvable input form must fail closed, got {:?}", debug_result(&other)),
        }
    }

    #[test]
    fn missing_blob_digest_fails_closed_at_the_action() {
        // The ARTIFACT names a digest the BlobStore never held → blobs.get is a typed NotFound surfacing
        // from the ACTION node — never empty input bytes.
        let ex = exam(Arc::new(FakeStrategy));
        let ct = ConfiguredTarget { providers: vec![], dep_outputs: vec![], actions: vec![template("M", &["x"], &["in"], &["o"])] };
        let in_ref = ArtifactRef { exec_path: "in".into(), producer: ArtifactProducer::Source };
        let mut ctx = MapCtx::new()
            .serve(&owner("app", "t"), ct)
            .serve(&in_ref, ArtifactValue { exec_path: "in".into(), digest: Digest::of(b"never stored") });
        match ex.f.compute(&NodeKey::from_key(&gak("app", "t", 0)), &mut ctx) {
            ComputeResult::Error(Error::NotFound { .. }) => {}
            other => panic!("a missing blob digest must fail closed, got {:?}", debug_result(&other)),
        }
    }

    #[test]
    fn action_re_run_uses_strategy_not_a_fabricated_output() {
        // mutant_exec_hardcodes_output regresses this: the value's digest would be Digest::of(b"HARDCODED"),
        // not the strategy's content → assertion fails (red under the mutant, green otherwise).
        let ex = exam(Arc::new(FakeStrategy));
        let ct = ConfiguredTarget { providers: vec![], dep_outputs: vec![], actions: vec![template("M", &["x"], &[], &["o"])] };
        let mut ctx = MapCtx::new().serve(&owner("app", "t"), ct);
        let val = match ex.f.compute(&NodeKey::from_key(&gak("app", "t", 0)), &mut ctx) {
            ComputeResult::Ready(v) => v,
            other => panic!("expected Ready, got {:?}", debug_result(&other)),
        };
        let av = val.as_any().downcast_ref::<ActionValue>().unwrap();
        let strategy_digest = Digest::of(&fake_output_content(&req_of("M", &["x"], &[], &["o"]), "o"));
        assert_eq!(av.output("o").unwrap().digest, strategy_digest, "the output must come from the strategy");
        assert_ne!(av.output("o").unwrap().digest, Digest::of(b"HARDCODED"),
            "the output must NOT be a fabricated/hardcoded value (the strategy must be invoked)");
    }

    #[test]
    fn missing_declared_output_is_fail_closed() {
        // A strategy that drops a required output → the node fails closed (never an empty/partial value), even
        // though the strategy exited zero.
        let ex = exam(Arc::new(DroppingStrategy { drop: "out/missing".into() }));
        let ct = ConfiguredTarget { providers: vec![], dep_outputs: vec![], actions: vec![template("Touch", &["c"], &[], &["out/keep", "out/missing"])] };
        let mut ctx = MapCtx::new().serve(&owner("app", "t"), ct);
        match ex.f.compute(&NodeKey::from_key(&gak("app", "t", 0)), &mut ctx) {
            ComputeResult::Error(Error::Invalid { .. }) => {}
            other => panic!("a missing declared output must fail closed, got {:?}", debug_result(&other)),
        }
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
