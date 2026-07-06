//! The FROZEN 8-dim action fingerprint (`RazelV4ActionKeyLockdown.md` §2, ratified 2026-07-06): the
//! [`ActionKey`] struct, its canonical byte-encode (golden-vector-stable), the fail-closed decoder, and
//! the template→fingerprint constructor. Under the artifact-model lockdown's THAW AMENDMENT the encode
//! bytes are **no longer an engine node key** — they are the in-node content fingerprint / cache identity,
//! computed inside `ACTION::compute` after inputs resolve. The bytes themselves are UNTOUCHED (the thaw is
//! a re-homing, not a re-shape); the unit tests below pin them.

use crate::artifact::Cur;
use crate::{enc_bytes, enc_str};
use razel_bzl_api::ActionTemplate;
use razel_core::Error;
use razel_exec_api::{InputArtifact, SpawnRequest};
use std::collections::BTreeMap;

/// One resolved input: its LOGICAL (exec-relative) path + its content bytes, materialized from the graph
/// (ARTIFACT digest → BlobStore bytes) inside `ACTION::compute`. Shared by the fingerprint's `inputs` and
/// `tools` dimensions and by the `SpawnRequest`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ActionInput {
    pub path: String,
    pub content: Vec<u8>,
}

/// The execution-platform reference folded into the fingerprint (ADR-0012 lockdown decision C / R2): the
/// platform's LABEL **and** its RESOLVED content digest — mirroring Bazel `PlatformInfo.addTo`, which folds
/// both, so a platform target edited under an unchanged label is a DIFFERENT fingerprint. Label-only is not
/// Bazel-compatible. `resolved_digest` is carried as opaque digest bytes (e.g. `Digest::of(platform_content)`
/// output) rather than `razel_core::Digest`, because the fingerprint must decode LOSSLESSLY and `Digest`
/// exposes no from-bytes constructor.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ExecPlatformRef {
    pub label: String,
    pub resolved_digest: Vec<u8>,
}

/// The action's CONTENT FINGERPRINT — the EIGHT ratified dimensions (ADR-0012 +
/// `RazelV4ActionKeyLockdown.md` §2, frozen-unless-thawed): mnemonic + argv (ordered — argv order is
/// semantic) + env (sorted by name — order is NOT semantic) + tools (sorted by path, same `(path, content)`
/// shape as inputs) + inputs (sorted by path, each `(path, content)` INLINED) + declared outputs (sorted,
/// deduped) + exec_platform (`None` = host assumed) + exec_properties (merged map, sorted). Two actions
/// share a fingerprint IFF every one of these is equal.
///
/// ROLE (the thaw amendment): this is **no longer the engine node key** — the `ACTION` node is keyed by
/// [`crate::GeneratingActionKey`] (positional). The fingerprint is computed INSIDE `compute()` from
/// `(template, resolved inputs)` and is the cache identity the future action cache keys on (Bazel's
/// `ActionKeyComputer` / `checkCacheAndExecuteIfNeeded` seam) and the conformance/golden fingerprint. Its
/// canonical `encode()` bytes are UNCHANGED — golden-vector-stable.
///
/// v1 sentinels (ADR-0010 discipline): `tools` empty (count frame 0), `exec_platform` `None` (tag 0),
/// `exec_properties` empty (count frame 0) — so minimal-cut fingerprints are byte-stable forever and any
/// future non-empty value is a *different* fingerprint, never a silent alias.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ActionKey {
    pub mnemonic: String,
    pub argv: Vec<String>,
    /// Declared env only (REQ-PATHENV-008) — `BTreeMap` is sorted, so the fingerprint is order-insensitive
    /// in env. This is the ONE env map: the same values are fed verbatim to the `SpawnRequest` (no second
    /// channel); inherited host values (PATH etc.) never enter unless declared (lockdown decision E / R4).
    pub env: BTreeMap<String, String>,
    /// (dim 4) — the tool subset of inputs, keyed by the SAME `(path, content)` shape (decision B / R1);
    /// sorted by path in `new`. Discipline: `tools ⊆ inputs` semantics — a marker slot, never a second
    /// digest of the same file. v1 sentinel: empty. (Tool runfiles are IN SCOPE for the contract but SCOPED
    /// OUT of the minimal cut: when a tool carries runfiles, it enters as ONE synthetic runfiles-tree entry
    /// in this same vec — additive, no struct change.)
    pub tools: Vec<ActionInput>,
    /// Sorted by path in `new`; each input's `(path, content bytes)` is INLINED (lossless), so the
    /// fingerprint changes when an input's bytes change. The bytes→producer-digest encode swap is the
    /// deferred step ordered AFTER this chain (`RazelV4ArtifactModelLockdown.md` §6.4).
    pub inputs: Vec<ActionInput>,
    /// Declared outputs the strategy MUST produce (sorted, deduped in `new`).
    pub outputs: Vec<String>,
    /// (dim 7) — the execution platform, folded centrally as presence + label + resolved content
    /// (decision C / R2). `None` = host assumed. v1 sentinel: `None` (tag 0).
    pub exec_platform: Option<ExecPlatformRef>,
    /// (dim 8) — the merged per-exec-group properties map (platform < target precedence), canonically
    /// sorted by construction (`BTreeMap`, decision D). v1 sentinel: empty (count frame 0).
    pub exec_properties: BTreeMap<String, String>,
}
impl ActionKey {
    /// Build a fingerprint with the canonicalization the kind guarantees: tools + inputs sorted by path,
    /// outputs sorted+deduped, env/exec_properties sorted by construction (`BTreeMap`).
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

    /// The canonical encoding, FROZEN at the ADR-0012 widening (`RazelV4ActionKeyLockdown.md` §2) and
    /// BYTE-IDENTICAL under the thaw re-homing: the spike's five frames in their original order —
    /// `mnemonic, argv, env, inputs, outputs` — then the three appended frames: `tools` (count frame,
    /// per-entry path + content), `exec_platform` (presence tag 0/1 + label frame + digest frame),
    /// `exec_properties` (count frame + sorted `(k,v)` frames). These bytes are the cache identity and the
    /// conformance/golden fingerprint (no longer a node key — the thaw amendment).
    pub fn encode(&self) -> Vec<u8> {
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
            // MUTANT: omit the input's content from the fingerprint → an input edit yields the SAME
            // fingerprint (a wrong-cache-hit once the AC keys on it). The "key changes with inputs" test reds.
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
        // COLLIDE to the same fingerprint and the cache silently serves the WRONG output — the §0
        // under-keying trap. `action_key_changes_for_tools` reds.
        if !cfg!(feature = "mutant_action_key_drops_tools") {
            b.extend_from_slice(&(self.tools.len() as u64).to_be_bytes());
            for t in &self.tools {
                enc_str(&mut b, &t.path);
                enc_bytes(&mut b, &t.content);
            }
        }
        // MUTANT: omit the exec dims (presence tag + properties frame) → the "same" action on a different
        // exec platform / with different exec_properties fingerprints identically (wrong-cache-hit).
        // `action_key_changes_for_exec` reds.
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

    /// The `SpawnRequest` this action runs as — the bytes the strategy needs. Rebuilt straight from the
    /// fingerprint (a pure function of it, no hidden state), so key-env == spawn-env == the one declared map.
    pub(crate) fn to_request(&self) -> SpawnRequest {
        SpawnRequest::new(
            self.mnemonic.clone(),
            self.argv.clone(),
            self.env.clone(),
            self.inputs.iter().map(|i| InputArtifact { path: i.path.clone(), content: i.content.clone() }).collect(),
            self.outputs.clone(),
        )
    }
}

/// Decode the canonical 8-dim fingerprint bytes back to an [`ActionKey`]. The encode INLINES input content
/// losslessly, so decode recovers the EXACT fingerprint (`decode(encode(k)) == k`). Fail-closed: a
/// malformed/truncated input is a typed `Error::Invalid`, never a panic — and a PRE-WIDENING five-frame
/// byte string is `Error::Invalid` too (its widened frames are missing → "truncated"), never a silent alias
/// of a widened fingerprint with empty dims. (No production caller decodes this anymore — the node key is
/// positional — but the codec properties stay frozen with the encode; the tests below keep them pinned.)
#[cfg_attr(not(test), allow(dead_code))]
fn decode_action_key(bytes: &[u8]) -> Result<ActionKey, Error> {
    let mut c = Cur::new(bytes, "ActionKey fingerprint");
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
        // Under the input-omitting mutant the content field is absent from encode; tolerate both so decode
        // stays total + symmetric with the active encoding (the round-trip property must hold under the
        // mutant too).
        let content = if cfg!(feature = "mutant_action_ignores_inputs_in_key") { Vec::new() } else { c.bytes()? };
        inputs.push(ActionInput { path, content });
    }
    let outc = c.u64()? as usize;
    let mut outputs = Vec::with_capacity(outc);
    for _ in 0..outc {
        outputs.push(c.str()?);
    }
    // ── the three widened frames (symmetric with encode; frame-absent under each drop-mutant so decode
    // stays total over the active encoding) ──
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
            t => {
                return Err(Error::Invalid {
                    what: "ActionKey fingerprint".into(),
                    detail: format!("bad exec_platform tag {t}"),
                })
            }
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
    c.finish()?;
    Ok(ActionKey { mnemonic, argv, env, tools, inputs, outputs, exec_platform, exec_properties })
}

/// Convert an analysis-emitted [`ActionTemplate`] + its RESOLVED inputs into the 8-dim fingerprint. THE
/// production caller is `ACTION::compute` (step 7 of the §2 chain) — the materialized `(path, content)`
/// inputs come off the graph (ARTIFACT digests → BlobStore bytes). Pure: equal (template, inputs) → equal
/// fingerprint. The widened dims default to their v1 sentinels (R3 reserve-the-key-now: tools empty,
/// exec_platform `None`, exec_properties empty) — when analysis later populates them, values fill the
/// already-frozen frames; the layout never moves, no consumer re-encodes.
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn action_key_round_trips() {
        let key = akey("Mn", &["a", "b"], &[("p/in", b"data")], &["p/out1", "p/out2"]);
        let decoded = decode_action_key(&key.encode()).expect("a well-formed key must decode");
        // The encode is LOSSLESS (inputs inlined), so decode recovers the EXACT key — including input bytes.
        assert_eq!(decoded, key, "decode(encode(k)) == k (lossless)");
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
}
