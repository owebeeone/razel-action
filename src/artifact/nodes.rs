//! The three artifact-model node functions: the shared pure `derived_outputs`, the `ARTIFACT`
//! identity projection (`ArtifactFn`), and `TARGET_COMPLETION` (`TargetCompletionFn`) — carved out
//! of `artifact.rs`.

use super::*;
use razel_analysis::{ConfiguredTarget, ConfiguredTargetKey};
use razel_core::{Digest, Error, NodeKey};
use std::collections::HashMap;
use razel_engine_api::{ComputeResult, Demand, DemandContext, NodeFunction};
use razel_ids::RootRelativePath;
use razel_os_api::{HostPath, System};
use razel_source::{resolve_source_path, ExternalRepos, FileKey, FileValue};
use std::sync::Arc;
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
    repos: ExternalRepos,
}
impl ArtifactFn {
    pub fn new(blobs: Arc<dyn BlobStore>, sys: Arc<dyn System>, root: HostPath) -> Self {
        Self::new_with_repos(blobs, sys, root, ExternalRepos::empty())
    }
    pub fn new_with_repos(blobs: Arc<dyn BlobStore>, sys: Arc<dyn System>, root: HostPath, repos: ExternalRepos) -> Self {
        Self { blobs, sys, root, repos }
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
                // FILE-PATH resolution (D1 exec side): an `external/<repo>/…` source reads from the repo's
                // registry root; a workspace source reads from the workspace root — the uniform choke point.
                let host = match resolve_source_path(&self.root, &self.repos, &rel) {
                    Ok(h) => h,
                    Err(e) => return ComputeResult::Error(e),
                };
                let bytes = match self.sys.read(&host) {
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
