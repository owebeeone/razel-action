    use super::testctx::MapCtx;
    use super::*;
    use crate::{ActionValue, OutputDigest};
    use razel_analysis::{ConfiguredTarget, ConfiguredTargetKey};
    use razel_bzl_api::ActionTemplate;
    use razel_core::{Digest, Error, Key, NodeKey};
    use razel_engine_api::{ComputeResult, NodeFunction};
    use razel_os_api::HostPath;
    use std::sync::Arc;

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
        ConfiguredTarget { providers: Vec::new(), actions, dep_outputs: Vec::new(), visibility: Vec::new() }
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
