use fathom::brief::{evaluate_ci_gate, generate_preflight_brief, GatePolicy};
use fathom::graph::analyze_workspace;
use fathom::ledger::WorkspaceLedger;
use fathom::sample_repo::create_sample_workspace;
use fathom::simulator::{build_flight_challenge, evaluate_flight_challenge};
use std::fs;
use std::path::PathBuf;

fn sample_dir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "fathom-sim-{tag}-{}-{}",
        std::process::id(),
        fathom::crypto::now_unix_secs()
    ));
    let _ = fs::remove_dir_all(&p);
    create_sample_workspace(&p).unwrap();
    p
}

#[test]
fn flight_simulator_mints_chained_receipts_and_lifts_ci_gate_to_green() {
    let dir = sample_dir("gate");
    let initial = analyze_workspace(&dir).unwrap();
    assert_eq!(
        initial.stale_drift_count, 1,
        "pulsepay-core starts with 1 AI-mutated Stale Drift function"
    );
    assert!(initial.ghost_zone_count >= 4);

    let initial_gate = evaluate_ci_gate(&initial, GatePolicy::default());
    assert!(!initial_gate.passed);

    // Wrong answer attempt must NOT mint a Sovereignty Receipt
    let target = initial
        .find_unit("src/billing.rs::process_stripe_webhook")
        .unwrap();
    let ch = build_flight_challenge(&dir, &initial, target);
    let wrong_answers: Vec<usize> = ch
        .questions
        .iter()
        .map(|q| (q.correct_index + 1) % q.options.len())
        .collect();
    let failed_eval = evaluate_flight_challenge(
        &dir,
        &initial,
        &target.unit_id,
        &wrong_answers,
        "ross",
        "Should not save on miss",
    )
    .unwrap();
    assert!(!failed_eval.passed);
    assert!(failed_eval.receipt.is_none());

    // Now pass all unowned & drifted units with 100% causal verification
    for u in &initial.units {
        let c = build_flight_challenge(&dir, &initial, u);
        let right: Vec<usize> = c.questions.iter().map(|q| q.correct_index).collect();
        let ev = evaluate_flight_challenge(
            &dir,
            &initial,
            &u.unit_id,
            &right,
            "ross",
            "Never release idempotency lock before settlement commits.",
        )
        .unwrap();
        assert!(ev.passed);
        assert!(ev.receipt.is_some());
    }

    let after = analyze_workspace(&dir).unwrap();
    assert_eq!(after.sovereignty_index, 100);
    assert_eq!(after.ghost_zone_count, 0);
    assert_eq!(after.stale_drift_count, 0);
    assert!(after.ledger.chain_valid);

    let after_gate = evaluate_ci_gate(&after, GatePolicy::default());
    assert!(
        after_gate.passed,
        "CI gate must pass at 100/100 sovereignty"
    );

    // Pre-Flight Brief must include the human reality invariants anchored above!
    let brief = generate_preflight_brief(
        &after,
        "src/billing.rs::process_stripe_webhook",
        "Add multi-currency support",
    );
    assert!(brief
        .markdown
        .contains("Never release idempotency lock before settlement commits."));
    assert!(!brief.one_way_doors.is_empty());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn detects_ledger_hash_chain_tampering() {
    let dir = sample_dir("tamper");
    let ledger_file = WorkspaceLedger::ledger_path(&dir);
    let raw = fs::read_to_string(&ledger_file).unwrap();
    let tampered = raw.replace("maya.chen", "forged.actor");
    fs::write(&ledger_file, tampered).unwrap();

    let report = analyze_workspace(&dir).unwrap();
    assert!(
        !report.ledger.chain_valid,
        "forged author in ledger.jsonl must break SHA-256 entry_hash verification"
    );

    let gate = evaluate_ci_gate(
        &report,
        GatePolicy {
            min_sovereignty: 0,
            max_critical_ghosts: 99,
            max_stale_drift: 99,
        },
    );
    assert!(
        !gate.passed,
        "tampered ledger chain must always fail CI gate regardless of numeric thresholds"
    );

    let _ = fs::remove_dir_all(&dir);
}
