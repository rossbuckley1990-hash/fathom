use fathom::graph::{analyze_workspace, OwnershipState};
use fathom::ledger::WorkspaceLedger;
use fathom::scanner::{compute_structural_hash, Language, SinkCategory};
use std::fs;
use std::path::PathBuf;

fn temp_workspace(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "fathom-test-{tag}-{}-{}",
        std::process::id(),
        fathom::crypto::now_unix_secs()
    ));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn structural_hash_ignores_comments_and_formatting_while_catching_logic_edits() {
    let v1 = r#"
pub fn settle_payout(amount_cents: i64, locked: bool) -> Result<i64, &'static str> {
    if locked {
        return Err("locked");
    }
    if amount_cents <= 0 {
        return Ok(0);
    }
    Ok(amount_cents)
}
"#;

    let v1_reformatted_with_comments = r#"
// Extensive architectural commentary added during code review
/* Multi-line block comment with { braces } and if (fake_guard) */
pub fn settle_payout(
    amount_cents: i64,
    locked: bool
) -> Result<i64, &'static str>
{
    // Check lock state first
    if locked { return Err("locked"); }

    if amount_cents <= 0 {
        return Ok(0);
    }

    Ok(amount_cents)
}
"#;

    let v2_operator_mutated = r#"
pub fn settle_payout(amount_cents: i64, locked: bool) -> Result<i64, &'static str> {
    if locked {
        return Err("locked");
    }
    if amount_cents < 0 {
        return Ok(0);
    }
    Ok(amount_cents)
}
"#;

    let h1 = compute_structural_hash(v1, Language::Rust);
    let h1_fmt = compute_structural_hash(v1_reformatted_with_comments, Language::Rust);
    let h2 = compute_structural_hash(v2_operator_mutated, Language::Rust);

    assert_eq!(
        h1, h1_fmt,
        "formatting and comments must never invalidate a human's Sovereignty Receipt"
    );
    assert_ne!(
        h1, h2,
        "changing `<=` to `<` must immediately mutate structural_hash"
    );
}

#[test]
fn detects_stale_ast_drift_when_code_mutates_underneath_anchored_receipt() {
    let dir = temp_workspace("drift");
    fs::create_dir_all(dir.join("src")).unwrap();

    let src_v1 = r#"
pub fn charge_invoice(amount_cents: i64, retry_count: u32) -> Result<i64, &'static str> {
    if retry_count > 3 {
        return Err("max retries exceeded");
    }
    if amount_cents <= 0 {
        return Err("invalid invoice amount");
    }
    Ok(amount_cents)
}
"#;
    fs::write(dir.join("src/pay.rs"), src_v1).unwrap();

    let r1 = analyze_workspace(&dir).unwrap();
    let unit = r1.find_unit("src/pay.rs::charge_invoice").unwrap();
    assert_eq!(unit.ownership_state, OwnershipState::Unverified);

    WorkspaceLedger::append_receipt(
        &dir,
        &unit.unit_id,
        &unit.structural_hash,
        "maya",
        100,
        "Never charge zero or negative cents.",
    )
    .unwrap();

    let r2 = analyze_workspace(&dir).unwrap();
    let unit2 = r2.find_unit("src/pay.rs::charge_invoice").unwrap();
    assert_eq!(unit2.ownership_state, OwnershipState::Anchored);
    assert_eq!(r2.sovereignty_index, 100);
    assert_eq!(r2.stale_drift_count, 0);

    // Add comments only -> STILL Anchored!
    fs::write(
        dir.join("src/pay.rs"),
        format!("// top comment\n{src_v1}\n// bottom comment\n"),
    )
    .unwrap();
    let r3 = analyze_workspace(&dir).unwrap();
    assert_eq!(r3.stale_drift_count, 0);
    assert_eq!(r3.sovereignty_index, 100);

    // Mutate retry cap `> 3` -> `> 10` -> IMMEDIATELY StaleDrift!
    let src_v2 = src_v1.replace("retry_count > 3", "retry_count > 10");
    fs::write(dir.join("src/pay.rs"), src_v2).unwrap();
    let r4 = analyze_workspace(&dir).unwrap();
    let unit4 = r4.find_unit("src/pay.rs::charge_invoice").unwrap();
    assert_eq!(unit4.ownership_state, OwnershipState::StaleDrift);
    assert_eq!(r4.stale_drift_count, 1);
    assert!(r4.sovereignty_index < 50);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn resolves_multilang_units_and_propagates_transitive_consequences_up_call_graph() {
    let dir = temp_workspace("multilang");
    fs::create_dir_all(dir.join("src")).unwrap();

    // Rust chain: api_entrypoint -> orchestrate_adjustment -> persist_refund_row (Persistence + Financial)
    let rust_code = r#"
pub fn api_entrypoint(user_ok: bool, cents: i64) -> Result<String, &'static str> {
    if !user_ok {
        return Err("unauthorized");
    }
    orchestrate_adjustment(cents)
}

pub fn orchestrate_adjustment(cents: i64) -> Result<String, &'static str> {
    if cents <= 0 {
        return Err("must be positive");
    }
    persist_refund_row(cents)
}

pub fn persist_refund_row(amount_cents: i64) -> Result<String, &'static str> {
    if amount_cents > 1_000_000 {
        return Err("cap");
    }
    let q = "INSERT INTO refunds (cents) VALUES (100)";
    Ok(q.to_string())
}
"#;

    let ts_code = r#"
export async function dispatchWebhookEvent(url: string, secret: string): Promise<boolean> {
    if (!url.startsWith("https://")) {
        throw new Error("TLS required");
    }
    const resp = await fetch(url);
    return resp.ok;
}
"#;

    let py_code = r#"
def verify_jwt_claims(token_str, expected_aud):
    """Docstring ignored by structural hash."""
    if not token_str:
        raise ValueError("empty jwt")
    if expected_aud != "prod":
        return False
    return True
"#;

    let go_code = r#"
package worker

import "os/exec"

func RunBackupCommand(bin string) error {
    if bin == "" {
        return nil
    }
    cmd := exec.Command(bin)
    return cmd.Run()
}
"#;

    fs::write(dir.join("src/flow.rs"), rust_code).unwrap();
    fs::write(dir.join("src/hook.ts"), ts_code).unwrap();
    fs::write(dir.join("src/claims.py"), py_code).unwrap();
    fs::write(dir.join("src/runner.go"), go_code).unwrap();

    let report = analyze_workspace(&dir).unwrap();
    assert_eq!(report.total_units, 6);

    let entry = report.find_unit("src/flow.rs::api_entrypoint").unwrap();
    assert!(
        entry.direct_sinks.is_empty(),
        "api_entrypoint has no local I/O lines"
    );
    assert!(
        entry
            .transitive_sink_categories
            .contains(&SinkCategory::Persistence),
        "transitive Persistence sink must propagate 2 hops up to api_entrypoint"
    );
    assert!(
        entry
            .transitive_sink_categories
            .contains(&SinkCategory::Financial),
        "transitive Financial sink must propagate 2 hops up to api_entrypoint"
    );

    let leaf = report.find_unit("src/flow.rs::persist_refund_row").unwrap();
    assert_eq!(leaf.transitive_caller_count, 2);

    assert!(report
        .find_unit("src/hook.ts::dispatchWebhookEvent")
        .is_some());
    assert!(report
        .find_unit("src/claims.py::verify_jwt_claims")
        .is_some());
    assert!(report
        .find_unit("src/runner.go::RunBackupCommand")
        .is_some());

    let _ = fs::remove_dir_all(&dir);
}
