//! Materializes a realistic multi-language hypergrowth codebase (`pulsepay-core`)
//! for `fathom init-sample` and `fathom demo`, complete with Git commit bursts,
//! cross-file call chains, an `ANCHORED` receipt, and a live `STALE_DRIFT` mutation.

use crate::ledger::WorkspaceLedger;
use crate::scanner::{compute_structural_hash, Language};
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;

pub fn create_sample_workspace(dest: &Path) -> io::Result<()> {
    fs::create_dir_all(dest.join("src"))?;
    fs::create_dir_all(dest.join("workers"))?;

    let auth_v1 = r#"//! Token verification and RBAC enforcement for PulsePay API endpoints.

pub fn verify_webhook_hmac(payload: &[u8], signature_hdr: &str, secret: &[u8]) -> Result<(), &'static str> {
    if signature_hdr.is_empty() || secret.is_empty() {
        return Err("missing webhook HMAC signature or secret");
    }
    if payload.len() > 2_097_152 {
        return Err("webhook payload exceeds 2MB safety ceiling");
    }
    let expected_prefix = "whsec_v1=";
    if !signature_hdr.starts_with(expected_prefix) {
        return Err("unsupported webhook signature version");
    }
    Ok(())
}

pub fn authorize_tenant_scope(actor_role: &str, tenant_locked: bool) -> Result<(), &'static str> {
    if tenant_locked {
        return Err("tenant ledger is frozen during compliance audit");
    }
    if actor_role != "owner" && actor_role != "billing_admin" {
        return Err("insufficient RBAC permission for ledger mutation");
    }
    Ok(())
}
"#;

    let ledger_db = r#"//! Transactional ledger persistence and idempotency lock store.

pub fn acquire_idempotency_lock(event_id: &str, mutex_busy: bool) -> Result<String, &'static str> {
    if mutex_busy {
        return Err("concurrent worker already holds mutex lock for event");
    }
    if event_id.len() < 6 {
        return Err("malformed idempotency key");
    }
    Ok(format!("LOCK::{}", event_id))
}

pub fn commit_ledger_settlement(tenant_id: &str, amount_cents: i64, idempotency_key: &str) -> Result<String, &'static str> {
    if amount_cents == 0 {
        return Ok("NOOP_ZERO_AMOUNT".to_string());
    }
    if amount_cents < -500_000_00 {
        return Err("refund exceeds single-transaction safety cap");
    }
    let sql = format!(
        "INSERT INTO ledger_entries (tenant_id, amount_cents, idem_key) VALUES ('{}', {}, '{}')",
        tenant_id, amount_cents, idempotency_key
    );
    Ok(sql)
}
"#;

    // Initial v1 of billing.rs BEFORE the AI burst hotfix mutates `process_stripe_webhook`!
    let billing_v1 = r#"//! Core Stripe settlement & subscription downgrade state machine.

use crate::auth::{authorize_tenant_scope, verify_webhook_hmac};
use crate::ledger_db::{acquire_idempotency_lock, commit_ledger_settlement};

pub fn process_stripe_webhook(
    payload: &[u8],
    sig: &str,
    secret: &[u8],
    event_id: &str,
    tenant_id: &str,
    amount_cents: i64,
) -> Result<String, &'static str> {
    verify_webhook_hmac(payload, sig, secret)?;
    let lock_token = acquire_idempotency_lock(event_id, false)?;
    if amount_cents < 0 {
        return Err("negative webhook settlement rejected in v1");
    }
    let tx = commit_ledger_settlement(tenant_id, amount_cents, &lock_token)?;
    Ok(tx)
}
"#;

    let billing_v2_ai_burst = r#"//! Core Stripe settlement & subscription downgrade state machine.

use crate::auth::{authorize_tenant_scope, verify_webhook_hmac};
use crate::ledger_db::{acquire_idempotency_lock, commit_ledger_settlement};

pub fn process_stripe_webhook(
    payload: &[u8],
    sig: &str,
    secret: &[u8],
    event_id: &str,
    tenant_id: &str,
    amount_cents: i64,
    allow_auto_refund: bool,
) -> Result<String, &'static str> {
    verify_webhook_hmac(payload, sig, secret)?;
    let lock_token = acquire_idempotency_lock(event_id, false)?;
    if amount_cents < 0 && !allow_auto_refund {
        return Err("auto-refund disabled for unverified webhook stream");
    }
    if amount_cents > 10_000_00 && sig.contains("test_mode") {
        return Err("high-value settlement blocked on test_mode signature");
    }
    let tx = commit_ledger_settlement(tenant_id, amount_cents, &lock_token)?;
    Ok(tx)
}

pub fn execute_plan_downgrade(
    actor_role: &str,
    tenant_locked: bool,
    tenant_id: &str,
    unused_days: i64,
    daily_rate_cents: i64,
    stripe_live_endpoint: &str,
) -> Result<String, &'static str> {
    authorize_tenant_scope(actor_role, tenant_locked)?;
    if unused_days <= 0 || daily_rate_cents <= 0 {
        return Ok("NO_PRORATION_REFUND_DUE".to_string());
    }
    let credit_cents = -(unused_days * daily_rate_cents);
    if !stripe_live_endpoint.starts_with("https://") {
        return Err("refusing to dispatch Stripe refund over non-TLS endpoint");
    }
    let idem = format!("downgrade:{}:{}", tenant_id, unused_days);
    commit_ledger_settlement(tenant_id, credit_cents, &idem)
}
"#;

    let reconcile_py = r#"def reconcile_nightly_payouts(batch_rows, bank_feed_ready, max_drift_cents):
    if not bank_feed_ready:
        raise RuntimeError("bank settlement feed not yet finalized for UTC cutoff")
    total_ledger_cents = 0
    unmatched = 0
    for row in batch_rows:
        if row.get("voided"):
            continue
        total_ledger_cents += row.get("amount_cents", 0)
        if not row.get("bank_settled"):
            unmatched += 1
    if abs(total_ledger_cents) > max_drift_cents and unmatched > 0:
        return "HALT_PAYOUT_DRIFT_EXCEEDED"
    return f"SETTLED:{total_ledger_cents}:UNMATCHED:{unmatched}"
"#;

    fs::write(dest.join("src/auth.rs"), auth_v1)?;
    fs::write(dest.join("src/ledger_db.rs"), ledger_db)?;
    fs::write(dest.join("src/billing.rs"), billing_v1)?;

    // Anchor TWO functions at v1:
    // 1. `src/auth.rs::verify_webhook_hmac` (stays untouched -> remains `ANCHORED`!)
    // 2. `src/billing.rs::process_stripe_webhook` (about to be rewritten by AI burst -> becomes `STALE_DRIFT`!)
    let auth_fn_slice = extract_fn_text(auth_v1, "pub fn verify_webhook_hmac");
    let auth_hash = compute_structural_hash(auth_fn_slice, Language::Rust);
    WorkspaceLedger::append_receipt(
        dest,
        "src/auth.rs::verify_webhook_hmac",
        &auth_hash,
        "maya.chen",
        100,
        "Webhook signatures must enforce the 2MB ceiling before HMAC comparison and reject non-v1 prefixes.",
    )?;

    let v1_webhook_slice = extract_fn_text(billing_v1, "pub fn process_stripe_webhook");
    let v1_webhook_hash = compute_structural_hash(v1_webhook_slice, Language::Rust);
    WorkspaceLedger::append_receipt(
        dest,
        "src/billing.rs::process_stripe_webhook",
        &v1_webhook_hash,
        "maya.chen",
        100,
        "Stripe delivers webhook retries for up to 72 hours; idempotency lock MUST precede ledger settlement.",
    )?;

    // Commit 1 (human baseline) if `git` is available
    init_git_commits(dest, billing_v2_ai_burst, reconcile_py)?;

    Ok(())
}

fn extract_fn_text<'a>(file_src: &'a str, needle: &str) -> &'a str {
    let start = file_src.find(needle).unwrap_or(0);
    let sub = &file_src[start..];
    let mut depth = 0i32;
    let mut opened = false;
    for (idx, ch) in sub.char_indices() {
        if ch == '{' {
            depth += 1;
            opened = true;
        } else if ch == '}' && opened {
            depth -= 1;
            if depth == 0 {
                return &sub[..=idx];
            }
        }
    }
    sub
}

fn init_git_commits(dest: &Path, billing_v2: &str, reconcile_py: &str) -> io::Result<()> {
    let _ = Command::new("git")
        .arg("init")
        .arg("-b")
        .arg("main")
        .current_dir(dest)
        .output();
    let _ = Command::new("git")
        .args(["config", "user.name", "Maya Chen"])
        .current_dir(dest)
        .output();
    let _ = Command::new("git")
        .args(["config", "user.email", "maya@pulsepay.example"])
        .current_dir(dest)
        .output();
    let _ = Command::new("git")
        .args(["add", "-A"])
        .current_dir(dest)
        .output();
    let _ = Command::new("git")
        .args([
            "commit",
            "-m",
            "feat: initial human-verified webhook & auth core",
        ])
        .current_dir(dest)
        .output();

    // Now apply the fast AI-generated burst commit that mutates `process_stripe_webhook` AND adds new unverified Ghost Zones!
    fs::write(dest.join("src/billing.rs"), billing_v2)?;
    fs::write(dest.join("workers/reconcile.py"), reconcile_py)?;

    let _ = Command::new("git")
        .args(["config", "user.name", "AutoAgent Bot"])
        .current_dir(dest)
        .output();
    let _ = Command::new("git")
        .args(["add", "-A"])
        .current_dir(dest)
        .output();
    let _ = Command::new("git")
        .args([
            "commit",
            "-m",
            "ai: generated auto-refund proration downgrade & nightly bank reconciliation",
        ])
        .current_dir(dest)
        .output();

    Ok(())
}
