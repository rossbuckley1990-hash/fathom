#![forbid(unsafe_code)]

use fathom::brief::{evaluate_ci_gate, generate_preflight_brief, GatePolicy};
use fathom::graph::{analyze_workspace, OwnershipState, WorkspaceReport};
use fathom::ledger::WorkspaceLedger;
use fathom::sample_repo::create_sample_workspace;
use fathom::scanner::truncate_clean;
use fathom::server::serve_blocking;
use fathom::simulator::{build_flight_challenge, evaluate_flight_challenge};
use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print_help();
        return ExitCode::SUCCESS;
    }
    if matches!(args[0].as_str(), "-V" | "--version" | "version") {
        println!("fathom {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    match run_cli(&args) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::from(2)
        }
    }
}

fn run_cli(args: &[String]) -> Result<ExitCode, String> {
    match args[0].as_str() {
        "scan" | "status" => cmd_scan(&args[1..]),
        "serve" => cmd_serve(&args[1..]),
        "brief" => cmd_brief(&args[1..]),
        "challenge" => cmd_challenge(&args[1..]),
        "invariant" => cmd_invariant(&args[1..]),
        "gate" | "verify" => cmd_gate(&args[1..]),
        "init-sample" => cmd_init_sample(&args[1..]),
        "demo" => cmd_demo(),
        other => Err(format!(
            "unknown subcommand '{other}'. Run `fathom --help` for usage."
        )),
    }
}

fn print_help() {
    println!(
        "\
fathom {ver} — Epistemic Sovereignty & Cognitive Debt Engine

USAGE:
    fathom <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    scan [path] [--json]
        Sound a repository's Sovereignty Index, Comprehension Coverage %, Ghost Zones,
        Stale AST Drift, and Cognitive Debt ranking.

    serve [path] [--bind 127.0.0.1:7979] [--demo]
        Launch the full interactive Fathom Web Product & live REST server.

    brief [target] [--path .] [--intent \"...\"] [--json]
        Synthesize an AI Pre-Flight Outcome Contract exposing One-Way Doors,
        upstream blast radius, and Human Reality Invariants before prompting an AI agent.

    challenge [unit_id] [--path .] [--author <handle>]
        Run an interactive 3-stage AST-grounded Causal Flight Check in the terminal
        and mint a SHA-256 hash-chained Sovereignty Receipt in `.fathom/ledger.jsonl`.

    invariant <scope> <statement> [--path .] [--author <handle>]
        Record a protected Human Reality Invariant in `.fathom/invariants.json`.

    gate [path] [--min-sovereignty 65] [--max-critical-ghosts 0] [--max-stale-drift 0] [--json]
        Verify ledger hash-chain integrity and enforce Cognitive Debt thresholds in CI.

    init-sample <dir>
        Materialize the realistic multi-language `pulsepay-core` hypergrowth workspace.

    demo
        Execute a live 4-act end-to-end verification of Ghost Zone detection, AST drift
        detection, Causal Flight anchoring, and Pre-Flight AI Outcome Contracts.
",
        ver = env!("CARGO_PKG_VERSION")
    );
}

fn cmd_scan(args: &[String]) -> Result<ExitCode, String> {
    let mut path = PathBuf::from(".");
    let mut as_json = false;
    for a in args {
        if a == "--json" {
            as_json = true;
        } else if !a.starts_with('-') {
            path = PathBuf::from(a);
        }
    }
    let report = analyze_workspace(&path).map_err(|e| e.to_string())?;
    if as_json {
        println!("{}", report.to_json().to_string_pretty());
    } else {
        print_workspace_report(&report);
    }
    Ok(ExitCode::SUCCESS)
}

fn print_workspace_report(r: &WorkspaceReport) {
    println!("┌──────────────────────────────────────────────────────────────────────────────┐");
    println!("│  FATHOM · WORKSPACE EPISTEMIC SOVEREIGNTY REPORT                             │");
    println!("└──────────────────────────────────────────────────────────────────────────────┘");
    println!("  Workspace              : {}", r.root_path);
    println!(
        "  Sovereignty Index      : {}/100  (Comprehension Coverage: {}% across {} load-bearing units)",
        r.sovereignty_index, r.comprehension_coverage_pct, r.load_bearing_units
    );
    println!(
        "  Active Ghost Zones     : {} total ({} critical) · Stale AST Drift: {} · Anchored: {}/{}",
        r.ghost_zone_count,
        r.critical_ghost_count,
        r.stale_drift_count,
        r.anchored_count,
        r.total_units
    );
    println!(
        "  Total Cognitive Debt   : {} pts · Velocity-Burst Commits: {} · Epistemic Bus Factor: {}",
        r.total_cognitive_debt, r.git_summary.burst_commit_count, r.epistemic_bus_factor
    );
    println!(
        "  Ledger Hash Chain      : {} ({} receipt(s), {} invariant(s))\n",
        if r.ledger.chain_valid {
            "INTACT ✓"
        } else {
            "TAMPERED ✗"
        },
        r.ledger.receipts.len(),
        r.ledger.invariants.len()
    );

    if r.units.is_empty() {
        println!("  (No supported production callable units found in `.rs`, `.ts`, `.js`, `.py`, `.go`.)");
        return;
    }

    println!(
        "  {:<40} {:<13} {:>6} {:>7} {:>6}  ONE-WAY DOORS",
        "CALLABLE UNIT", "STATE", "CONSEQ", "OPACITY", "DEBT"
    );
    println!("  {}", "─".repeat(94));

    for u in r.units.iter().take(14) {
        let st = match u.ownership_state {
            OwnershipState::Anchored => "ANCHORED ✓",
            OwnershipState::StaleDrift => "STALE DRIFT!",
            OwnershipState::Unverified if u.is_ghost_zone => "GHOST ZONE !",
            OwnershipState::Unverified => "unverified",
        };
        let mut sinks: Vec<&str> = Vec::new();
        for s in &u.direct_sinks {
            let lbl = s.category.label();
            if !sinks.contains(&lbl) {
                sinks.push(lbl);
            }
            if sinks.len() == 2 {
                break;
            }
        }
        let sink_str = if sinks.is_empty() {
            if u.transitive_sink_categories.is_empty() {
                "—".to_string()
            } else {
                format!("(transitive: {})", u.transitive_sink_categories[0].label())
            }
        } else {
            sinks.join(", ")
        };
        println!(
            "  {:<40} {:<13} {:>6} {:>7} {:>6}  {}",
            truncate_clean(&u.unit_id, 40),
            st,
            u.consequence_score,
            u.opacity_score,
            u.cognitive_debt,
            sink_str
        );
    }

    if let Some(first_unowned) = r
        .units
        .iter()
        .find(|u| u.ownership_state != OwnershipState::Anchored)
    {
        println!(
            "\n  Next Action -> Run `fathom challenge \"{}\"` or `fathom serve`",
            first_unowned.unit_id
        );
    }
}

fn cmd_serve(args: &[String]) -> Result<ExitCode, String> {
    let mut bind = "127.0.0.1:7979".to_string();
    let mut path = PathBuf::from(".");
    let mut use_demo = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                i += 1;
                bind = args.get(i).ok_or("missing value for --bind")?.clone();
            }
            "--demo" => {
                use_demo = true;
            }
            p if !p.starts_with('-') => {
                path = PathBuf::from(p);
            }
            other => return Err(format!("unknown option '{other}' for `fathom serve`")),
        }
        i += 1;
    }

    if use_demo {
        let demo_dir = env::temp_dir().join("fathom-pulsepay-core-demo");
        let _ = fs::remove_dir_all(&demo_dir);
        create_sample_workspace(&demo_dir).map_err(|e| e.to_string())?;
        path = demo_dir;
    }

    serve_blocking(&bind, path).map_err(|e| e.to_string())?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_brief(args: &[String]) -> Result<ExitCode, String> {
    let mut path = PathBuf::from(".");
    let mut target = "*".to_string();
    let mut intent = String::new();
    let mut as_json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--path" => {
                i += 1;
                path = PathBuf::from(args.get(i).ok_or("missing value for --path")?);
            }
            "--intent" => {
                i += 1;
                intent = args.get(i).ok_or("missing value for --intent")?.clone();
            }
            "--json" => as_json = true,
            pos if !pos.starts_with('-') => target = pos.to_string(),
            other => return Err(format!("unknown option '{other}' for `fathom brief`")),
        }
        i += 1;
    }

    let report = analyze_workspace(&path).map_err(|e| e.to_string())?;
    let brief = generate_preflight_brief(&report, &target, &intent);
    if as_json {
        println!("{}", brief.to_json().to_string_pretty());
    } else {
        print!("{}", brief.markdown);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_challenge(args: &[String]) -> Result<ExitCode, String> {
    let mut path = PathBuf::from(".");
    let mut target_id = String::new();
    let mut author = env::var("USER").unwrap_or_else(|_| "human-steward".to_string());

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--path" => {
                i += 1;
                path = PathBuf::from(args.get(i).ok_or("missing value for --path")?);
            }
            "--author" => {
                i += 1;
                author = args.get(i).ok_or("missing value for --author")?.clone();
            }
            pos if !pos.starts_with('-') => target_id = pos.to_string(),
            other => return Err(format!("unknown option '{other}' for `fathom challenge`")),
        }
        i += 1;
    }

    let report = analyze_workspace(&path).map_err(|e| e.to_string())?;
    let unit = if target_id.is_empty() {
        report
            .units
            .iter()
            .find(|u| u.ownership_state != OwnershipState::Anchored)
            .or_else(|| report.units.first())
            .ok_or("no callable units found in workspace")?
    } else {
        report
            .find_unit(&target_id)
            .ok_or_else(|| format!("callable unit '{target_id}' not found"))?
    };

    let ch = build_flight_challenge(&path, &report, unit);
    println!("══════════════════════════════════════════════════════════════════════════════");
    println!(
        "  CAUSAL FLIGHT SIMULATOR · {} (Consequence {}/100, Debt {})",
        ch.unit_id, ch.consequence_score, ch.cognitive_debt
    );
    println!("  Structural SHA-256: {}", ch.structural_hash);
    println!("══════════════════════════════════════════════════════════════════════════════\n");
    println!("{}", ch.source_excerpt);

    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut answers = Vec::with_capacity(ch.questions.len());

    for q in &ch.questions {
        println!("── Stage {} · {} ──", q.index + 1, q.dimension);
        println!("  {}\n", q.prompt);
        for (oi, opt) in q.options.iter().enumerate() {
            println!("    [{}] {}", oi + 1, opt);
        }
        print!("\n  Select [1-{}]: ", q.options.len());
        let _ = io::stdout().flush();
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;
        let picked = line
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|&v| v >= 1 && v <= q.options.len())
            .ok_or("invalid choice")?
            - 1;
        answers.push(picked);
        println!();
    }

    print!("  Optional 1-sentence Human Reality Invariant (Enter to skip): ");
    let _ = io::stdout().flush();
    let mut inv_note = String::new();
    reader.read_line(&mut inv_note).map_err(|e| e.to_string())?;

    let eval = evaluate_flight_challenge(
        &path,
        &report,
        &ch.unit_id,
        &answers,
        &author,
        inv_note.trim(),
    )
    .map_err(|e| e.to_string())?;

    for v in &eval.verdicts {
        println!(
            "  Stage {}: {} — {}",
            v.index + 1,
            if v.is_correct { "PASS ✓" } else { "MISS ✗" },
            v.explanation
        );
    }

    if let Some(rcpt) = eval.receipt {
        println!(
            "\n  ✓ ANCHORED! Minted hash-chained Sovereignty Receipt `{}` (`{}`)",
            rcpt.receipt_id,
            &rcpt.entry_hash[..16]
        );
        Ok(ExitCode::SUCCESS)
    } else {
        println!(
            "\n  ✗ Score {}% — 100% causal lock required to mint a Sovereignty Receipt.",
            eval.score_pct
        );
        Ok(ExitCode::from(1))
    }
}

fn cmd_invariant(args: &[String]) -> Result<ExitCode, String> {
    let mut path = PathBuf::from(".");
    let mut author = env::var("USER").unwrap_or_else(|_| "human-steward".to_string());
    let mut positional = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--path" => {
                i += 1;
                path = PathBuf::from(args.get(i).ok_or("missing value for --path")?);
            }
            "--author" => {
                i += 1;
                author = args.get(i).ok_or("missing value for --author")?.clone();
            }
            pos if !pos.starts_with('-') => positional.push(pos.to_string()),
            other => return Err(format!("unknown option '{other}' for `fathom invariant`")),
        }
        i += 1;
    }

    if positional.len() < 2 {
        return Err(
            "usage: fathom invariant <scope> \"<statement>\" [--path .] [--author <handle>]"
                .to_string(),
        );
    }
    let scope = &positional[0];
    let statement = positional[1..].join(" ");
    let inv = WorkspaceLedger::add_invariant(&path, scope, &statement, &author)
        .map_err(|e| e.to_string())?;
    println!(
        "✓ Recorded Human Reality Invariant `{}` on `{}`: {}",
        inv.id, inv.scope, inv.statement
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_gate(args: &[String]) -> Result<ExitCode, String> {
    let mut path = PathBuf::from(".");
    let mut policy = GatePolicy::default();
    let mut as_json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--min-sovereignty" => {
                i += 1;
                policy.min_sovereignty = args
                    .get(i)
                    .ok_or("missing value for --min-sovereignty")?
                    .parse::<u32>()
                    .map_err(|_| "invalid integer for --min-sovereignty")?;
            }
            "--max-critical-ghosts" => {
                i += 1;
                policy.max_critical_ghosts = args
                    .get(i)
                    .ok_or("missing value for --max-critical-ghosts")?
                    .parse::<usize>()
                    .map_err(|_| "invalid integer for --max-critical-ghosts")?;
            }
            "--max-stale-drift" => {
                i += 1;
                policy.max_stale_drift = args
                    .get(i)
                    .ok_or("missing value for --max-stale-drift")?
                    .parse::<usize>()
                    .map_err(|_| "invalid integer for --max-stale-drift")?;
            }
            "--json" => as_json = true,
            pos if !pos.starts_with('-') => path = PathBuf::from(pos),
            other => return Err(format!("unknown option '{other}' for `fathom gate`")),
        }
        i += 1;
    }

    let report = analyze_workspace(&path).map_err(|e| e.to_string())?;
    let gate = evaluate_ci_gate(&report, policy);

    if as_json {
        println!("{}", gate.to_json().to_string_pretty());
    } else if gate.passed {
        println!(
            "✓ FATHOM CI GATE PASSED — Sovereignty {}/100 (min {}), Critical Ghosts {} (max {}), Stale Drift {} (max {})",
            report.sovereignty_index,
            policy.min_sovereignty,
            report.critical_ghost_count,
            policy.max_critical_ghosts,
            report.stale_drift_count,
            policy.max_stale_drift
        );
    } else {
        println!("✗ FATHOM CI GATE BLOCKED:");
        for v in &gate.violations {
            println!("  • {v}");
        }
        if !gate.remediation_targets.is_empty() {
            println!(
                "  Remediate via `fathom serve` or `fathom challenge \"{}\"`",
                gate.remediation_targets[0]
            );
        }
    }

    Ok(if gate.passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn cmd_init_sample(args: &[String]) -> Result<ExitCode, String> {
    let dest = args
        .first()
        .map(PathBuf::from)
        .ok_or("usage: fathom init-sample <dest_dir>")?;
    create_sample_workspace(&dest).map_err(|e| e.to_string())?;
    println!(
        "✓ Initialized sample hypergrowth repository at {}",
        dest.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_demo() -> Result<ExitCode, String> {
    let demo_dir = env::temp_dir().join(format!("fathom-demo-{}", std::process::id()));
    let _ = fs::remove_dir_all(&demo_dir);
    create_sample_workspace(&demo_dir).map_err(|e| e.to_string())?;

    println!("══════════════════════════════════════════════════════════════════════════════");
    println!("  FATHOM · 4-ACT LIVE OUTCOME DEMONSTRATION (`pulsepay-core`)");
    println!("══════════════════════════════════════════════════════════════════════════════\n");

    // ACT 1
    let r1 = analyze_workspace(&demo_dir).map_err(|e| e.to_string())?;
    let g1 = evaluate_ci_gate(&r1, GatePolicy::default());
    println!("ACT 1 · Detecting Silent Cognitive Debt After an AI Velocity Burst");
    println!(
        "  Initial Sovereignty Index : {}/100 ({} Ghost Zones, {} Stale AST Drift)",
        r1.sovereignty_index, r1.ghost_zone_count, r1.stale_drift_count
    );
    println!(
        "  CI Gate Verdict           : {} ({})",
        if g1.passed { "PASSED" } else { "BLOCKED ✗" },
        g1.violations.join(" | ")
    );

    // ACT 2: Anchor unowned & drifted critical units via deterministic Flight Checks
    println!("\nACT 2 · Re-Anchoring Human Causal Ownership via AST Flight Simulator");
    anchor_all_unowned(&demo_dir, &r1)?;
    let r2 = analyze_workspace(&demo_dir).map_err(|e| e.to_string())?;
    let g2 = evaluate_ci_gate(&r2, GatePolicy::default());
    println!(
        "  Post-Flight Sovereignty   : {}/100 ({} Ghost Zones, {} Stale Drift, {} Hash-Chained Receipts)",
        r2.sovereignty_index,
        r2.ghost_zone_count,
        r2.stale_drift_count,
        r2.ledger.receipts.len()
    );
    println!(
        "  CI Gate Verdict           : {}",
        if g2.passed { "PASSED ✓" } else { "BLOCKED" }
    );

    // ACT 3: Prove comment/whitespace invariance vs real AST mutation sensitivity
    println!("\nACT 3 · Whitespace/Comment Invariance vs. Real Logic Mutation Detection");
    let auth_file = demo_dir.join("src/auth.rs");
    let orig_auth = fs::read_to_string(&auth_file).map_err(|e| e.to_string())?;
    fs::write(
        &auth_file,
        format!("// Formatting & doc comment pass\n\n{orig_auth}\n// trailing note\n"),
    )
    .map_err(|e| e.to_string())?;
    let r_comment = analyze_workspace(&demo_dir).map_err(|e| e.to_string())?;
    println!(
        "  After comment/whitespace edit -> Stale Drift count: {} (Receipts stay ANCHORED ✓)",
        r_comment.stale_drift_count
    );

    let mutated_auth = orig_auth.replace("payload.len() > 2_097_152", "payload.len() > 8_388_608");
    fs::write(&auth_file, mutated_auth).map_err(|e| e.to_string())?;
    let r_mutated = analyze_workspace(&demo_dir).map_err(|e| e.to_string())?;
    println!(
        "  After 1 constant/branch edit  -> Stale Drift count: {} (`verify_webhook_hmac` flagged STALE_DRIFT ⚠)",
        r_mutated.stale_drift_count
    );

    // ACT 4: Synthesize Pre-Flight AI Outcome Contract
    println!("\nACT 4 · AI Pre-Flight Outcome Contract (`fathom brief`)");
    let brief = generate_preflight_brief(
        &r_mutated,
        "src/billing.rs",
        "Add partial proration refunds with exponential retry backoff",
    );
    println!(
        "  Scoped Units: {} | One-Way Doors Surfaced: {} | Protected Human Invariants: {}",
        brief.scoped_units.len(),
        brief.one_way_doors.len(),
        brief.protected_invariants.len()
    );
    println!("\n  Launch the full interactive product anytime with:\n    cargo run --release -- serve --demo\n");

    let _ = fs::remove_dir_all(&demo_dir);
    Ok(ExitCode::SUCCESS)
}

fn anchor_all_unowned(root: &Path, report: &WorkspaceReport) -> Result<(), String> {
    for u in &report.units {
        if u.ownership_state != OwnershipState::Anchored {
            let ch = build_flight_challenge(root, report, u);
            let correct_answers: Vec<usize> =
                ch.questions.iter().map(|q| q.correct_index).collect();
            let note = format!(
                "Verified causal path & One-Way-Door boundaries for `{}`.",
                u.name
            );
            evaluate_flight_challenge(root, report, &u.unit_id, &correct_answers, "ross", &note)
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
