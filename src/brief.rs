//! Pre-Flight Outcome Contract generator (`fathom brief`) and CI Sovereignty Gate (`fathom gate`).
//!
//! Why `fathom brief` matters to AI tools:
//! Models like Gemini can only protect invariants that are legible in context.
//! Before an AI agent edits a subsystem, `fathom brief` extracts every load-bearing caller,
//! One-Way-Door sink, Ghost Zone warning, and recorded Human Reality Invariant into a
//! deterministic contract so fast tool execution doesn't destroy unstated truth.

use crate::graph::{AnalyzedUnit, OwnershipState, WorkspaceReport};
use crate::json::Json;
use crate::ledger::HumanInvariant;
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct PreFlightBrief {
    pub target: String,
    pub intent: String,
    pub scoped_units: Vec<String>,
    pub upstream_blast_radius: Vec<String>,
    pub one_way_doors: Vec<String>,
    pub protected_invariants: Vec<HumanInvariant>,
    pub ghost_warnings: Vec<String>,
    pub markdown: String,
}

impl PreFlightBrief {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("target", Json::Str(self.target.clone())),
            ("intent", Json::Str(self.intent.clone())),
            (
                "scoped_units",
                Json::Array(self.scoped_units.iter().cloned().map(Json::Str).collect()),
            ),
            (
                "upstream_blast_radius",
                Json::Array(
                    self.upstream_blast_radius
                        .iter()
                        .cloned()
                        .map(Json::Str)
                        .collect(),
                ),
            ),
            (
                "one_way_doors",
                Json::Array(self.one_way_doors.iter().cloned().map(Json::Str).collect()),
            ),
            (
                "protected_invariants",
                Json::Array(
                    self.protected_invariants
                        .iter()
                        .map(HumanInvariant::to_json)
                        .collect(),
                ),
            ),
            (
                "ghost_warnings",
                Json::Array(self.ghost_warnings.iter().cloned().map(Json::Str).collect()),
            ),
            ("markdown", Json::Str(self.markdown.clone())),
        ])
    }
}

pub fn generate_preflight_brief(
    report: &WorkspaceReport,
    target_query: &str,
    intent: &str,
) -> PreFlightBrief {
    let q = target_query.trim();
    let matched: Vec<&AnalyzedUnit> = if q.is_empty() || q == "*" || q == "." {
        report.units.iter().take(6).collect()
    } else {
        let hits: Vec<&AnalyzedUnit> = report
            .units
            .iter()
            .filter(|u| {
                u.unit_id == q
                    || u.name == q
                    || u.file_path == q
                    || u.unit_id.contains(q)
                    || u.file_path.contains(q)
            })
            .collect();
        if hits.is_empty() {
            report.units.iter().take(4).collect()
        } else {
            hits
        }
    };

    let scoped_units: Vec<String> = matched.iter().map(|u| u.unit_id.clone()).collect();
    let mut callers_set = BTreeSet::new();
    let mut doors = Vec::new();
    let mut inv_map = BTreeSet::new();
    let mut protected_invariants = Vec::new();
    let mut ghost_warnings = Vec::new();

    // Include global `*` invariants as well
    for inv in &report.ledger.invariants {
        if inv.scope == "*" && inv_map.insert(inv.id.clone()) {
            protected_invariants.push(inv.clone());
        }
    }

    for u in &matched {
        for caller in &u.callers {
            if !scoped_units.contains(caller) {
                callers_set.insert(caller.clone());
            }
        }
        for s in &u.direct_sinks {
            doors.push(format!(
                "[{}] {}:L{} — `{}`",
                s.category.label(),
                u.file_path,
                s.line,
                s.snippet
            ));
        }
        for inv in &u.invariants {
            if inv_map.insert(inv.id.clone()) {
                protected_invariants.push(inv.clone());
            }
        }
        match u.ownership_state {
            OwnershipState::StaleDrift => {
                ghost_warnings.push(format!(
                    "STALE_DRIFT on `{}` (Consequence {}/100): AST mutated since last human sign-off (`{}`). Surface every branch/state change explicitly.",
                    u.unit_id,
                    u.consequence_score,
                    u.latest_receipt
                        .as_ref()
                        .map(|r| r.author.as_str())
                        .unwrap_or("unknown")
                ));
            }
            OwnershipState::Unverified if u.is_ghost_zone => {
                ghost_warnings.push(format!(
                    "GHOST_ZONE on `{}` (Cognitive Debt {}, Consequence {}/100): zero verified human causal receipt on record. Do NOT expand side-effect blast radius silently.",
                    u.unit_id, u.cognitive_debt, u.consequence_score
                ));
            }
            _ => {}
        }
    }

    let upstream_blast_radius: Vec<String> = callers_set.into_iter().collect();
    let clean_intent = if intent.trim().is_empty() {
        "Modify target scope safely without violating load-bearing invariants or expanding unowned Cognitive Debt."
    } else {
        intent.trim()
    };
    let clean_target = if q.is_empty() {
        "workspace-critical-paths"
    } else {
        q
    };

    let mut md = String::new();
    md.push_str("# FATHOM PRE-FLIGHT OUTCOME CONTRACT\n\n");
    md.push_str(&format!("- **Target Scope**: `{clean_target}`\n"));
    md.push_str(&format!("- **Intended Outcome**: {clean_intent}\n"));
    md.push_str(&format!(
        "- **Workspace Sovereignty Index**: `{}/100` (`{}` active Ghost Zones)\n\n",
        report.sovereignty_index, report.ghost_zone_count
    ));

    md.push_str("## 1. Scoped Callable Units & Structural Fingerprints\n");
    for u in &matched {
        md.push_str(&format!(
            "- `{}` (`{}:L{}-L{}`, hash `{}`, Consequence `{}/100`, State `{}`)\n",
            u.unit_id,
            u.file_path,
            u.start_line,
            u.end_line,
            &u.structural_hash[..12],
            u.consequence_score,
            u.ownership_state.as_str().to_uppercase()
        ));
    }

    md.push_str("\n## 2. Non-Negotiable Human Reality Invariants\n");
    if protected_invariants.is_empty() {
        md.push_str("- *(No human invariants recorded yet for this scope — preserve existing observable behavior, idempotency, and error contracts.)*\n");
    } else {
        for inv in &protected_invariants {
            md.push_str(&format!(
                "- **[{} · by @{}]** {}\n",
                inv.scope, inv.author, inv.statement
            ));
        }
    }

    md.push_str("\n## 3. One-Way Doors & Irreversible Side-Effect Sinks in Scope\n");
    if doors.is_empty() {
        md.push_str("- None detected directly in target body (verify transitive callees before introducing I/O).\n");
    } else {
        for d in &doors {
            md.push_str(&format!("- {d}\n"));
        }
    }

    md.push_str("\n## 4. Upstream Blast Radius (Callers That Break on Contract Drift)\n");
    if upstream_blast_radius.is_empty() {
        md.push_str("- Top-level entrypoints (check external API/CLI/webhook consumers).\n");
    } else {
        for c in &upstream_blast_radius {
            md.push_str(&format!("- `{c}`\n"));
        }
    }

    if !ghost_warnings.is_empty() {
        md.push_str("\n## 5. Cognitive Debt & Sovereignty Alerts\n");
        for w in &ghost_warnings {
            md.push_str(&format!("- ⚠️ {w}\n"));
        }
    }

    md.push_str("\n## 6. Required Outcome Verification Before Completion\n");
    md.push_str("1. Verify every Human Reality Invariant in Section 2 against concrete failure/edge inputs (not only happy-path unit tests).\n");
    md.push_str("2. Explicitly report any changed branch conditions or One-Way-Door side effects so the human steward can re-anchor via `fathom challenge`.\n");

    PreFlightBrief {
        target: clean_target.to_string(),
        intent: clean_intent.to_string(),
        scoped_units,
        upstream_blast_radius,
        one_way_doors: doors,
        protected_invariants,
        ghost_warnings,
        markdown: md,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct GatePolicy {
    pub min_sovereignty: u32,
    pub max_critical_ghosts: usize,
    pub max_stale_drift: usize,
}

impl Default for GatePolicy {
    fn default() -> Self {
        Self {
            min_sovereignty: 65,
            max_critical_ghosts: 0,
            max_stale_drift: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GateEvaluation {
    pub passed: bool,
    pub policy: GatePolicy,
    pub violations: Vec<String>,
    pub remediation_targets: Vec<String>,
}

impl GateEvaluation {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("passed", Json::Bool(self.passed)),
            (
                "policy",
                Json::obj(vec![
                    (
                        "min_sovereignty",
                        Json::Number(self.policy.min_sovereignty as f64),
                    ),
                    (
                        "max_critical_ghosts",
                        Json::Number(self.policy.max_critical_ghosts as f64),
                    ),
                    (
                        "max_stale_drift",
                        Json::Number(self.policy.max_stale_drift as f64),
                    ),
                ]),
            ),
            (
                "violations",
                Json::Array(self.violations.iter().cloned().map(Json::Str).collect()),
            ),
            (
                "remediation_targets",
                Json::Array(
                    self.remediation_targets
                        .iter()
                        .cloned()
                        .map(Json::Str)
                        .collect(),
                ),
            ),
        ])
    }
}

pub fn evaluate_ci_gate(report: &WorkspaceReport, policy: GatePolicy) -> GateEvaluation {
    let mut violations = Vec::new();
    let mut targets = Vec::new();

    if !report.ledger.chain_valid {
        violations.push(format!(
            "Sovereignty Ledger hash chain invalid: {}",
            report
                .ledger
                .chain_error
                .as_deref()
                .unwrap_or("tampered receipt")
        ));
    }

    if report.sovereignty_index < policy.min_sovereignty {
        violations.push(format!(
            "Workspace Sovereignty Index is {}/100 (minimum required: {}/100)",
            report.sovereignty_index, policy.min_sovereignty
        ));
    }

    if report.critical_ghost_count > policy.max_critical_ghosts {
        violations.push(format!(
            "Found {} Critical Ghost Zone(s) operating without verified human causal ownership (max allowed: {})",
            report.critical_ghost_count, policy.max_critical_ghosts
        ));
    }

    if report.stale_drift_count > policy.max_stale_drift {
        violations.push(format!(
            "Found {} Stale AST Drift unit(s) whose code mutated after human sign-off (max allowed: {})",
            report.stale_drift_count, policy.max_stale_drift
        ));
    }

    for u in &report.units {
        if u.risk_tier == "critical" || u.ownership_state == OwnershipState::StaleDrift {
            targets.push(u.unit_id.clone());
        }
    }

    GateEvaluation {
        passed: violations.is_empty(),
        policy,
        violations,
        remediation_targets: targets,
    }
}
