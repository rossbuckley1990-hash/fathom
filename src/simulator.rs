//! Deterministic AST-grounded Causal Flight Simulator.
//!
//! Synthesizes 3-stage counterfactual & blast-radius probes directly from real parsed
//! source code (`guards`, `direct_sinks`, `transitive_sink_categories`, `callers`, `callees`)
//! and issues hash-chained Sovereignty Receipts upon 100% causal verification.

use crate::crypto::sha256;
use crate::graph::{AnalyzedUnit, WorkspaceReport};
use crate::json::Json;
use crate::ledger::{SovereigntyReceipt, WorkspaceLedger};
use crate::scanner::SinkCategory;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ChallengeQuestion {
    pub index: usize,
    pub dimension: &'static str,
    pub prompt: String,
    pub options: Vec<String>,
    pub correct_index: usize,
    pub explanation: String,
}

impl ChallengeQuestion {
    /// Public view for UI/CLI before submission (omits `correct_index` so clients validate via oracle,
    /// while remaining deterministic on re-evaluation).
    pub fn to_public_json(&self) -> Json {
        Json::obj(vec![
            ("index", Json::Number(self.index as f64)),
            ("dimension", Json::Str(self.dimension.to_string())),
            ("prompt", Json::Str(self.prompt.clone())),
            (
                "options",
                Json::Array(self.options.iter().cloned().map(Json::Str).collect()),
            ),
        ])
    }
}

#[derive(Debug, Clone)]
pub struct FlightChallenge {
    pub unit_id: String,
    pub unit_name: String,
    pub file_path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub structural_hash: String,
    pub consequence_score: u32,
    pub opacity_score: u32,
    pub cognitive_debt: u32,
    pub source_excerpt: String,
    pub questions: Vec<ChallengeQuestion>,
}

impl FlightChallenge {
    pub fn to_public_json(&self) -> Json {
        Json::obj(vec![
            ("unit_id", Json::Str(self.unit_id.clone())),
            ("unit_name", Json::Str(self.unit_name.clone())),
            ("file_path", Json::Str(self.file_path.clone())),
            ("start_line", Json::Number(self.start_line as f64)),
            ("end_line", Json::Number(self.end_line as f64)),
            ("structural_hash", Json::Str(self.structural_hash.clone())),
            (
                "consequence_score",
                Json::Number(self.consequence_score as f64),
            ),
            ("opacity_score", Json::Number(self.opacity_score as f64)),
            ("cognitive_debt", Json::Number(self.cognitive_debt as f64)),
            ("source_excerpt", Json::Str(self.source_excerpt.clone())),
            (
                "questions",
                Json::Array(
                    self.questions
                        .iter()
                        .map(ChallengeQuestion::to_public_json)
                        .collect(),
                ),
            ),
        ])
    }
}

#[derive(Debug, Clone)]
pub struct QuestionVerdict {
    pub index: usize,
    pub selected: usize,
    pub correct_index: usize,
    pub is_correct: bool,
    pub explanation: String,
}

impl QuestionVerdict {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("index", Json::Number(self.index as f64)),
            ("selected", Json::Number(self.selected as f64)),
            ("correct_index", Json::Number(self.correct_index as f64)),
            ("is_correct", Json::Bool(self.is_correct)),
            ("explanation", Json::Str(self.explanation.clone())),
        ])
    }
}

#[derive(Debug, Clone)]
pub struct ChallengeEvaluation {
    pub passed: bool,
    pub score_pct: u32,
    pub verdicts: Vec<QuestionVerdict>,
    pub receipt: Option<SovereigntyReceipt>,
}

impl ChallengeEvaluation {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("passed", Json::Bool(self.passed)),
            ("score_pct", Json::Number(self.score_pct as f64)),
            (
                "verdicts",
                Json::Array(self.verdicts.iter().map(QuestionVerdict::to_json).collect()),
            ),
            (
                "receipt",
                self.receipt
                    .as_ref()
                    .map(SovereigntyReceipt::to_json)
                    .unwrap_or(Json::Null),
            ),
        ])
    }
}

/// Read exact line range `[start_line..=end_line]` with line numbers for inspection.
pub fn read_unit_source_excerpt(root: &Path, unit: &AnalyzedUnit) -> String {
    let full = root.join(&unit.file_path);
    let Ok(raw) = fs::read_to_string(full) else {
        return unit.signature.clone();
    };
    let lines: Vec<&str> = raw.lines().collect();
    let start = unit.start_line.saturating_sub(1).min(lines.len());
    let end = unit.end_line.min(lines.len());
    let mut out = String::new();
    for (idx, ln) in lines[start..end].iter().enumerate() {
        let line_no = start + idx + 1;
        out.push_str(&format!("{line_no:>4} | {ln}\n"));
    }
    out
}

pub fn build_flight_challenge(
    root: &Path,
    report: &WorkspaceReport,
    unit: &AnalyzedUnit,
) -> FlightChallenge {
    let q1 = build_branch_question(report, unit);
    let q2 = build_sink_question(unit);
    let q3 = build_coupling_question(report, unit);

    FlightChallenge {
        unit_id: unit.unit_id.clone(),
        unit_name: unit.name.clone(),
        file_path: unit.file_path.clone(),
        start_line: unit.start_line,
        end_line: unit.end_line,
        structural_hash: unit.structural_hash.clone(),
        consequence_score: unit.consequence_score,
        opacity_score: unit.opacity_score,
        cognitive_debt: unit.cognitive_debt,
        source_excerpt: read_unit_source_excerpt(root, unit),
        questions: vec![q1, q2, q3],
    }
}

pub fn evaluate_flight_challenge(
    root: &Path,
    report: &WorkspaceReport,
    unit_id: &str,
    answers: &[usize],
    author: &str,
    invariant_note: &str,
) -> io::Result<ChallengeEvaluation> {
    let unit = report.find_unit(unit_id).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("callable unit '{unit_id}' not found in workspace"),
        )
    })?;
    let challenge = build_flight_challenge(root, report, unit);
    if answers.len() != challenge.questions.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "expected {} answers, received {}",
                challenge.questions.len(),
                answers.len()
            ),
        ));
    }

    let mut correct = 0usize;
    let mut verdicts = Vec::with_capacity(challenge.questions.len());
    for (q, &sel) in challenge.questions.iter().zip(answers.iter()) {
        let ok = sel == q.correct_index;
        if ok {
            correct += 1;
        }
        verdicts.push(QuestionVerdict {
            index: q.index,
            selected: sel,
            correct_index: q.correct_index,
            is_correct: ok,
            explanation: q.explanation.clone(),
        });
    }

    let score_pct = ((correct as f64 / challenge.questions.len() as f64) * 100.0).round() as u32;
    let passed = correct == challenge.questions.len();

    let receipt = if passed {
        Some(WorkspaceLedger::append_receipt(
            root,
            &unit.unit_id,
            &unit.structural_hash,
            author,
            score_pct,
            invariant_note,
        )?)
    } else {
        None
    };

    Ok(ChallengeEvaluation {
        passed,
        score_pct,
        verdicts,
        receipt,
    })
}

fn build_branch_question(report: &WorkspaceReport, unit: &AnalyzedUnit) -> ChallengeQuestion {
    if let Some(guard) = unit.guards.first() {
        let correct = format!("Executes `{}`", guard.outcome_summary);

        // Pull realistic distractor branch outcomes from sibling guards in the codebase, plus canonical fallbacks
        let mut distractors: Vec<String> = Vec::new();
        for other_u in &report.units {
            for g in &other_u.guards {
                let cand = format!("Executes `{}`", g.outcome_summary);
                if cand != correct && !distractors.contains(&cand) {
                    distractors.push(cand);
                }
                if distractors.len() >= 2 {
                    break;
                }
            }
            if distractors.len() >= 2 {
                break;
            }
        }
        let fallbacks = [
            "Silently coerced to a no-op default without surfacing an error or state change"
                .to_string(),
            "Bypasses validation guards and commits the downstream mutation unconditionally"
                .to_string(),
            "Spawns a detached background retry loop while returning immediate success to caller"
                .to_string(),
        ];
        for fb in fallbacks {
            if distractors.len() >= 3 {
                break;
            }
            if fb != correct && !distractors.contains(&fb) {
                distractors.push(fb);
            }
        }

        let (options, correct_index) =
            deterministic_shuffle(&unit.structural_hash, 0, correct, distractors);
        return ChallengeQuestion {
            index: 0,
            dimension: "Control-Flow & Branch Trajectory",
            prompt: format!(
                "In `{}` ({}:L{}), when condition `{}` holds, what actually happens next?",
                unit.name, unit.file_path, guard.line, guard.condition
            ),
            options,
            correct_index,
            explanation: format!(
                "At {}:L{}, guard `{}` directly triggers `{}`.",
                unit.file_path, guard.line, guard.condition, guard.outcome_summary
            ),
        };
    }

    // Linear / guardless unit fallback grounded in actual decision & error counts
    let correct = format!(
        "Linear execution path ({} decision path, {} explicit error/bailout exits across {} LoC)",
        unit.decision_points, unit.error_paths, unit.loc
    );
    let distractors = vec![
        "Multi-branch retry loop with exponential backoff and partial commit recovery".to_string(),
        "Recursive state-machine dispatcher with >= 6 conditional guard transitions".to_string(),
        "Lock-acquiring critical section with early panic on contention".to_string(),
    ];
    let (options, correct_index) =
        deterministic_shuffle(&unit.structural_hash, 0, correct, distractors);
    ChallengeQuestion {
        index: 0,
        dimension: "Control-Flow & Branch Trajectory",
        prompt: format!(
            "What is the actual control-flow structure of `{}` ({}:L{}-L{})?",
            unit.name, unit.file_path, unit.start_line, unit.end_line
        ),
        options,
        correct_index,
        explanation: format!(
            "`{}` spans {} lines (L{}-L{}) with {} decision path(s) and {} error-propagation exit(s).",
            unit.name, unit.loc, unit.start_line, unit.end_line, unit.decision_points, unit.error_paths
        ),
    }
}

fn build_sink_question(unit: &AnalyzedUnit) -> ChallengeQuestion {
    let all_cats = [
        SinkCategory::Financial,
        SinkCategory::AuthCrypto,
        SinkCategory::Persistence,
        SinkCategory::ExternalNetwork,
        SinkCategory::Concurrency,
        SinkCategory::ProcessExec,
    ];

    if let Some(primary_sink) = unit.direct_sinks.first() {
        let correct = format!(
            "{} — directly at L{} (`{}`)",
            primary_sink.category.label(),
            primary_sink.line,
            primary_sink.snippet
        );
        let mut distractors = Vec::new();
        for cat in all_cats {
            if !unit.transitive_sink_categories.contains(&cat) {
                distractors.push(format!(
                    "{} — crosses external {} boundary inside body",
                    cat.label(),
                    cat.as_str()
                ));
            }
            if distractors.len() == 2 {
                break;
            }
        }
        distractors.push(
            "Pure in-memory calculation — crosses zero persistence, auth, financial, or I/O boundaries"
                .to_string(),
        );
        while distractors.len() < 3 {
            distractors.push(
                "Process / Shell Exec — spawns an external OS child subprocess directly"
                    .to_string(),
            );
        }

        let (options, correct_index) =
            deterministic_shuffle(&unit.structural_hash, 1, correct, distractors);
        return ChallengeQuestion {
            index: 1,
            dimension: "One-Way-Door & Side-Effect Boundary",
            prompt: format!(
                "Which consequential One-Way-Door sink does `{}` directly execute?",
                unit.name
            ),
            options,
            correct_index,
            explanation: format!(
                "`{}` crosses `{}` at {}:L{}: `{}`.",
                unit.name,
                primary_sink.category.label(),
                unit.file_path,
                primary_sink.line,
                primary_sink.snippet
            ),
        };
    }

    if let Some(&trans_cat) = unit.transitive_sink_categories.first() {
        let correct = format!(
            "Transitive {} boundary reached via downstream callees ({})",
            trans_cat.label(),
            unit.callees.join(", ")
        );
        let distractors = vec![
            "Pure isolated leaf helper — neither directly nor transitively reaches any side-effect sink"
                .to_string(),
            "Spawns raw OS kernel processes (`Command::new`) directly inside its own body"
                .to_string(),
            "Executes `DROP TABLE` / destructive schema truncation directly on disk".to_string(),
        ];
        let (options, correct_index) =
            deterministic_shuffle(&unit.structural_hash, 1, correct, distractors);
        return ChallengeQuestion {
            index: 1,
            dimension: "One-Way-Door & Side-Effect Boundary",
            prompt: format!(
                "`{}` has no direct sink lines inside its body, yet carries Consequence Score {}/100. Why?",
                unit.name, unit.consequence_score
            ),
            options,
            correct_index,
            explanation: format!(
                "Even though `{}` looks clean locally, its downstream callees ({}) cross `{}`.",
                unit.name,
                unit.callees.join(", "),
                trans_cat.label()
            ),
        };
    }

    let correct =
        "Pure / in-memory computation — zero direct or transitive One-Way-Door I/O sinks detected"
            .to_string();
    let distractors = vec![
        "Financial / Ledger — mutates payment settlement balances directly".to_string(),
        "State / DB Mutation — commits SQL transactions or overwrites filesystem state".to_string(),
        "External Network / Webhook — dispatches outbound HTTP webhook requests".to_string(),
    ];
    let (options, correct_index) =
        deterministic_shuffle(&unit.structural_hash, 1, correct, distractors);
    ChallengeQuestion {
        index: 1,
        dimension: "One-Way-Door & Side-Effect Boundary",
        prompt: format!(
            "What One-Way-Door side-effect profile applies to `{}`?",
            unit.name
        ),
        options,
        correct_index,
        explanation: format!(
            "`{}` performs pure in-memory logic with zero direct or transitive external/storage sinks.",
            unit.name
        ),
    }
}

fn build_coupling_question(report: &WorkspaceReport, unit: &AnalyzedUnit) -> ChallengeQuestion {
    if let Some(first_caller) = unit.callers.first() {
        let correct = format!(
            "`{}` directly calls `{}` ({} total transitive upstream dependent(s))",
            first_caller, unit.name, unit.transitive_caller_count
        );
        let mut distractors = Vec::new();
        for other in &report.units {
            if other.unit_id != unit.unit_id
                && !unit.callers.contains(&other.unit_id)
                && distractors.len() < 2
            {
                distractors.push(format!(
                    "`{}` is the sole upstream caller of `{}`",
                    other.unit_id, unit.name
                ));
            }
        }
        distractors.push(format!(
            "Zero internal callers — `{}` is an unreferenced dead-code leaf",
            unit.name
        ));
        while distractors.len() < 3 {
            distractors.push("Called exclusively by external build scripts".to_string());
        }

        let (options, correct_index) =
            deterministic_shuffle(&unit.structural_hash, 2, correct, distractors);
        return ChallengeQuestion {
            index: 2,
            dimension: "Blast Radius & Call-Graph Coupling",
            prompt: format!(
                "If you alter the return semantics or invariants of `{}`, which upstream caller in the repository is directly impacted?",
                unit.name
            ),
            options,
            correct_index,
            explanation: format!(
                "`{}` has {} direct caller(s) ({}) and {} transitive upstream dependent(s).",
                unit.name,
                unit.callers.len(),
                unit.callers.join(", "),
                unit.transitive_caller_count
            ),
        };
    }

    if let Some(first_callee) = unit.callees.first() {
        let correct = TopEntrypointFmt::describe(&unit.name, first_callee, unit.callees.len());
        let mut distractors = Vec::new();
        for other in &report.units {
            if other.unit_id != unit.unit_id
                && !unit.callees.contains(&other.unit_id)
                && distractors.len() < 2
            {
                distractors.push(format!(
                    "Delegates directly to `{}` as its primary downstream step",
                    other.unit_id
                ));
            }
        }
        distractors.push(
            "Calls zero internal workspace functions — completely self-contained leaf".to_string(),
        );
        while distractors.len() < 3 {
            distractors.push("Recursively invokes only itself".to_string());
        }

        let (options, correct_index) =
            deterministic_shuffle(&unit.structural_hash, 2, correct, distractors);
        return ChallengeQuestion {
            index: 2,
            dimension: "Blast Radius & Call-Graph Coupling",
            prompt: format!(
                "`{}` acts as a top-level entrypoint (0 internal callers). Which workspace unit does it directly orchestrate?",
                unit.name
            ),
            options,
            correct_index,
            explanation: format!(
                "`{}` has 0 internal callers and directly invokes {} workspace unit(s): {}.",
                unit.name,
                unit.callees.len(),
                unit.callees.join(", ")
            ),
        };
    }

    let correct = format!(
        "Standalone boundary unit (0 internal workspace callers, 0 internal workspace callees; hash `{}`)",
        &unit.structural_hash[..8]
    );
    let distractors = vec![
        "Central hub invoked by >= 4 internal modules across the workspace".to_string(),
        "Orchestrates >= 3 downstream persistence and network helpers".to_string(),
        "Mutually recursive helper pair across two modules".to_string(),
    ];
    let (options, correct_index) =
        deterministic_shuffle(&unit.structural_hash, 2, correct, distractors);
    ChallengeQuestion {
        index: 2,
        dimension: "Blast Radius & Call-Graph Coupling",
        prompt: format!(
            "How is `{}` coupled within the internal repository call graph?",
            unit.name
        ),
        options,
        correct_index,
        explanation: format!(
            "`{}` is a standalone boundary function with 0 internal callers and 0 internal callees.",
            unit.name
        ),
    }
}

struct TopEntrypointFmt;
impl TopEntrypointFmt {
    fn describe(name: &str, callee: &str, total: usize) -> String {
        format!("Top-level entrypoint `{name}` directly invokes `{callee}` ({total} internal callee(s))")
    }
}

fn deterministic_shuffle(
    structural_hash: &str,
    q_idx: usize,
    correct: String,
    mut distractors: Vec<String>,
) -> (Vec<String>, usize) {
    distractors.truncate(3);
    let mut items: Vec<(bool, String)> = Vec::with_capacity(1 + distractors.len());
    items.push((true, correct));
    for d in distractors {
        items.push((false, d));
    }

    let seed = sha256(format!("fathom-q-shuffle|{structural_hash}|{q_idx}").as_bytes());
    let len = items.len();
    for i in (1..len).rev() {
        let j = (seed[i % seed.len()] as usize) % (i + 1);
        items.swap(i, j);
    }

    let correct_idx = items.iter().position(|(is_c, _)| *is_c).unwrap_or(0);
    let options = items.into_iter().map(|(_, text)| text).collect();
    (options, correct_idx)
}
