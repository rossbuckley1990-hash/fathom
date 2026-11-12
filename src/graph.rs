//! Cross-file call-graph resolution, transitive consequence propagation,
//! Cognitive Debt scoring, Ghost Zone detection, and Workspace Sovereignty reports.

use crate::git_intel::{analyze_git_history, FileGitStats, RepoGitSummary};
use crate::json::Json;
use crate::ledger::{HumanInvariant, SovereigntyReceipt, WorkspaceLedger};
use crate::scanner::{scan_workspace_units, BranchGuard, ConsequenceSink, Language, SinkCategory};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipState {
    /// Current `structural_hash` matches a verified human Flight Check receipt (`S = 1.0`).
    Anchored,
    /// A human previously verified an older AST of this function, and logic mutated since (`S = 0.30`).
    StaleDrift,
    /// Zero verified human causal model recorded (`S = 0.0`).
    Unverified,
}

impl OwnershipState {
    pub fn as_str(self) -> &'static str {
        match self {
            OwnershipState::Anchored => "anchored",
            OwnershipState::StaleDrift => "stale_drift",
            OwnershipState::Unverified => "unverified",
        }
    }

    pub fn sovereignty_factor(self) -> f64 {
        match self {
            OwnershipState::Anchored => 1.0,
            OwnershipState::StaleDrift => 0.30,
            OwnershipState::Unverified => 0.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnalyzedUnit {
    pub unit_id: String,
    pub name: String,
    pub file_path: String,
    pub language: Language,
    pub signature: String,
    pub start_line: usize,
    pub end_line: usize,
    pub loc: usize,
    pub structural_hash: String,
    pub decision_points: usize,
    pub max_nesting: usize,
    pub error_paths: usize,
    pub direct_sinks: Vec<ConsequenceSink>,
    pub transitive_sink_categories: Vec<SinkCategory>,
    pub guards: Vec<BranchGuard>,
    pub callers: Vec<String>,
    pub callees: Vec<String>,
    pub transitive_caller_count: usize,
    pub git_stats: FileGitStats,
    pub ownership_state: OwnershipState,
    pub latest_receipt: Option<SovereigntyReceipt>,
    pub invariants: Vec<HumanInvariant>,
    pub consequence_score: u32,
    pub opacity_score: u32,
    pub cognitive_debt: u32,
    pub is_ghost_zone: bool,
    pub risk_tier: &'static str,
}

impl AnalyzedUnit {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("unit_id", Json::Str(self.unit_id.clone())),
            ("name", Json::Str(self.name.clone())),
            ("file_path", Json::Str(self.file_path.clone())),
            ("language", Json::Str(self.language.as_str().to_string())),
            ("signature", Json::Str(self.signature.clone())),
            ("start_line", Json::Number(self.start_line as f64)),
            ("end_line", Json::Number(self.end_line as f64)),
            ("loc", Json::Number(self.loc as f64)),
            ("structural_hash", Json::Str(self.structural_hash.clone())),
            ("decision_points", Json::Number(self.decision_points as f64)),
            ("max_nesting", Json::Number(self.max_nesting as f64)),
            ("error_paths", Json::Number(self.error_paths as f64)),
            (
                "direct_sinks",
                Json::Array(
                    self.direct_sinks
                        .iter()
                        .map(ConsequenceSink::to_json)
                        .collect(),
                ),
            ),
            (
                "transitive_sink_categories",
                Json::Array(
                    self.transitive_sink_categories
                        .iter()
                        .map(|c| Json::Str(c.as_str().to_string()))
                        .collect(),
                ),
            ),
            (
                "guards",
                Json::Array(self.guards.iter().map(BranchGuard::to_json).collect()),
            ),
            (
                "callers",
                Json::Array(self.callers.iter().cloned().map(Json::Str).collect()),
            ),
            (
                "callees",
                Json::Array(self.callees.iter().cloned().map(Json::Str).collect()),
            ),
            (
                "transitive_caller_count",
                Json::Number(self.transitive_caller_count as f64),
            ),
            (
                "git",
                Json::obj(vec![
                    (
                        "commit_count",
                        Json::Number(self.git_stats.commit_count as f64),
                    ),
                    (
                        "distinct_authors",
                        Json::Number(self.git_stats.distinct_authors as f64),
                    ),
                    (
                        "burst_commits",
                        Json::Number(self.git_stats.burst_commits as f64),
                    ),
                    (
                        "total_added",
                        Json::Number(self.git_stats.total_added as f64),
                    ),
                    (
                        "total_deleted",
                        Json::Number(self.git_stats.total_deleted as f64),
                    ),
                    ("last_author", Json::Str(self.git_stats.last_author.clone())),
                ]),
            ),
            (
                "ownership_state",
                Json::Str(self.ownership_state.as_str().to_string()),
            ),
            (
                "latest_receipt",
                self.latest_receipt
                    .as_ref()
                    .map(SovereigntyReceipt::to_json)
                    .unwrap_or(Json::Null),
            ),
            (
                "invariants",
                Json::Array(
                    self.invariants
                        .iter()
                        .map(HumanInvariant::to_json)
                        .collect(),
                ),
            ),
            (
                "consequence_score",
                Json::Number(self.consequence_score as f64),
            ),
            ("opacity_score", Json::Number(self.opacity_score as f64)),
            ("cognitive_debt", Json::Number(self.cognitive_debt as f64)),
            ("is_ghost_zone", Json::Bool(self.is_ghost_zone)),
            ("risk_tier", Json::Str(self.risk_tier.to_string())),
        ])
    }
}

#[derive(Debug, Clone)]
pub struct WorkspaceReport {
    pub root_path: String,
    pub total_units: usize,
    pub load_bearing_units: usize,
    pub sovereignty_index: u32,
    pub comprehension_coverage_pct: u32,
    pub total_cognitive_debt: u32,
    pub ghost_zone_count: usize,
    pub critical_ghost_count: usize,
    pub stale_drift_count: usize,
    pub anchored_count: usize,
    pub epistemic_bus_factor: usize,
    pub git_summary: RepoGitSummary,
    pub ledger: WorkspaceLedger,
    pub units: Vec<AnalyzedUnit>,
}

impl WorkspaceReport {
    pub fn find_unit(&self, query: &str) -> Option<&AnalyzedUnit> {
        let q = query.trim();
        if let Some(exact) = self.units.iter().find(|u| u.unit_id == q) {
            return Some(exact);
        }
        if let Some(by_name) = self.units.iter().find(|u| u.name == q) {
            return Some(by_name);
        }
        self.units
            .iter()
            .find(|u| u.unit_id.contains(q) || u.file_path == q)
    }

    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("root_path", Json::Str(self.root_path.clone())),
            ("total_units", Json::Number(self.total_units as f64)),
            (
                "load_bearing_units",
                Json::Number(self.load_bearing_units as f64),
            ),
            (
                "sovereignty_index",
                Json::Number(self.sovereignty_index as f64),
            ),
            (
                "comprehension_coverage_pct",
                Json::Number(self.comprehension_coverage_pct as f64),
            ),
            (
                "total_cognitive_debt",
                Json::Number(self.total_cognitive_debt as f64),
            ),
            (
                "ghost_zone_count",
                Json::Number(self.ghost_zone_count as f64),
            ),
            (
                "critical_ghost_count",
                Json::Number(self.critical_ghost_count as f64),
            ),
            (
                "stale_drift_count",
                Json::Number(self.stale_drift_count as f64),
            ),
            ("anchored_count", Json::Number(self.anchored_count as f64)),
            (
                "epistemic_bus_factor",
                Json::Number(self.epistemic_bus_factor as f64),
            ),
            (
                "git_summary",
                Json::obj(vec![
                    ("has_git", Json::Bool(self.git_summary.has_git)),
                    (
                        "total_commits",
                        Json::Number(self.git_summary.total_commits as f64),
                    ),
                    (
                        "distinct_authors",
                        Json::Number(self.git_summary.distinct_authors as f64),
                    ),
                    (
                        "burst_commit_count",
                        Json::Number(self.git_summary.burst_commit_count as f64),
                    ),
                ]),
            ),
            (
                "ledger_status",
                Json::obj(vec![
                    ("chain_valid", Json::Bool(self.ledger.chain_valid)),
                    (
                        "chain_error",
                        self.ledger
                            .chain_error
                            .as_ref()
                            .map(|s| Json::Str(s.clone()))
                            .unwrap_or(Json::Null),
                    ),
                    (
                        "receipt_count",
                        Json::Number(self.ledger.receipts.len() as f64),
                    ),
                    (
                        "invariant_count",
                        Json::Number(self.ledger.invariants.len() as f64),
                    ),
                ]),
            ),
            (
                "units",
                Json::Array(self.units.iter().map(AnalyzedUnit::to_json).collect()),
            ),
        ])
    }
}

/// Perform full cross-file source, Git velocity, call-graph, and Sovereignty Ledger analysis on `root`.
pub fn analyze_workspace(root: &Path) -> io::Result<WorkspaceReport> {
    let canonical_root = fs::canonicalize_safe(root);
    let raw_units = scan_workspace_units(&canonical_root)?;
    let git_summary = analyze_git_history(&canonical_root);
    let ledger = WorkspaceLedger::load(&canonical_root);
    let latest_receipts = ledger.latest_by_unit();

    // Index function names -> unit indices (preferring same-file resolution when multiple exist)
    let mut by_name: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (idx, u) in raw_units.iter().enumerate() {
        by_name.entry(u.name.clone()).or_default().push(idx);
    }

    let n = raw_units.len();
    let mut callees_idx: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    let mut callers_idx: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];

    for (src_idx, u) in raw_units.iter().enumerate() {
        for called_name in &u.raw_calls {
            if let Some(candidates) = by_name.get(called_name) {
                let target_idx = candidates
                    .iter()
                    .copied()
                    .find(|&c| raw_units[c].file_path == u.file_path && c != src_idx)
                    .or_else(|| candidates.iter().copied().find(|&c| c != src_idx));
                if let Some(dst_idx) = target_idx {
                    callees_idx[src_idx].insert(dst_idx);
                    callers_idx[dst_idx].insert(src_idx);
                }
            }
        }
    }

    let mut analyzed = Vec::with_capacity(n);
    let mut verified_stewards = BTreeSet::new();

    for (idx, u) in raw_units.iter().enumerate() {
        // BFS upstream callers (blast radius)
        let trans_callers = bfs_reachable(idx, &callers_idx);
        // BFS downstream callees (transitive consequence sinks!)
        let trans_callees = bfs_reachable(idx, &callees_idx);

        let direct_cats: BTreeSet<SinkCategory> = u.sinks.iter().map(|s| s.category).collect();
        let mut trans_cats: BTreeSet<SinkCategory> = direct_cats.clone();
        for &callee_i in &trans_callees {
            for s in &raw_units[callee_i].sinks {
                trans_cats.insert(s.category);
            }
        }

        // Consequence Score C(u) in 0..=100
        let direct_sink_pts: u32 = direct_cats.iter().map(|c| c.severity_weight()).sum();
        let indirect_only_pts: u32 = trans_cats
            .difference(&direct_cats)
            .map(|c| c.severity_weight() / 2)
            .sum();
        let fan_in_pts =
            ((callers_idx[idx].len() as u32 * 9) + (trans_callers.len() as u32 * 4)).min(30);
        let error_pts = (u.error_paths as u32 * 3).min(14);
        let base_load = if u.loc >= 25 || u.decision_points >= 4 {
            14
        } else {
            8
        };
        let consequence_score =
            (base_load + direct_sink_pts + indirect_only_pts + fan_in_pts + error_pts).min(100);

        // Opacity & Velocity Pressure O(u) in 0..=100
        let git_stats = git_summary
            .files
            .get(&u.file_path)
            .cloned()
            .unwrap_or_default();
        let branch_pts = (u.decision_points as u32 * 5).min(42);
        let nest_pts = (u.max_nesting as u32 * 6).min(20);
        let size_pts = (u.loc as u32 / 4).min(18);
        let vel_pts = git_stats.velocity_pressure();
        let opacity_score = (branch_pts + nest_pts + size_pts + vel_pts).min(100);

        // Ownership state against Normalized Structural Hash
        let latest_receipt = latest_receipts.get(&u.unit_id).cloned();
        let ownership_state = match &latest_receipt {
            Some(r) if r.structural_hash == u.structural_hash && ledger.chain_valid => {
                verified_stewards.insert(r.author.clone());
                OwnershipState::Anchored
            }
            Some(_) => OwnershipState::StaleDrift,
            None => OwnershipState::Unverified,
        };

        let s_factor = ownership_state.sovereignty_factor();
        let raw_debt =
            (consequence_score as f64) * (opacity_score as f64 / 100.0) * (1.0 - s_factor);
        let cognitive_debt = raw_debt.round() as u32;

        let is_ghost_zone = consequence_score >= 45
            && opacity_score >= 25
            && ownership_state != OwnershipState::Anchored;

        let risk_tier = if ownership_state == OwnershipState::Anchored {
            "anchored"
        } else if cognitive_debt >= 40 || (is_ghost_zone && consequence_score >= 68) {
            "critical"
        } else if is_ghost_zone || ownership_state == OwnershipState::StaleDrift {
            "elevated"
        } else {
            "moderate"
        };

        let callers = callers_idx[idx]
            .iter()
            .map(|&c| raw_units[c].unit_id.clone())
            .collect();
        let callees = callees_idx[idx]
            .iter()
            .map(|&c| raw_units[c].unit_id.clone())
            .collect();
        let invariants = ledger.invariants_for(&u.unit_id, &u.file_path);

        analyzed.push(AnalyzedUnit {
            unit_id: u.unit_id.clone(),
            name: u.name.clone(),
            file_path: u.file_path.clone(),
            language: u.language,
            signature: u.signature.clone(),
            start_line: u.start_line,
            end_line: u.end_line,
            loc: u.loc,
            structural_hash: u.structural_hash.clone(),
            decision_points: u.decision_points,
            max_nesting: u.max_nesting,
            error_paths: u.error_paths,
            direct_sinks: u.sinks.clone(),
            transitive_sink_categories: trans_cats.into_iter().collect(),
            guards: u.guards.clone(),
            callers,
            callees,
            transitive_caller_count: trans_callers.len(),
            git_stats,
            ownership_state,
            latest_receipt,
            invariants,
            consequence_score,
            opacity_score,
            cognitive_debt,
            is_ghost_zone,
            risk_tier,
        });
    }

    // Sort highest Cognitive Debt first (deterministic tie-break by Consequence then unit_id)
    analyzed.sort_by(|a, b| {
        b.cognitive_debt
            .cmp(&a.cognitive_debt)
            .then_with(|| b.consequence_score.cmp(&a.consequence_score))
            .then_with(|| a.unit_id.cmp(&b.unit_id))
    });

    // Aggregate Workspace Sovereignty Index (consequence-weighted ownership across load-bearing units)
    let mut weighted_owned = 0.0f64;
    let mut weighted_total = 0.0f64;
    let mut load_bearing_units = 0usize;
    let mut load_bearing_anchored = 0usize;
    let mut total_cognitive_debt = 0u32;
    let mut ghost_zone_count = 0usize;
    let mut critical_ghost_count = 0usize;
    let mut stale_drift_count = 0usize;
    let mut anchored_count = 0usize;

    for u in &analyzed {
        total_cognitive_debt += u.cognitive_debt;
        if u.is_ghost_zone {
            ghost_zone_count += 1;
            if u.risk_tier == "critical" {
                critical_ghost_count += 1;
            }
        }
        match u.ownership_state {
            OwnershipState::Anchored => anchored_count += 1,
            OwnershipState::StaleDrift => stale_drift_count += 1,
            OwnershipState::Unverified => {}
        }

        let w = u.consequence_score.max(1) as f64;
        weighted_total += w;
        weighted_owned += w * u.ownership_state.sovereignty_factor();

        if u.consequence_score >= 35 {
            load_bearing_units += 1;
            if u.ownership_state == OwnershipState::Anchored {
                load_bearing_anchored += 1;
            }
        }
    }

    let sovereignty_index = if analyzed.is_empty() {
        100
    } else {
        ((weighted_owned / weighted_total) * 100.0).round() as u32
    };

    let comprehension_coverage_pct = if load_bearing_units == 0 {
        100
    } else {
        ((load_bearing_anchored as f64 / load_bearing_units as f64) * 100.0).round() as u32
    };

    Ok(WorkspaceReport {
        root_path: canonical_root.to_string_lossy().into_owned(),
        total_units: analyzed.len(),
        load_bearing_units,
        sovereignty_index,
        comprehension_coverage_pct,
        total_cognitive_debt,
        ghost_zone_count,
        critical_ghost_count,
        stale_drift_count,
        anchored_count,
        epistemic_bus_factor: verified_stewards.len(),
        git_summary,
        ledger,
        units: analyzed,
    })
}

fn bfs_reachable(start: usize, adj: &[BTreeSet<usize>]) -> BTreeSet<usize> {
    let mut visited = BTreeSet::new();
    let mut q = VecDeque::new();
    for &nxt in &adj[start] {
        if visited.insert(nxt) {
            q.push_back(nxt);
        }
    }
    while let Some(cur) = q.pop_front() {
        for &nxt in &adj[cur] {
            if nxt != start && visited.insert(nxt) {
                q.push_back(nxt);
            }
        }
    }
    visited
}

mod fs {
    use std::path::{Path, PathBuf};
    pub fn canonicalize_safe(p: &Path) -> PathBuf {
        std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
    }
}
