//! Git commit-burst & comprehension-erosion forensics (`git log --numstat`).
//!
//! Detects velocity surges where code generation outpaced human causal assimilation,
//! churn-on-churn thrashing, author silos (bus factor), and recency decay.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct FileGitStats {
    pub commit_count: usize,
    pub distinct_authors: usize,
    pub total_added: usize,
    pub total_deleted: usize,
    /// Commits touching this file with >160 lines changed or AI/bulk burst markers.
    pub burst_commits: usize,
    pub last_commit_unix: u64,
    pub last_author: String,
}

impl FileGitStats {
    /// Velocity & churn pressure (0..=35) added to Opacity when large bursts or repeated rewrites occur.
    pub fn velocity_pressure(&self) -> u32 {
        if self.commit_count == 0 {
            // Uncommitted / freshly generated workspace files still carry initial unverified velocity!
            return 14;
        }
        let burst_pts = (self.burst_commits as u32 * 9).min(18);
        let churn_pts = if self.commit_count >= 3 && self.total_deleted > 40 {
            10
        } else if self.commit_count >= 2 {
            4
        } else {
            0
        };
        let silo_pts = if self.distinct_authors <= 1 { 5 } else { 0 };
        (burst_pts + churn_pts + silo_pts).min(35)
    }
}

#[derive(Debug, Clone, Default)]
pub struct RepoGitSummary {
    pub has_git: bool,
    pub total_commits: usize,
    pub distinct_authors: usize,
    pub burst_commit_count: usize,
    pub files: BTreeMap<String, FileGitStats>,
}

pub fn analyze_git_history(root: &Path) -> RepoGitSummary {
    if !root.join(".git").exists() {
        return RepoGitSummary::default();
    }

    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "log",
            "-n",
            "250",
            "--format=@@COMMIT@@|%ct|%an|%s",
            "--numstat",
        ])
        .output();

    let Ok(out) = output else {
        return RepoGitSummary::default();
    };
    if !out.status.success() {
        return RepoGitSummary::default();
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut summary = RepoGitSummary {
        has_git: true,
        ..Default::default()
    };

    let mut all_authors = BTreeSet::new();
    let mut per_file_authors: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    struct PendingCommit {
        ts: u64,
        author: String,
        subject: String,
        files: Vec<(String, usize, usize)>,
        commit_total_added: usize,
    }

    let mut commits: Vec<PendingCommit> = Vec::new();
    let mut cur: Option<PendingCommit> = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("@@COMMIT@@|") {
            if let Some(prev) = cur.take() {
                commits.push(prev);
            }
            let mut parts = rest.splitn(3, '|');
            let ts = parts
                .next()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let author = parts.next().unwrap_or("unknown").trim().to_string();
            let subject = parts.next().unwrap_or("").trim().to_string();
            all_authors.insert(author.clone());
            cur = Some(PendingCommit {
                ts,
                author,
                subject,
                files: Vec::new(),
                commit_total_added: 0,
            });
        } else if let Some(ref mut c) = cur {
            let cols: Vec<&str> = trimmed.split('\t').collect();
            if cols.len() == 3 {
                let added = cols[0].parse::<usize>().unwrap_or(0);
                let deleted = cols[1].parse::<usize>().unwrap_or(0);
                let path = cols[2].trim().to_string();
                c.commit_total_added += added;
                c.files.push((path, added, deleted));
            }
        }
    }
    if let Some(last) = cur.take() {
        commits.push(last);
    }

    summary.total_commits = commits.len();
    summary.distinct_authors = all_authors.len();

    for c in commits {
        let subj_lower = c.subject.to_ascii_lowercase();
        let is_commit_burst = c.commit_total_added >= 250
            || subj_lower.contains("ai:")
            || subj_lower.contains("agent")
            || subj_lower.contains("automerge")
            || subj_lower.contains("generated");
        if is_commit_burst {
            summary.burst_commit_count += 1;
        }

        for (path, added, deleted) in c.files {
            let entry = summary.files.entry(path.clone()).or_default();
            entry.commit_count += 1;
            entry.total_added += added;
            entry.total_deleted += deleted;
            if is_commit_burst || added + deleted >= 160 {
                entry.burst_commits += 1;
            }
            if c.ts >= entry.last_commit_unix {
                entry.last_commit_unix = c.ts;
                entry.last_author = c.author.clone();
            }
            per_file_authors
                .entry(path)
                .or_default()
                .insert(c.author.clone());
        }
    }

    for (path, authors) in per_file_authors {
        if let Some(entry) = summary.files.get_mut(&path) {
            entry.distinct_authors = authors.len();
        }
    }

    summary
}
