//! Git-native, SHA-256 hash-chained Sovereignty Ledger (`.fathom/ledger.jsonl`)
//! and Human Reality Invariant Registry (`.fathom/invariants.json`).

use crate::crypto::{format_utc_iso8601, now_unix_secs, sha256_hex};
use crate::json::{parse_json, Json};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SovereigntyReceipt {
    pub seq: u64,
    pub receipt_id: String,
    pub prev_hash: String,
    pub unit_id: String,
    pub structural_hash: String,
    pub author: String,
    pub timestamp_utc: String,
    pub score_pct: u32,
    pub invariant_note: String,
    pub entry_hash: String,
}

impl SovereigntyReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn compute_entry_hash(
        seq: u64,
        prev_hash: &str,
        unit_id: &str,
        structural_hash: &str,
        author: &str,
        timestamp_utc: &str,
        score_pct: u32,
        invariant_note: &str,
    ) -> String {
        let canonical = format!(
            "fathom-receipt-v1|{seq}|{prev_hash}|{unit_id}|{structural_hash}|{author}|{timestamp_utc}|{score_pct}|{invariant_note}"
        );
        sha256_hex(canonical.as_bytes())
    }

    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("seq", Json::Number(self.seq as f64)),
            ("receipt_id", Json::Str(self.receipt_id.clone())),
            ("prev_hash", Json::Str(self.prev_hash.clone())),
            ("unit_id", Json::Str(self.unit_id.clone())),
            ("structural_hash", Json::Str(self.structural_hash.clone())),
            ("author", Json::Str(self.author.clone())),
            ("timestamp_utc", Json::Str(self.timestamp_utc.clone())),
            ("score_pct", Json::Number(self.score_pct as f64)),
            ("invariant_note", Json::Str(self.invariant_note.clone())),
            ("entry_hash", Json::Str(self.entry_hash.clone())),
        ])
    }

    pub fn from_json(v: &Json) -> Result<Self, String> {
        Ok(Self {
            seq: v.get("seq").and_then(Json::as_u64).ok_or("missing seq")?,
            receipt_id: v
                .get("receipt_id")
                .and_then(Json::as_str)
                .ok_or("missing receipt_id")?
                .to_string(),
            prev_hash: v
                .get("prev_hash")
                .and_then(Json::as_str)
                .ok_or("missing prev_hash")?
                .to_string(),
            unit_id: v
                .get("unit_id")
                .and_then(Json::as_str)
                .ok_or("missing unit_id")?
                .to_string(),
            structural_hash: v
                .get("structural_hash")
                .and_then(Json::as_str)
                .ok_or("missing structural_hash")?
                .to_string(),
            author: v
                .get("author")
                .and_then(Json::as_str)
                .ok_or("missing author")?
                .to_string(),
            timestamp_utc: v
                .get("timestamp_utc")
                .and_then(Json::as_str)
                .ok_or("missing timestamp_utc")?
                .to_string(),
            score_pct: v
                .get("score_pct")
                .and_then(Json::as_u64)
                .ok_or("missing score_pct")? as u32,
            invariant_note: v
                .get("invariant_note")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_string(),
            entry_hash: v
                .get("entry_hash")
                .and_then(Json::as_str)
                .ok_or("missing entry_hash")?
                .to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanInvariant {
    pub id: String,
    /// `unit_id` (e.g. `src/billing.rs::settle_invoice`), `file_path` (`src/billing.rs`), or `*`.
    pub scope: String,
    pub statement: String,
    pub author: String,
    pub created_at_utc: String,
}

impl HumanInvariant {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("id", Json::Str(self.id.clone())),
            ("scope", Json::Str(self.scope.clone())),
            ("statement", Json::Str(self.statement.clone())),
            ("author", Json::Str(self.author.clone())),
            ("created_at_utc", Json::Str(self.created_at_utc.clone())),
        ])
    }

    pub fn from_json(v: &Json) -> Result<Self, String> {
        Ok(Self {
            id: v
                .get("id")
                .and_then(Json::as_str)
                .ok_or("missing invariant id")?
                .to_string(),
            scope: v
                .get("scope")
                .and_then(Json::as_str)
                .ok_or("missing scope")?
                .to_string(),
            statement: v
                .get("statement")
                .and_then(Json::as_str)
                .ok_or("missing statement")?
                .to_string(),
            author: v
                .get("author")
                .and_then(Json::as_str)
                .unwrap_or("human")
                .to_string(),
            created_at_utc: v
                .get("created_at_utc")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_string(),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct WorkspaceLedger {
    pub receipts: Vec<SovereigntyReceipt>,
    pub invariants: Vec<HumanInvariant>,
    pub chain_valid: bool,
    pub chain_error: Option<String>,
}

impl WorkspaceLedger {
    pub fn fathom_dir(root: &Path) -> PathBuf {
        root.join(".fathom")
    }

    pub fn ledger_path(root: &Path) -> PathBuf {
        Self::fathom_dir(root).join("ledger.jsonl")
    }

    pub fn invariants_path(root: &Path) -> PathBuf {
        Self::fathom_dir(root).join("invariants.json")
    }

    pub fn load(root: &Path) -> Self {
        let mut receipts = Vec::new();
        let ledger_file = Self::ledger_path(root);
        let mut parse_err: Option<String> = None;

        if let Ok(raw) = fs::read_to_string(&ledger_file) {
            for (idx, line) in raw.lines().enumerate() {
                let t = line.trim();
                if t.is_empty() {
                    continue;
                }
                match parse_json(t)
                    .map_err(|e| e.to_string())
                    .and_then(|j| SovereigntyReceipt::from_json(&j))
                {
                    Ok(r) => receipts.push(r),
                    Err(e) => {
                        parse_err = Some(format!("ledger line {}: {e}", idx + 1));
                        break;
                    }
                }
            }
        }

        let (chain_valid, chain_error) = if let Some(err) = parse_err {
            (false, Some(err))
        } else {
            match verify_receipt_chain(&receipts) {
                Ok(()) => (true, None),
                Err(e) => (false, Some(e)),
            }
        };

        let mut invariants = Vec::new();
        let inv_file = Self::invariants_path(root);
        if let Ok(raw) = fs::read_to_string(&inv_file) {
            if let Ok(Json::Array(items)) = parse_json(&raw) {
                for item in items {
                    if let Ok(inv) = HumanInvariant::from_json(&item) {
                        invariants.push(inv);
                    }
                }
            }
        }

        Self {
            receipts,
            invariants,
            chain_valid,
            chain_error,
        }
    }

    /// Latest receipt per `unit_id`.
    pub fn latest_by_unit(&self) -> BTreeMap<String, SovereigntyReceipt> {
        let mut map = BTreeMap::new();
        for r in &self.receipts {
            map.insert(r.unit_id.clone(), r.clone());
        }
        map
    }

    /// Find all invariants applicable to `unit_id` or `file_path` or `*`.
    pub fn invariants_for(&self, unit_id: &str, file_path: &str) -> Vec<HumanInvariant> {
        self.invariants
            .iter()
            .filter(|inv| inv.scope == "*" || inv.scope == unit_id || inv.scope == file_path)
            .cloned()
            .collect()
    }

    pub fn append_receipt(
        root: &Path,
        unit_id: &str,
        structural_hash: &str,
        author: &str,
        score_pct: u32,
        invariant_note: &str,
    ) -> io::Result<SovereigntyReceipt> {
        let current = Self::load(root);
        if !current.chain_valid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                current
                    .chain_error
                    .unwrap_or_else(|| "corrupt ledger chain".to_string()),
            ));
        }
        let seq = current.receipts.last().map(|r| r.seq + 1).unwrap_or(1);
        let prev_hash = current
            .receipts
            .last()
            .map(|r| r.entry_hash.clone())
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());
        let timestamp_utc = format_utc_iso8601(now_unix_secs());
        let clean_author = if author.trim().is_empty() {
            "human-steward"
        } else {
            author.trim()
        };
        let clean_note = invariant_note.trim();

        let entry_hash = SovereigntyReceipt::compute_entry_hash(
            seq,
            &prev_hash,
            unit_id,
            structural_hash,
            clean_author,
            &timestamp_utc,
            score_pct,
            clean_note,
        );
        let receipt_id = format!("fth-rcpt-{}", &entry_hash[..12]);
        let receipt = SovereigntyReceipt {
            seq,
            receipt_id,
            prev_hash,
            unit_id: unit_id.to_string(),
            structural_hash: structural_hash.to_string(),
            author: clean_author.to_string(),
            timestamp_utc: timestamp_utc.clone(),
            score_pct,
            invariant_note: clean_note.to_string(),
            entry_hash,
        };

        let dir = Self::fathom_dir(root);
        fs::create_dir_all(&dir)?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(Self::ledger_path(root))?;
        writeln!(f, "{}", receipt.to_json().to_string_compact())?;

        // Automatically persist non-empty human reality invariants into `.fathom/invariants.json`
        if !clean_note.is_empty() {
            let _ = Self::add_invariant(root, unit_id, clean_note, clean_author);
        }

        Ok(receipt)
    }

    pub fn add_invariant(
        root: &Path,
        scope: &str,
        statement: &str,
        author: &str,
    ) -> io::Result<HumanInvariant> {
        let mut current = Self::load(root);
        let clean_stmt = statement.trim();
        let clean_scope = scope.trim();
        let clean_author = if author.trim().is_empty() {
            "human-steward"
        } else {
            author.trim()
        };

        // Deduplicate exact `(scope, statement)` pairs
        if let Some(existing) = current
            .invariants
            .iter()
            .find(|i| i.scope == clean_scope && i.statement.eq_ignore_ascii_case(clean_stmt))
        {
            return Ok(existing.clone());
        }

        let ts = format_utc_iso8601(now_unix_secs());
        let id_hash = sha256_hex(format!("{clean_scope}|{clean_stmt}|{ts}").as_bytes());
        let inv = HumanInvariant {
            id: format!("inv-{}", &id_hash[..10]),
            scope: clean_scope.to_string(),
            statement: clean_stmt.to_string(),
            author: clean_author.to_string(),
            created_at_utc: ts,
        };
        current.invariants.push(inv.clone());

        let dir = Self::fathom_dir(root);
        fs::create_dir_all(&dir)?;
        let arr = Json::Array(
            current
                .invariants
                .iter()
                .map(HumanInvariant::to_json)
                .collect(),
        );
        fs::write(Self::invariants_path(root), arr.to_string_pretty() + "\n")?;
        Ok(inv)
    }
}

pub fn verify_receipt_chain(receipts: &[SovereigntyReceipt]) -> Result<(), String> {
    let mut expected_prev = GENESIS_PREV_HASH.to_string();
    for (idx, r) in receipts.iter().enumerate() {
        let expected_seq = (idx + 1) as u64;
        if r.seq != expected_seq {
            return Err(format!(
                "sequence discontinuity at index {idx}: expected seq {expected_seq}, got {}",
                r.seq
            ));
        }
        if r.prev_hash != expected_prev {
            return Err(format!(
                "hash-chain break at receipt {} (seq {}): prev_hash mismatch",
                r.receipt_id, r.seq
            ));
        }
        let recomputed = SovereigntyReceipt::compute_entry_hash(
            r.seq,
            &r.prev_hash,
            &r.unit_id,
            &r.structural_hash,
            &r.author,
            &r.timestamp_utc,
            r.score_pct,
            &r.invariant_note,
        );
        if recomputed != r.entry_hash {
            return Err(format!(
                "tampered receipt {} (seq {}): entry_hash mismatch",
                r.receipt_id, r.seq
            ));
        }
        expected_prev = r.entry_hash.clone();
    }
    Ok(())
}
