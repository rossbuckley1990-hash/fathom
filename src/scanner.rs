//! Comment-and-string-aware multi-language source scanner (Rust, TypeScript/JS, Python, Go).
//!
//! Extracts callable units, computes whitespace/comment-invariant Normalized Structural Hashes,
//! detects One-Way-Door consequence sinks, and captures real control-flow branch guards
//! for the Causal Flight Simulator.

use crate::crypto::sha256_hex;
use crate::json::Json;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Rust,
    TypeScript,
    JavaScript,
    Python,
    Go,
}

impl Language {
    pub fn from_path(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?;
        match ext {
            "rs" => Some(Language::Rust),
            "ts" | "tsx" => Some(Language::TypeScript),
            "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
            "py" => Some(Language::Python),
            "go" => Some(Language::Go),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Language::Rust => "rust",
            Language::TypeScript => "typescript",
            Language::JavaScript => "javascript",
            Language::Python => "python",
            Language::Go => "go",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SinkCategory {
    Financial,
    AuthCrypto,
    Persistence,
    ExternalNetwork,
    Concurrency,
    ProcessExec,
}

impl SinkCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            SinkCategory::Financial => "financial",
            SinkCategory::AuthCrypto => "auth_crypto",
            SinkCategory::Persistence => "persistence",
            SinkCategory::ExternalNetwork => "external_network",
            SinkCategory::Concurrency => "concurrency",
            SinkCategory::ProcessExec => "process_exec",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SinkCategory::Financial => "Financial / Ledger",
            SinkCategory::AuthCrypto => "Auth & Cryptography",
            SinkCategory::Persistence => "State / DB Mutation",
            SinkCategory::ExternalNetwork => "External Network / Webhook",
            SinkCategory::Concurrency => "Concurrency & Locks",
            SinkCategory::ProcessExec => "Process / Shell Exec",
        }
    }

    pub fn severity_weight(self) -> u32 {
        match self {
            SinkCategory::Financial => 34,
            SinkCategory::AuthCrypto => 30,
            SinkCategory::Persistence => 26,
            SinkCategory::ProcessExec => 26,
            SinkCategory::Concurrency => 22,
            SinkCategory::ExternalNetwork => 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsequenceSink {
    pub category: SinkCategory,
    pub line: usize,
    pub snippet: String,
}

impl ConsequenceSink {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("category", Json::Str(self.category.as_str().to_string())),
            ("label", Json::Str(self.category.label().to_string())),
            ("line", Json::Number(self.line as f64)),
            ("snippet", Json::Str(self.snippet.clone())),
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchGuard {
    pub line: usize,
    pub condition: String,
    pub outcome_summary: String,
}

impl BranchGuard {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("line", Json::Number(self.line as f64)),
            ("condition", Json::Str(self.condition.clone())),
            ("outcome_summary", Json::Str(self.outcome_summary.clone())),
        ])
    }
}

#[derive(Debug, Clone)]
pub struct RawCallableUnit {
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
    pub sinks: Vec<ConsequenceSink>,
    pub guards: Vec<BranchGuard>,
    pub raw_calls: Vec<String>,
}

const IGNORED_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "dist",
    "build",
    "out",
    ".next",
    "__pycache__",
    ".venv",
    "venv",
    ".fathom",
    "vendor",
    "coverage",
    "tests",
];

fn is_test_filename(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    name.ends_with("_test.rs")
        || name.ends_with("_test.go")
        || name.ends_with(".test.ts")
        || name.ends_with(".spec.ts")
        || name.ends_with(".test.js")
        || name.ends_with(".spec.js")
        || (name.starts_with("test_") && name.ends_with(".py"))
}

/// Walk `root` deterministically and extract all production callable units.
pub fn scan_workspace_units(root: &Path) -> io::Result<Vec<RawCallableUnit>> {
    let mut files = Vec::new();
    collect_source_files(root, root, &mut files)?;
    files.sort();

    let mut units = Vec::new();
    for rel_path in files {
        let full_path = root.join(&rel_path);
        let Some(lang) = Language::from_path(&rel_path) else {
            continue;
        };
        let Ok(source) = fs::read_to_string(&full_path) else {
            continue;
        };
        let rel_str = rel_path
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        let mut file_units = extract_units_from_file(&rel_str, lang, &source);
        units.append(&mut file_units);
    }
    Ok(units)
}

fn collect_source_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name.starts_with('.') && path != *root {
            continue;
        }
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() {
            if IGNORED_DIRS.contains(&name) {
                continue;
            }
            collect_source_files(root, &path, out)?;
        } else if ft.is_file() && Language::from_path(&path).is_some() && !is_test_filename(&path) {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_path_buf());
            }
        }
    }
    Ok(())
}

/// Strip comments while preserving exact newlines and masking string literals as `"S"`
/// for brace/structure scanning, PLUS producing the exact normalized token stream for hashing.
pub fn strip_comments_preserve_lines(source: &str, lang: Language) -> String {
    let bytes = source.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        let b = bytes[i];
        // Line comments
        if lang != Language::Python && b == b'/' && i + 1 < len && bytes[i + 1] == b'/' {
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if lang == Language::Python && b == b'#' {
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Block comments /* ... */
        if lang != Language::Python && b == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
            i += 2;
            let mut depth = 1usize;
            while i < len && depth > 0 {
                if lang == Language::Rust && i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'*'
                {
                    depth += 1;
                    i += 2;
                } else if i + 1 < len && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    if bytes[i] == b'\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
            }
            out.push(' ');
            continue;
        }
        // Python triple-quoted docstrings / strings
        if lang == Language::Python
            && i + 2 < len
            && ((b == b'"' && bytes[i + 1] == b'"' && bytes[i + 2] == b'"')
                || (b == b'\'' && bytes[i + 1] == b'\'' && bytes[i + 2] == b'\''))
        {
            let q = b;
            i += 3;
            while i < len {
                if i + 2 < len && bytes[i] == q && bytes[i + 1] == q && bytes[i + 2] == q {
                    i += 3;
                    break;
                }
                if bytes[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            continue;
        }
        // Rust raw strings r#"..."# or r"..."
        if lang == Language::Rust
            && b == b'r'
            && i + 1 < len
            && (bytes[i + 1] == b'#' || bytes[i + 1] == b'"')
        {
            let mut hashes = 0usize;
            let mut j = i + 1;
            while j < len && bytes[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < len && bytes[j] == b'"' {
                out.push_str("r\"");
                i = j + 1;
                while i < len {
                    if bytes[i] == b'"' {
                        let mut ok = true;
                        for h in 0..hashes {
                            if i + 1 + h >= len || bytes[i + 1 + h] != b'#' {
                                ok = false;
                                break;
                            }
                        }
                        if ok {
                            i += 1 + hashes;
                            break;
                        }
                    }
                    if bytes[i] == b'\n' {
                        out.push('\n');
                    } else {
                        out.push('x');
                    }
                    i += 1;
                }
                out.push('"');
                continue;
            }
        }
        // Normal quoted strings ("...", '...', `...`)
        if b == b'"' || b == b'`' || (b == b'\'' && lang != Language::Rust) {
            let quote = b;
            out.push(quote as char);
            i += 1;
            while i < len {
                if bytes[i] == b'\\' {
                    out.push('x');
                    i = (i + 2).min(len);
                    continue;
                }
                if bytes[i] == quote {
                    i += 1;
                    break;
                }
                if bytes[i] == b'\n' {
                    out.push('\n');
                } else {
                    // Keep string content hashed for logic accuracy, neutralize `{` `}` inside strings!
                    let ch = bytes[i];
                    if matches!(ch, b'{' | b'}' | b'(' | b')') {
                        out.push('_');
                    } else if ch.is_ascii() {
                        out.push(ch as char);
                    } else {
                        out.push('u');
                    }
                }
                i += 1;
            }
            out.push(quote as char);
            continue;
        }
        // Rust char literal vs lifetime ('a vs 'x')
        if lang == Language::Rust && b == b'\'' {
            if i + 2 < len && bytes[i + 1] != b'\\' && bytes[i + 2] == b'\'' {
                out.push_str("'c'");
                i += 3;
                continue;
            }
            if i + 3 < len && bytes[i + 1] == b'\\' && bytes[i + 3] == b'\'' {
                out.push_str("'e'");
                i += 4;
                continue;
            }
        }

        let rest = &source[i..];
        let ch = rest.chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Compute a 24-hex SHA-256 structural fingerprint over comment-stripped, whitespace-normalized code tokens.
/// Reformatting (`cargo fmt` / `prettier` / `black`) or editing comments produces the EXACT same hash;
/// mutating any operator, identifier, literal, or branch immediately produces a new hash.
pub fn compute_structural_hash(code_slice: &str, lang: Language) -> String {
    let stripped = strip_comments_preserve_lines(code_slice, lang);
    let mut normalized = String::with_capacity(stripped.len());
    let mut prev_alnum = false;

    // Token-aware normalization: separate adjacent identifier tokens with a single space,
    // collapse all whitespace/newlines everywhere else.
    let chars: Vec<char> = stripped.chars().collect();
    let mut idx = 0;
    while idx < chars.len() {
        let c = chars[idx];
        if c.is_whitespace() {
            idx += 1;
            continue;
        }
        let is_id = c.is_ascii_alphanumeric() || c == '_';
        if is_id {
            if prev_alnum {
                normalized.push(' ');
            }
            while idx < chars.len() && (chars[idx].is_ascii_alphanumeric() || chars[idx] == '_') {
                normalized.push(chars[idx]);
                idx += 1;
            }
            prev_alnum = true;
        } else {
            normalized.push(c);
            prev_alnum = false;
            idx += 1;
        }
    }

    let full = sha256_hex(normalized.as_bytes());
    full[..24].to_string()
}

pub fn extract_units_from_file(
    rel_path: &str,
    lang: Language,
    source: &str,
) -> Vec<RawCallableUnit> {
    let raw_lines: Vec<&str> = source.lines().collect();
    let stripped = strip_comments_preserve_lines(source, lang);
    let clean_lines: Vec<&str> = stripped.lines().collect();

    if lang == Language::Python {
        return extract_python_units(rel_path, &raw_lines, &clean_lines);
    }
    extract_brace_units(rel_path, lang, &raw_lines, &clean_lines)
}

fn extract_brace_units(
    rel_path: &str,
    lang: Language,
    raw_lines: &[&str],
    clean_lines: &[&str],
) -> Vec<RawCallableUnit> {
    let mut units = Vec::new();
    let total = clean_lines.len().min(raw_lines.len());
    let mut i = 0usize;
    let mut pending_test_attr = false;

    while i < total {
        let trimmed = clean_lines[i].trim();

        // Skip Rust `#[cfg(test)] mod ... { ... }` blocks and `#[test]` functions
        if lang == Language::Rust {
            if trimmed.starts_with("#[cfg(test)]") {
                if let Some(end_mod) = skip_brace_block(clean_lines, i) {
                    i = end_mod + 1;
                    continue;
                }
            }
            if trimmed.starts_with("#[test]") || trimmed.contains("::test]") {
                pending_test_attr = true;
                i += 1;
                continue;
            }
        }

        if let Some(fn_name) = detect_brace_fn_header(trimmed, lang) {
            let start_line = i + 1; // 1-indexed
            if let Some(end_idx) = find_function_end_brace(clean_lines, i) {
                if pending_test_attr || fn_name.starts_with("test_") {
                    pending_test_attr = false;
                    i = end_idx + 1;
                    continue;
                }
                let end_line = end_idx + 1;
                let loc = end_line - start_line + 1;
                if loc >= 4 {
                    let sig = raw_lines[i].trim().trim_end_matches('{').trim().to_string();
                    let raw_slice = raw_lines[i..=end_idx].join("\n");
                    let clean_slice = &clean_lines[i..=end_idx];
                    let unit = build_unit(
                        rel_path,
                        &fn_name,
                        lang,
                        sig,
                        start_line,
                        end_line,
                        &raw_slice,
                        &raw_lines[i..=end_idx],
                        clean_slice,
                    );
                    units.push(unit);
                }
                pending_test_attr = false;
                i = end_idx + 1;
                continue;
            }
        }

        if !trimmed.is_empty() && !trimmed.starts_with("#[") {
            pending_test_attr = false;
        }
        i += 1;
    }

    units
}

fn skip_brace_block(clean_lines: &[&str], start_idx: usize) -> Option<usize> {
    find_function_end_brace(clean_lines, start_idx)
}

fn find_function_end_brace(clean_lines: &[&str], start_idx: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut opened = false;
    for (idx, line) in clean_lines.iter().enumerate().skip(start_idx) {
        if !opened && idx > start_idx + 12 {
            return None;
        }
        if !opened && line.trim_end().ends_with(';') {
            // Trait method signature without body
            return None;
        }
        for ch in line.chars() {
            if ch == '{' {
                depth += 1;
                opened = true;
            } else if ch == '}' && opened {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
        }
    }
    None
}

fn detect_brace_fn_header(trimmed: &str, lang: Language) -> Option<String> {
    match lang {
        Language::Rust => {
            // Matches `fn name(`, `pub fn name<`, `pub(crate) async fn name(`
            let pos = if trimmed.starts_with("fn ") {
                Some(3)
            } else {
                trimmed.find(" fn ").map(|p| p + 4)
            }?;
            let after = trimmed[pos..].trim_start();
            let name = take_ident(after)?;
            Some(name)
        }
        Language::Go => {
            if !trimmed.starts_with("func ") {
                return None;
            }
            let mut after = trimmed[5..].trim_start();
            // Receiver `func (s *Server) Handle(...)`
            if after.starts_with('(') {
                let close = after.find(')')?;
                after = after[close + 1..].trim_start();
            }
            let name = take_ident(after)?;
            Some(name)
        }
        Language::TypeScript | Language::JavaScript => {
            // `export async function foo(` or `function foo(`
            if let Some(pos) = if trimmed.starts_with("function ") {
                Some(9)
            } else {
                trimmed.find(" function ").map(|p| p + 10)
            } {
                let name = take_ident(trimmed[pos..].trim_start())?;
                return Some(name);
            }
            // Arrow function `export const foo = async (...) =>`
            for kw in ["export const ", "const ", "export let "] {
                if let Some(rest) = trimmed.strip_prefix(kw) {
                    if trimmed.contains("=>") {
                        if let Some(name) = take_ident(rest.trim_start()) {
                            return Some(name);
                        }
                    }
                }
            }
            None
        }
        Language::Python => None,
    }
}

fn extract_python_units(
    rel_path: &str,
    raw_lines: &[&str],
    clean_lines: &[&str],
) -> Vec<RawCallableUnit> {
    let mut units = Vec::new();
    let total = clean_lines.len().min(raw_lines.len());
    let mut i = 0usize;

    while i < total {
        let line = clean_lines[i];
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        let def_rest = trimmed
            .strip_prefix("def ")
            .or_else(|| trimmed.strip_prefix("async def "));

        if let Some(after_def) = def_rest {
            if let Some(fn_name) = take_ident(after_def.trim_start()) {
                if fn_name.starts_with("test_") {
                    i += 1;
                    continue;
                }
                let start_idx = i;
                let mut end_idx = i;
                let mut j = i + 1;
                // Advance past multi-line parameter list if needed
                let mut header_done = trimmed.contains(':');
                while j < total {
                    let cl = clean_lines[j];
                    let ct = cl.trim();
                    if ct.is_empty() {
                        j += 1;
                        continue;
                    }
                    if !header_done {
                        if ct.contains(':') {
                            header_done = true;
                        }
                        end_idx = j;
                        j += 1;
                        continue;
                    }
                    let cur_indent = cl.len() - cl.trim_start().len();
                    if cur_indent <= indent && !ct.starts_with(')') && !ct.starts_with(']') {
                        break;
                    }
                    end_idx = j;
                    j += 1;
                }

                let start_line = start_idx + 1;
                let end_line = end_idx + 1;
                if end_line - start_line + 1 >= 4 {
                    let sig = raw_lines[start_idx]
                        .trim()
                        .trim_end_matches(':')
                        .to_string();
                    let raw_slice = raw_lines[start_idx..=end_idx].join("\n");
                    let unit = build_unit(
                        rel_path,
                        &fn_name,
                        Language::Python,
                        sig,
                        start_line,
                        end_line,
                        &raw_slice,
                        &raw_lines[start_idx..=end_idx],
                        &clean_lines[start_idx..=end_idx],
                    );
                    units.push(unit);
                }
            }
        }
        i += 1;
    }

    units
}

#[allow(clippy::too_many_arguments)]
fn build_unit(
    rel_path: &str,
    fn_name: &str,
    lang: Language,
    signature: String,
    start_line: usize,
    end_line: usize,
    raw_slice: &str,
    raw_fn_lines: &[&str],
    clean_fn_lines: &[&str],
) -> RawCallableUnit {
    let structural_hash = compute_structural_hash(raw_slice, lang);
    let mut decision_points = 1usize; // Base cyclomatic path = 1
    let mut max_nesting = 0usize;
    let mut cur_nesting = 0usize;
    let mut error_paths = 0usize;
    let mut sinks = Vec::new();
    let mut guards = Vec::new();
    let mut call_set = BTreeSet::new();

    for (offset, (&raw_ln, &clean_ln)) in raw_fn_lines.iter().zip(clean_fn_lines.iter()).enumerate()
    {
        let line_no = start_line + offset;
        let ct = clean_ln.trim();
        if ct.is_empty() {
            continue;
        }

        // Nesting tracking
        if lang == Language::Python {
            let ind = (clean_ln.len() - clean_ln.trim_start().len()) / 4;
            if ind > max_nesting {
                max_nesting = ind;
            }
        } else {
            for ch in ct.chars() {
                if ch == '{' {
                    cur_nesting += 1;
                    if cur_nesting > max_nesting {
                        max_nesting = cur_nesting;
                    }
                } else if ch == '}' {
                    cur_nesting = cur_nesting.saturating_sub(1);
                }
            }
        }

        // Decision points
        for kw in [
            "if ", "if(", "else if", "elif ", "match ", "switch ", "case ", "for ", "while ",
            "loop ", "catch ", "except",
        ] {
            if contains_token_prefix(ct, kw) {
                decision_points += 1;
            }
        }
        decision_points += ct.matches("&&").count() + ct.matches("||").count();
        if lang == Language::Rust {
            decision_points += ct.matches("?;").count() + ct.matches("?)").count();
        }

        // Error / abort paths
        for err_pat in [
            "Err(",
            "return Err",
            "throw ",
            "raise ",
            "panic!(",
            "bail!(",
            "fmt.Errorf",
            "errors.New",
        ] {
            if ct.contains(err_pat) {
                error_paths += 1;
            }
        }
        if lang == Language::Rust && (ct.contains("?;") || ct.ends_with('?')) {
            error_paths += 1;
        }

        // Extract real branch guards for Causal Flight Simulator
        if guards.len() < 6 && offset > 0 {
            if let Some(guard) = extract_guard_at(line_no, raw_ln, raw_fn_lines, offset) {
                guards.push(guard);
            }
        }

        // Consequence & One-Way-Door sink detection (check raw_ln for SQL/domain strings, gated by non-comment ct)
        detect_sinks_on_line(line_no, raw_ln, ct, &mut sinks);

        // Extract called function identifiers (skip line 0 which is own declaration!)
        if offset > 0 {
            extract_calls_on_line(ct, fn_name, &mut call_set);
        }
    }

    RawCallableUnit {
        unit_id: format!("{rel_path}::{fn_name}"),
        name: fn_name.to_string(),
        file_path: rel_path.to_string(),
        language: lang,
        signature,
        start_line,
        end_line,
        loc: end_line - start_line + 1,
        structural_hash,
        decision_points,
        max_nesting: max_nesting.saturating_sub(1),
        error_paths,
        sinks,
        guards,
        raw_calls: call_set.into_iter().collect(),
    }
}

fn extract_guard_at(
    line_no: usize,
    raw_ln: &str,
    raw_fn_lines: &[&str],
    offset: usize,
) -> Option<BranchGuard> {
    let rt = raw_ln.trim();
    let cond = if let Some(rest) = rt.strip_prefix("if ") {
        Some(rest.trim_end_matches('{').trim_end_matches(':').trim())
    } else if let Some(rest) = rt.strip_prefix("else if ") {
        Some(rest.trim_end_matches('{').trim())
    } else if let Some(rest) = rt.strip_prefix("elif ") {
        Some(rest.trim_end_matches(':').trim())
    } else {
        rt.strip_prefix("match ")
            .map(|rest| rest.trim_end_matches('{').trim())
    }?;

    if cond.len() < 3 || cond.len() > 110 {
        return None;
    }

    // Look at the next 1..=3 non-empty lines inside the branch to summarize what happens!
    let mut body_lines = Vec::new();
    for next in raw_fn_lines.iter().skip(offset + 1).take(4) {
        let nt = next.trim();
        if nt.is_empty() || nt.starts_with("//") || nt.starts_with('#') {
            continue;
        }
        if nt == "}" {
            break;
        }
        body_lines.push(nt);
        if body_lines.len() == 2 {
            break;
        }
    }
    if body_lines.is_empty() {
        return None;
    }

    let outcome = truncate_clean(&body_lines.join(" "), 110);
    Some(BranchGuard {
        line: line_no,
        condition: cond.to_string(),
        outcome_summary: outcome,
    })
}

fn detect_sinks_on_line(
    line_no: usize,
    raw_ln: &str,
    clean_trimmed: &str,
    sinks: &mut Vec<ConsequenceSink>,
) {
    if clean_trimmed.is_empty() || sinks.len() >= 12 {
        return;
    }
    // Mask quoted string literals out of `clean_trimmed` for code-identifier sink matching
    // so help text or rule tables mentioning `"Command::new"` do not self-trigger!
    let code_only = mask_quoted_literals(clean_trimmed).to_ascii_lowercase();
    let raw_lower = raw_ln.to_ascii_lowercase();
    let snippet = truncate_clean(raw_ln.trim(), 96);

    // Code-token sinks (matched only outside string literals)
    let code_rules: &[(SinkCategory, &[&str])] = &[
        (
            SinkCategory::Financial,
            &[
                "charge_customer",
                "charge(",
                "refund",
                "payout",
                "invoice",
                "stripe_live",
                "stripe_webhook",
                "stripe_client",
                "payment",
                "debit_",
                "credit_balance",
                "transfer_funds",
                "amount_cents",
                "daily_rate_cents",
                "credit_cents",
                "commit_ledger_settlement",
            ],
        ),
        (
            SinkCategory::AuthCrypto,
            &[
                "verify_signature",
                "verify_webhook_hmac",
                "verify_token",
                "hmac",
                "jwt",
                "pbkdf2",
                "argon2",
                "chacha20",
                "decrypt",
                "encrypt",
                "authorize_",
                "api_key",
                "permission",
                "constant_time",
                "ct_eq",
            ],
        ),
        (
            SinkCategory::Persistence,
            &[
                "fs::write",
                "fs::remove_file",
                "fs::remove_dir_all",
                "remove_file(",
                "remove_dir_all(",
                "write_all(",
                "openoptions::new",
                "writefilesync",
                ".commit(",
                ".rollback(",
            ],
        ),
        (
            SinkCategory::ExternalNetwork,
            &[
                "webhook",
                "fetch(",
                "reqwest",
                "tcpstream",
                "tcplistener",
                "send_request",
                "post_json",
                "publish_event",
            ],
        ),
        (
            SinkCategory::Concurrency,
            &[
                "mutex",
                "rwlock",
                ".lock(",
                "atomic",
                "thread::spawn",
                "tokio::spawn",
                "promise.all",
                "acquire_idempotency_lock",
            ],
        ),
        (
            SinkCategory::ProcessExec,
            &["command::new", "subprocess.", "child_process", "os/exec"],
        ),
    ];

    // String-literal SQL DML & live endpoint protocol rules (require SQL/URL phrasing in code line)
    let literal_rules: &[(SinkCategory, &[&str])] = &[
        (
            SinkCategory::Persistence,
            &[
                "\"insert into ",
                "\"update ",
                "\"delete from ",
                "\"drop table ",
                "\"alter table ",
                "\"truncate table ",
            ],
        ),
        (SinkCategory::ExternalNetwork, &["\"https://", "'https://'"]),
    ];

    for (cat, patterns) in code_rules {
        if patterns.iter().any(|p| code_only.contains(p)) {
            let already_cat_on_line = sinks
                .iter()
                .any(|s| s.line == line_no && s.category == *cat);
            if !already_cat_on_line {
                sinks.push(ConsequenceSink {
                    category: *cat,
                    line: line_no,
                    snippet: snippet.clone(),
                });
            }
        }
    }

    for (cat, patterns) in literal_rules {
        if patterns.iter().any(|p| raw_lower.contains(p)) {
            let already_cat_on_line = sinks
                .iter()
                .any(|s| s.line == line_no && s.category == *cat);
            if !already_cat_on_line {
                sinks.push(ConsequenceSink {
                    category: *cat,
                    line: line_no,
                    snippet: snippet.clone(),
                });
            }
        }
    }
}

fn mask_quoted_literals(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' || b == b'`' {
            let q = b;
            out.push('"');
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                    continue;
                }
                if bytes[i] == q {
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push('"');
        } else {
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn extract_calls_on_line(clean_line: &str, self_name: &str, out: &mut BTreeSet<String>) {
    const KEYWORDS: &[&str] = &[
        "if",
        "else",
        "match",
        "for",
        "while",
        "loop",
        "return",
        "Some",
        "None",
        "Ok",
        "Err",
        "vec",
        "format",
        "println",
        "eprintln",
        "write",
        "writeln",
        "assert",
        "assert_eq",
        "debug_assert",
        "sizeof",
        "typeof",
        "switch",
        "case",
        "catch",
        "function",
        "def",
        "len",
        "range",
        "make",
        "new",
        "append",
        "String",
        "Vec",
        "Box",
        "Arc",
        "Mutex",
    ];

    let bytes = clean_line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let ident = &clean_line[start..i];
            let mut j = i;
            while j < bytes.len() && bytes[j] == b' ' {
                j += 1;
            }
            if j < bytes.len()
                && bytes[j] == b'('
                && ident != self_name
                && ident.len() >= 2
                && !KEYWORDS.contains(&ident)
            {
                out.insert(ident.to_string());
            }
        } else {
            i += 1;
        }
    }
}

fn take_ident(s: &str) -> Option<String> {
    let mut end = 0usize;
    for (idx, ch) in s.char_indices() {
        if idx == 0 {
            if !(ch.is_ascii_alphabetic() || ch == '_') {
                return None;
            }
        } else if !(ch.is_ascii_alphanumeric() || ch == '_') {
            break;
        }
        end = idx + ch.len_utf8();
    }
    if end == 0 {
        None
    } else {
        Some(s[..end].to_string())
    }
}

fn contains_token_prefix(haystack: &str, needle: &str) -> bool {
    for (idx, _) in haystack.match_indices(needle) {
        if idx == 0 {
            return true;
        }
        let prev = haystack.as_bytes()[idx - 1];
        if !(prev.is_ascii_alphanumeric() || prev == b'_') {
            return true;
        }
    }
    false
}

pub fn truncate_clean(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        return s.to_string();
    }
    let prefix: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    format!("{prefix}…")
}
