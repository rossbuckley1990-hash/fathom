# fathom

**Epistemic Sovereignty & Cognitive Debt Engine for the AI Engineering Era.**

> *Green unit tests prove code matched yesterday's assertions. They do not prove any living human still holds an accurate causal model of what happens at 3:00 a.m. when production goes off-script — or that your next AI prompt won't violate an unstated invariant.*  
> — Read the full thesis in [`WHY_I_BUILT_THIS.md`](WHY_I_BUILT_THIS.md)

[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-0ea5e9)](#architecture)
[![Unsafe Forbidden](https://img.shields.io/badge/unsafe-forbidden-10b981)](#architecture)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-64748b)](LICENSE)

`fathom` is a zero-dependency, full-stack software product (single static Rust binary + 5-view interactive Web Application + REST API + CLI + Git-native hash-chained ledger + CI Gate) that measures **Human Comprehension Coverage**, detects **Ghost Zones** and **Stale AST Drift**, restores human causal ownership via **AST-grounded Causal Flight Simulators**, and synthesizes **AI Pre-Flight Outcome Contracts**.

---

## Why Teams Need `fathom`

AI coding agents broke the 70-year coupling between *how fast code is written* and *how much of it the human team actually understands*.

$$\mathrm{CognitiveDebt}(u) = C(u) \times \frac{O(u)}{100} \times \bigl(1 - S(u)\bigr)$$

For every callable function $u$ across Rust (`.rs`), TypeScript/JavaScript (`.ts`, `.tsx`, `.js`, `.jsx`), Python (`.py`), and Go (`.go`), `fathom` computes:

1. **Consequence Weight $C(u) \in [0, 100]$**: Direct + **transitive call-graph propagation** of **One-Way-Door sinks** (`Financial / Ledger`, `Auth & Cryptography`, `State / DB Mutation`, `External Network / Webhook`, `Concurrency & Locks`, `Process / Shell Exec`) combined with upstream caller blast-radius fan-in.
2. **Opacity & Velocity Pressure $O(u) \in [0, 100]$**: Cyclomatic branch density, nesting depth, and `git log --numstat` forensics (flagging AI-scale commit bursts and churn-on-churn thrashing).
3. **Verified Human Sovereignty $S(u) \in \{0.0, 0.30, 1.0\}$**:
   - **`ANCHORED` ($S = 1.0$)**: Current comment/whitespace-invariant **Normalized Structural Hash** matches a verified **Sovereignty Receipt** in `.fathom/ledger.jsonl`.
   - **`STALE_DRIFT` ($S = 0.30$)**: A human previously understood an earlier version of $u$, **and a subsequent commit mutated its AST/logic** (`old_hash != current_hash`), creating dangerous false familiarity.
   - **`GHOST_ZONE` ($S = 0.0$, high $C \times O$)**: Load-bearing, side-effectful code running in production with zero verified human causal model on record.

---

## Quickstart (Zero Setup, Zero API Keys)

```bash
# Build release binary (~1s, zero external dependencies, 100% offline)
cargo build --release

# 1. Watch the 4-Act end-to-end outcome loop on a realistic hypergrowth codebase:
./target/release/fathom demo

# 2. Launch the full 5-View Interactive Web Product on the demo workspace (or pass any repo path!):
./target/release/fathom serve --demo
# -> Open http://127.0.0.1:7979

# 3. Scan any real repository on your machine:
./target/release/fathom scan /path/to/your/repo
```

---

## The Full Product (`fathom serve`)

Running `fathom serve [path]` launches a live local server (`http://127.0.0.1:7979`) with five integrated views wired directly to your filesystem and `.fathom/` Git-native ledger:

1. **Command Deck & Consequence × Opacity Topography**: Live Sovereignty Index (`0–100`), Comprehension Coverage `%`, Ghost-Zone & Stale-Drift KPIs, interactive SVG scatter map of every function in the repository, and priority triage queue.
2. **Codebase X-Ray & Source Inspector**: Filter symbols by ownership state or One-Way-Door category; inspect live line-numbered source code highlighting exact sink lines and branch guards alongside upstream callers and downstream callees.
3. **Causal Flight Simulator**: Synthesizes deterministic 3-stage counterfactual branch, sink, and blast-radius probes straight from your real source AST. Achieving 100% causal lock mints a **SHA-256 Hash-Chained Sovereignty Receipt** in `.fathom/ledger.jsonl` and promotes your 1-sentence **Human Reality Invariant** into `.fathom/invariants.json`.
4. **AI Pre-Flight Contract Studio**: Select any file, symbol, or intent before prompting Gemini, Claude Code, Cursor, or Codex to generate a copy-ready Markdown **Outcome Contract** surfacing every One-Way Door, caller dependency, Ghost-Zone warning, and protected Human Invariant in scope.
5. **Sovereignty Ledger & CI Gate Simulator**: Inspect the tamper-evident receipt chain, see live hash matches vs. AST drift, tune policy thresholds, and generate drop-in GitHub Actions workflows.

---

## CLI Reference

```bash
# Sound repository Cognitive Debt & Ghost Zones (human table or --json)
fathom scan .
fathom scan . --json

# Generate a grounded AI Pre-Flight Outcome Contract before an agent edits a file/function
fathom brief src/billing.rs --intent "Add idempotent partial refunds"

# Record a tacit Human Reality Invariant for AI tools & teammates to respect
fathom invariant "src/billing.rs::process_stripe_webhook" \
  "Stripe retries webhooks for 72h; never release idempotency lock before settlement commits."

# Run an interactive terminal Causal Flight Check & mint a hash-chained receipt
fathom challenge "src/billing.rs::process_stripe_webhook" --author ross

# Enforce Human Epistemic Sovereignty in CI / pre-push hooks (exits 1 on violation)
fathom gate . --min-sovereignty 65 --max-critical-ghosts 0 --max-stale-drift 0
```

### GitHub Actions Gate Integration

Commit `.fathom/ledger.jsonl` and `.fathom/invariants.json` directly into Git alongside your source code. Formatting changes (`cargo fmt`, `prettier`, `black`, `gofmt`) and comment edits **never** invalidate receipts; real logic mutations on critical paths automatically flag `STALE_DRIFT` so reviewers re-anchor before merge:

```yaml
- name: Enforce Human Epistemic Sovereignty
  run: fathom gate --min-sovereignty 65 --max-critical-ghosts 0 --max-stale-drift 0
```

---

## Architecture

- **Zero External Crates** (`Cargo.toml` `[dependencies]` is completely empty) and `#![forbid(unsafe_code)]` across library and binary.
- [`src/scanner.rs`](src/scanner.rs): Comment-and-string-aware lexical analyzer for Rust, TypeScript/JS, Python, and Go; Normalized Structural SHA-256 hashing; One-Way-Door & branch-guard extraction.
- [`src/git_intel.rs`](src/git_intel.rs): `git log --numstat` commit-burst, churn-thrashing, and author concentration forensics.
- [`src/graph.rs`](src/graph.rs): Cross-file symbol call resolution, BFS blast-radius & transitive sink propagation, and Cognitive Debt scoring.
- [`src/ledger.rs`](src/ledger.rs): Tamper-evident SHA-256 hash-chained `.fathom/ledger.jsonl` receipts & `.fathom/invariants.json` registry.
- [`src/simulator.rs`](src/simulator.rs): Deterministic AST-grounded 3-stage Causal Flight Simulator & verification oracle.
- [`src/brief.rs`](src/brief.rs): Pre-Flight AI Outcome Contract synthesizer & CI Sovereignty Gate evaluator.
- [`src/server.rs`](src/server.rs) + [`web/app.html`](web/app.html): Multi-threaded local HTTP REST API & embedded 5-view Web Product.

## License

Dual-licensed under [MIT](LICENSE) or Apache-2.0.
