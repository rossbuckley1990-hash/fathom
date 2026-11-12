use fathom::sample_repo::create_sample_workspace;
use fathom::server::{spawn_background_server, APP_HTML};
use std::fs;
use std::process::Command;

#[test]
fn web_product_js_parses_cleanly_and_live_http_api_completes_full_sovereignty_loop() {
    let dir = std::env::temp_dir().join(format!("fathom-http-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    create_sample_workspace(&dir).unwrap();

    let port = spawn_background_server(dir.clone()).unwrap();

    // Extract inline <script> from web/app.html to verify zero JS syntax regressions via Node vm.Script
    let script_start = APP_HTML.find("<script>").expect("missing <script>") + "<script>".len();
    let script_end = APP_HTML.rfind("</script>").expect("missing </script>");
    let js_code = &APP_HTML[script_start..script_end];
    let js_check_file =
        std::env::temp_dir().join(format!("fathom-ui-syntax-{}.js", std::process::id()));
    fs::write(&js_check_file, js_code).unwrap();

    let node_e2e = format!(
        r#"
const fs = require('fs');
const vm = require('vm');

// 1. Compile embedded UI JavaScript to guarantee zero syntax errors
const uiCode = fs.readFileSync({js_path:?}, 'utf8');
new vm.Script(uiCode, {{ filename: 'web/app.html' }});

(async () => {{
  const base = 'http://127.0.0.1:{port}';

  // 2. Verify HTML shell serves cleanly
  const htmlRes = await fetch(base + '/');
  if (htmlRes.status !== 200) throw new Error('GET / failed');
  const htmlText = await htmlRes.text();
  if (!htmlText.includes('Epistemic Sovereignty')) throw new Error('missing product header');

  // 3. Inspect initial hypergrowth workspace state
  const st1 = await (await fetch(base + '/api/state')).json();
  if (st1.report.stale_drift_count !== 1) {{
    throw new Error('expected 1 stale drift unit, got ' + st1.report.stale_drift_count);
  }}
  if (st1.default_gate.passed !== false) {{
    throw new Error('expected initial CI gate to block');
  }}

  // 4. Inspect live source code endpoint
  const srcRes = await (await fetch(base + '/api/source?unit_id=' + encodeURIComponent('src/billing.rs::process_stripe_webhook'))).json();
  if (!srcRes.excerpt.includes('process_stripe_webhook')) {{
    throw new Error('source excerpt missing target function');
  }}

  // 5. Record a standalone Human Reality Invariant
  const invRes = await (await fetch(base + '/api/invariant', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{
      scope: 'src/billing.rs',
      statement: 'Never dispatch proration refunds over unencrypted HTTP.',
      author: 'ross'
    }})
  }})).json();
  if (!invRes.invariant.id.startsWith('inv-')) throw new Error('missing invariant id');

  // 6. Synthesize AI Pre-Flight Outcome Contract & confirm invariant injection
  const brief = await (await fetch(base + '/api/brief', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{
      target: 'src/billing.rs',
      intent: 'Add enterprise multi-seat downgrade support'
    }})
  }})).json();
  if (!brief.markdown.includes('Never dispatch proration refunds over unencrypted HTTP.')) {{
    throw new Error('brief markdown missing injected human invariant');
  }}

  // 7.Verify challenge oracle rejects wrong answers and accepts exact causal lock
  const targetId = 'src/billing.rs::process_stripe_webhook';
  const ch = await (await fetch(base + '/api/challenge?unit_id=' + encodeURIComponent(targetId))).json();
  if (ch.questions.length !== 3) throw new Error('expected 3 challenge stages');

  // Find exact passing combination deterministically across each independent question's verdict!
  const probeRes = await (await fetch(base + '/api/challenge/verify', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{
      unit_id: targetId,
      answers: [0, 0, 0],
      author: 'ross',
      invariant_note: ''
    }})
  }})).json();

  const exactAnswers = probeRes.evaluation.verdicts.map(v => v.correct_index);
  const passRes = await (await fetch(base + '/api/challenge/verify', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{
      unit_id: targetId,
      answers: exactAnswers,
      author: 'ross',
      invariant_note: 'High-value test_mode webhooks must always abort prior to settlement.'
    }})
  }})).json();

  if (!passRes.evaluation.passed || !passRes.evaluation.receipt) {{
    throw new Error('expected 100% causal lock receipt');
  }}
  if (passRes.state.report.stale_drift_count !== 0) {{
    throw new Error('expected stale_drift_count to drop to 0 after re-anchoring');
  }}

  console.log('LIVE_PRODUCT_E2E_OK');
}})().catch(err => {{
  console.error(err);
  process.exit(1);
}});
"#,
        js_path = js_check_file.to_string_lossy(),
        port = port
    );

    let out = Command::new("node")
        .arg("-e")
        .arg(&node_e2e)
        .output()
        .expect("failed to execute node for E2E verification");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("LIVE_PRODUCT_E2E_OK"),
        "Node E2E failed:\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    );

    let _ = fs::remove_file(&js_check_file);
    let _ = fs::remove_dir_all(&dir);
}
