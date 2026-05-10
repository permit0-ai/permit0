#![forbid(unsafe_code)]

use std::io::Write;
use std::process::{Command, Stdio};

fn permit0_bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_permit0"));
    // Run from the workspace root so packs/ and profiles/ are found
    cmd.current_dir(env!("CARGO_MANIFEST_DIR").to_string() + "/../..");
    cmd
}

#[test]
fn help_exits_zero() {
    let output = permit0_bin().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Agent safety"));
}

#[test]
fn check_gmail_send_normalizes() {
    let input = r#"{"tool_name":"gmail_send","parameters":{"to":"bob@external.com","subject":"Hi","body":"ok"}}"#;
    let output = permit0_bin()
        .args(["check", "--input", input])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("email.send"),
        "expected email.send action, got: {stdout}"
    );
    assert!(
        stdout.contains("gmail"),
        "expected gmail channel, got: {stdout}"
    );
}

#[test]
fn check_outlook_send_normalizes() {
    let input = r#"{"tool_name":"outlook_send","parameters":{"to":"bob@external.com","subject":"Hi","body":"ok"}}"#;
    let output = permit0_bin()
        .args(["check", "--input", input])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("email.send"),
        "expected email.send action, got: {stdout}"
    );
    assert!(
        stdout.contains("outlook"),
        "expected outlook channel, got: {stdout}"
    );
}

#[test]
fn check_unknown_tool_human() {
    let input = r#"{"tool_name":"unknown_widget","parameters":{"x":1}}"#;
    let output = permit0_bin()
        .args(["check", "--input", input])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("HUMAN"), "expected HUMAN, got: {stdout}");
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn pack_validate_email() {
    // Email pack moved to packs/permit0/email/ in PR 3 of the pack
    // taxonomy refactor. Try the owner-namespaced location first; fall
    // back to the legacy flat path for back-compat with checkouts that
    // haven't merged the move yet.
    let pack_path = if std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .map(|root| root.join("packs/permit0/email").is_dir())
        .unwrap_or(false)
    {
        "packs/permit0/email"
    } else {
        "packs/email"
    };
    let output = permit0_bin()
        .args(["pack", "validate", pack_path])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "pack validate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("valid"));
}

#[test]
fn calibrate_validate_fintech() {
    let output = permit0_bin()
        .args(["calibrate", "validate", "--profile", "fintech"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("passes all guardrails"));
}

#[test]
fn calibrate_validate_healthtech() {
    let output = permit0_bin()
        .args(["calibrate", "validate", "--profile", "healthtech"])
        .output()
        .unwrap();
    assert!(output.status.success());
}

#[test]
fn calibrate_diff_fintech() {
    let output = permit0_bin()
        .args(["calibrate", "diff", "--profile", "fintech"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FINANCIAL"));
}

#[test]
fn hook_with_safe_email() {
    let input = r#"{"tool_name":"gmail_send","tool_input":{"to":"bob@external.com","subject":"Hi","body":"ok"}}"#;
    let mut child = permit0_bin()
        .args(["hook"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "hook failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // PreToolUse envelope: hookSpecificOutput.permissionDecision is one of
    // allow / deny / ask, or absent for `defer` (let Claude Code decide).
    let decision = &parsed["hookSpecificOutput"]["permissionDecision"];
    assert!(
        decision.is_null() || decision == "allow" || decision == "ask" || decision == "deny",
        "unexpected hook output: {stdout}",
    );
}

#[test]
fn gateway_processes_jsonl() {
    let input = r#"{"tool_name":"gmail_send","parameters":{"to":"bob@external.com","subject":"Hi","body":"ok"}}"#;
    let mut child = permit0_bin()
        .args(["gateway"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "gateway failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(parsed["permission"].is_string());
    assert!(parsed["action_type"].is_string());
}

#[test]
fn pack_new_creates_scaffold() {
    // PR 7 of the pack taxonomy refactor changed `pack new` to:
    //   - require a `<owner>/<name>` argument
    //   - copy the in-tree packs/_template/ and substitute markers
    //   - place the result at packs/<owner>/<name>/
    //
    // The test runs in a temp dir so it doesn't pollute the workspace.
    // Symlink the workspace's packs/_template into the temp dir so the
    // scaffolder can find it.
    let tmp = std::env::temp_dir().join("permit0_test_pack_new");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("packs")).unwrap();

    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let template_src = workspace_root.join("packs/_template");
    let template_dst = tmp.join("packs/_template");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&template_src, &template_dst).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&template_src, &template_dst).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_permit0"))
        .current_dir(&tmp)
        .args(["pack", "new", "alice/test_service"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "pack new failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify scaffolded files exist (schema v2 + per-channel layout).
    assert!(
        tmp.join("packs/alice/test_service/pack.yaml").exists(),
        "pack.yaml missing"
    );
    assert!(
        tmp.join("packs/alice/test_service/normalizers/test_service/_channel.yaml")
            .exists(),
        "_channel.yaml missing"
    );
    assert!(
        tmp.join("packs/alice/test_service/normalizers/test_service/aliases.yaml")
            .exists(),
        "aliases.yaml missing"
    );
    assert!(
        tmp.join("packs/alice/test_service/normalizers/test_service/TODO_VERB.yaml")
            .exists(),
        "TODO_VERB.yaml stub missing"
    );
    assert!(
        tmp.join("packs/alice/test_service/risk_rules/TODO_VERB.yaml")
            .exists(),
        "risk_rules TODO_VERB.yaml stub missing"
    );

    // pack.yaml should contain the substituted owner / pack name.
    let pack_yaml =
        std::fs::read_to_string(tmp.join("packs/alice/test_service/pack.yaml")).unwrap();
    assert!(
        pack_yaml.contains(r#"permit0_pack: "alice/test_service""#),
        "permit0_pack not substituted: {pack_yaml}"
    );
    assert!(
        pack_yaml.contains("name: test_service"),
        "name not substituted: {pack_yaml}"
    );

    // Bad arg shape errors out cleanly.
    let bad = Command::new(env!("CARGO_BIN_EXE_permit0"))
        .current_dir(&tmp)
        .args(["pack", "new", "no_slash_here"])
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("expected `<owner>/<name>`"),
        "expected usage hint: stderr={}",
        String::from_utf8_lossy(&bad.stderr)
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn serve_help() {
    let output = permit0_bin().args(["serve", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--port"));
    assert!(stdout.contains("--ui"));
}

#[test]
fn check_output_format() {
    let input = r#"{"tool_name":"gmail_send","parameters":{"to":"bob@external.com","subject":"Hi","body":"ok"}}"#;
    let output = permit0_bin()
        .args(["check", "--input", input])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Verify output structure
    assert!(stdout.contains("Permission:"));
    assert!(stdout.contains("Source:"));
    assert!(stdout.contains("Action:"));
    assert!(stdout.contains("Channel:"));
    assert!(stdout.contains("NormHash:"));
}

#[test]
fn invalid_json_fails() {
    let output = permit0_bin()
        .args(["check", "--input", "not-json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

// ── Codex hook integration tests ─────────────────────────────────────
//
// Codex's PreToolUse contract treats a non-zero exit, malformed stdout,
// or any output containing `permissionDecision: "allow"` as fail-open
// (the tool runs anyway with a warning). These tests run the full
// permit0 binary as a subprocess to verify end-to-end:
//
// - Empty stdout for "no objection" (allow / defer / shadow paths)
// - Valid deny envelope for blocks (unknown deny, malformed stdin,
//   remote daemon down)
// - Never emits the forbidden `"permissionDecision":"allow"` form
//
// Process-level tests are essential here because the failure modes are
// at the I/O boundary, not inside the type system.

const CODEX_UNKNOWN_TOOL_JSON: &str = r#"{
    "session_id": "codex-test-1",
    "transcript_path": "/tmp/codex.jsonl",
    "cwd": "/tmp",
    "hook_event_name": "PreToolUse",
    "model": "gpt-5.4",
    "turn_id": "turn-1",
    "tool_name": "completely_unknown_widget",
    "tool_use_id": "call-1",
    "tool_input": {}
}"#;

const CODEX_GMAIL_SEND_JSON: &str = r#"{
    "session_id": "codex-test-1",
    "transcript_path": "/tmp/codex.jsonl",
    "cwd": "/tmp",
    "hook_event_name": "PreToolUse",
    "model": "gpt-5.4",
    "turn_id": "turn-2",
    "tool_name": "mcp__permit0-gmail__gmail_send",
    "tool_use_id": "call-2",
    "tool_input": {"to": "bob@external.com", "subject": "Hi", "body": "ok"}
}"#;

fn run_codex_hook(args: &[&str], stdin: &str) -> std::process::Output {
    let mut child = permit0_bin()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn codex_hook_unknown_defer_produces_empty_stdout() {
    // Codex defer/allow contract: zero stdout bytes = "no objection".
    // Any other output (even an empty-string println with a newline)
    // may trigger Codex's invalid-JSON warning path.
    let output = run_codex_hook(
        &["hook", "--client", "codex", "--unknown", "defer"],
        CODEX_UNKNOWN_TOOL_JSON,
    );
    assert!(
        output.status.success(),
        "hook exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "Codex defer MUST produce zero stdout bytes, got: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn codex_hook_unknown_deny_produces_deny_envelope() {
    let output = run_codex_hook(
        &["hook", "--client", "codex", "--unknown", "deny"],
        CODEX_UNKNOWN_TOOL_JSON,
    );
    assert!(
        output.status.success(),
        "hook exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout must be valid JSON for deny: err={e}, stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(
        parsed["hookSpecificOutput"]["hookEventName"], "PreToolUse",
        "deny envelope must declare PreToolUse",
    );
    assert_eq!(
        parsed["hookSpecificOutput"]["permissionDecision"], "deny",
        "Codex --unknown deny must produce permissionDecision: deny",
    );
    assert!(
        parsed["hookSpecificOutput"]["permissionDecisionReason"].is_string(),
        "deny envelope must include a reason",
    );
}

#[test]
fn codex_hook_malformed_stdin_fails_closed() {
    // CRITICAL: in Codex, fail-open semantics mean a malformed stdin
    // (which `?`-style error propagation would surface as exit 1) would
    // let the tool execute. The fail-closed wrapper must convert this
    // into a deny envelope or exit 2 (also a Codex block).
    let output = run_codex_hook(&["hook", "--client", "codex"], "not valid json");
    if output.status.success() {
        // Preferred: structured deny envelope.
        let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)
            .expect("malformed stdin must produce valid JSON");
        assert_eq!(
            parsed["hookSpecificOutput"]["permissionDecision"],
            "deny",
            "malformed stdin must fail closed to deny, got: {}",
            String::from_utf8_lossy(&output.stdout),
        );
    } else {
        // Acceptable fallback: exit 2 (Codex treats this as a block).
        // Bare exit 1 fails open in Codex and is a security bug.
        assert_eq!(
            output.status.code(),
            Some(2),
            "Codex fail-closed must use exit 2, got {:?} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

#[test]
fn codex_hook_empty_stdin_fails_closed() {
    // Zero-byte stdin is another shape of "input we can't parse" — Codex
    // would fail open if the hook just exited 1. Same fail-closed
    // contract as malformed JSON: either a structured deny envelope on
    // stdout (exit 0) or exit code 2 with stderr reason.
    let output = run_codex_hook(&["hook", "--client", "codex"], "");
    if output.status.success() {
        let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)
            .expect("empty stdin must produce a parseable deny envelope");
        assert_eq!(
            parsed["hookSpecificOutput"]["permissionDecision"],
            "deny",
            "empty stdin must fail closed to deny, got: {}",
            String::from_utf8_lossy(&output.stdout),
        );
    } else {
        assert_eq!(
            output.status.code(),
            Some(2),
            "Codex fail-closed must use exit 2 for empty stdin, got {:?} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

#[test]
fn codex_hook_remote_daemon_down_fails_closed() {
    // Pointed at an unreachable port → transport error. The remote
    // error mapper returns HookOutput::ask, which the Codex emitter
    // converts to a deny envelope (Codex has no `ask`, so HITL/transport
    // failures fall through to deny).
    let output = run_codex_hook(
        &[
            "hook",
            "--client",
            "codex",
            "--remote",
            "http://127.0.0.1:1",
        ],
        CODEX_GMAIL_SEND_JSON,
    );
    assert!(
        output.status.success(),
        "hook exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "remote-down stdout must be valid JSON: err={e}, stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(
        parsed["hookSpecificOutput"]["permissionDecision"],
        "deny",
        "Codex must deny when daemon is unreachable, got: {}",
        String::from_utf8_lossy(&output.stdout),
    );
    let reason = parsed["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or_default();
    assert!(
        reason.contains("remote unavailable"),
        "deny reason must explain transport failure, got: {reason}",
    );
}

#[test]
fn codex_hook_shadow_produces_empty_stdout() {
    // Shadow mode forces HookOutput::allow internally. Under Codex,
    // that converts to zero stdout bytes. The shadow log goes to
    // stderr; stdout must be empty so Codex sees "no objection".
    let output = run_codex_hook(
        &[
            "hook",
            "--client",
            "codex",
            "--shadow",
            "--unknown",
            "defer",
        ],
        CODEX_GMAIL_SEND_JSON,
    );
    assert!(
        output.status.success(),
        "hook exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "Codex shadow allow must be zero stdout bytes, got: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn codex_hook_minimal_claude_payload_does_not_error() {
    // Codex back-compat: passing a Claude-style minimal payload through
    // `--client codex` must not error (HookInput has all Codex fields
    // optional). The output should be either empty (defer/allow) or a
    // valid deny envelope.
    let claude_minimal = r#"{"tool_name":"completely_unknown_widget","tool_input":{}}"#;
    let output = run_codex_hook(
        &["hook", "--client", "codex", "--unknown", "defer"],
        claude_minimal,
    );
    assert!(
        output.status.success(),
        "minimal payload must not error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Defer + Codex = zero stdout bytes.
    assert!(
        output.stdout.is_empty(),
        "minimal payload + defer must yield empty stdout, got: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn codex_hook_never_emits_permission_decision_allow() {
    // Codex's strictest invariant: stdout must NEVER contain
    // `"permissionDecision":"allow"` — Codex explicitly rejects this
    // form and would fail open with a warning. Verify across the most
    // bug-prone modes (shadow, unknown allow, unknown defer, deny).
    let combos: &[(&[&str], &str)] = &[
        (
            &["hook", "--client", "codex", "--unknown", "defer"],
            CODEX_GMAIL_SEND_JSON,
        ),
        (
            &["hook", "--client", "codex", "--unknown", "allow"],
            CODEX_UNKNOWN_TOOL_JSON,
        ),
        (
            &["hook", "--client", "codex", "--unknown", "deny"],
            CODEX_UNKNOWN_TOOL_JSON,
        ),
        (
            &[
                "hook",
                "--client",
                "codex",
                "--shadow",
                "--unknown",
                "defer",
            ],
            CODEX_GMAIL_SEND_JSON,
        ),
    ];
    for (args, stdin) in combos {
        let output = run_codex_hook(args, stdin);
        // Empty stdout is the allow path; valid deny JSON is the
        // block path. Either way, the literal forbidden substring
        // must not appear.
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.is_empty() {
            // Parse and structurally check — never substring.
            let parsed: serde_json::Value =
                serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
                    panic!("non-empty stdout must be JSON for args={args:?}: {e}, stdout={stdout}")
                });
            assert_ne!(
                parsed["hookSpecificOutput"]["permissionDecision"], "allow",
                "Codex must NEVER emit permissionDecision: allow (args={args:?}), got: {stdout}",
            );
        }
    }
}
