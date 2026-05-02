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
        decision.is_null()
            || decision == "allow"
            || decision == "ask"
            || decision == "deny",
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
