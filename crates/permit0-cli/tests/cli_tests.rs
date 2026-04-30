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
    let output = permit0_bin()
        .args(["pack", "validate", "packs/email"])
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
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "hook failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Claude Code PreToolUse hook output (post 7de8a2d) uses the nested
    // `hookSpecificOutput.permissionDecision` shape with values
    // "allow" | "deny" | "ask" | "defer".
    let decision = &parsed["hookSpecificOutput"]["permissionDecision"];
    assert!(
        decision == "allow" || decision == "ask",
        "expected allow or ask, got: {stdout}"
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
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
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
    // Use a temp dir to avoid polluting the workspace
    let tmp = std::env::temp_dir().join("permit0_test_pack_new");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("packs")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_permit0"))
        .current_dir(&tmp)
        .args(["pack", "new", "test_service"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "pack new failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify scaffold files exist
    assert!(tmp.join("packs/test_service/normalizers/test_service.normalizer.yaml").exists());
    assert!(tmp.join("packs/test_service/risk_rules/test_service.risk_rule.yaml").exists());
    assert!(tmp.join("packs/test_service/fixtures/test_service_basic.fixture.yaml").exists());
    assert!(tmp.join("packs/test_service/README.md").exists());

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn serve_help() {
    let output = permit0_bin()
        .args(["serve", "--help"])
        .output()
        .unwrap();
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
