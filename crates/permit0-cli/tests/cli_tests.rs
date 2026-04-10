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
fn check_stripe_low_charge_allow() {
    let input = r#"{"tool_name":"http","parameters":{"method":"POST","url":"https://api.stripe.com/v1/charges","body":{"amount":50,"currency":"usd"}}}"#;
    let output = permit0_bin()
        .args(["check", "--input", input])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ALLOW"), "expected ALLOW, got: {stdout}");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn check_stripe_crypto_deny() {
    let input = r#"{"tool_name":"http","parameters":{"method":"POST","url":"https://api.stripe.com/v1/charges","body":{"amount":1000,"currency":"btc"}}}"#;
    let output = permit0_bin()
        .args(["check", "--input", input])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DENY"), "expected DENY, got: {stdout}");
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn check_bash_safe_command_allow() {
    let input = r#"{"tool_name":"bash","parameters":{"command":"echo hello"}}"#;
    let output = permit0_bin()
        .args(["check", "--input", input])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ALLOW"), "expected ALLOW, got: {stdout}");
}

#[test]
fn check_bash_device_write_deny() {
    let input = r#"{"tool_name":"bash","parameters":{"command":"echo data > /dev/sda"}}"#;
    let output = permit0_bin()
        .args(["check", "--input", input])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DENY"), "expected DENY, got: {stdout}");
    assert_eq!(output.status.code(), Some(2));
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
fn pack_validate_stripe() {
    let output = permit0_bin()
        .args(["pack", "validate", "packs/stripe"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("valid"));
}

#[test]
fn pack_validate_all_packs() {
    for pack in ["packs/stripe", "packs/bash", "packs/gmail"] {
        let output = permit0_bin()
            .args(["pack", "validate", pack])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "pack validate failed for {pack}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn pack_test_stripe() {
    let output = permit0_bin()
        .args(["pack", "test", "packs/stripe"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "pack test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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
    assert!(stdout.contains("payments.charge"));
}

// ── Phase 16: Host Adapter Tests ──

#[test]
fn hook_with_safe_command() {
    let input = r#"{"tool_name":"bash","tool_input":{"command":"ls -la"}}"#;
    let mut child = permit0_bin()
        .args(["hook"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "hook failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        parsed["decision"] == "allow" || parsed["decision"] == "ask_user",
        "expected allow or ask_user, got: {stdout}"
    );
}

#[test]
fn hook_with_device_write_blocks() {
    // Device write is a known deny case from the bash pack
    let input = r#"{"tool_name":"bash","tool_input":{"command":"echo data > /dev/sda"}}"#;
    let mut child = permit0_bin()
        .args(["hook"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        parsed["decision"], "block",
        "expected block for device write, got: {stdout}"
    );
}

#[test]
fn gateway_processes_jsonl() {
    let input = r#"{"tool_name":"bash","parameters":{"command":"echo hello"}}"#;
    let mut child = permit0_bin()
        .args(["gateway"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "gateway failed: {}", String::from_utf8_lossy(&output.stderr));
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
    assert!(output.status.success(), "pack new failed: {}", String::from_utf8_lossy(&output.stderr));

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
    let input = r#"{"tool_name":"http","parameters":{"method":"POST","url":"https://api.stripe.com/v1/charges","body":{"amount":100,"currency":"usd"}}}"#;
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
