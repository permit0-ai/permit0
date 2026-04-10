#![forbid(unsafe_code)]

use std::process::Command;

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
