/**
 * Tests for permit0 Node.js bindings — mirrors Rust integration tests.
 */

import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { describe, it, expect, beforeAll } from "vitest";
import { createRequire } from "module";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const { Engine, EngineBuilder } = require("../index.js");

const PACKS_DIR = path.resolve(__dirname, "..", "..", "..", "packs");
const STRIPE_NORM_YAML = path.join(
  PACKS_DIR,
  "stripe",
  "normalizers",
  "charges_create.yaml"
);
const STRIPE_RISK_YAML = path.join(
  PACKS_DIR,
  "stripe",
  "risk_rules",
  "charge.yaml"
);
const BASH_NORM_YAML = path.join(
  PACKS_DIR,
  "bash",
  "normalizers",
  "shell.yaml"
);
const BASH_RISK_YAML = path.join(
  PACKS_DIR,
  "bash",
  "risk_rules",
  "shell.yaml"
);

// ── Engine.fromPacks tests ──

describe("Engine.fromPacks", () => {
  let engine;

  beforeAll(() => {
    engine = Engine.fromPacks(PACKS_DIR);
  });

  it("creates an engine", () => {
    expect(engine).toBeDefined();
  });

  it("allows safe bash commands", () => {
    const result = engine.getPermission("bash", { command: "ls -la" });
    expect(result.permission).toBe("Allow");
    expect(result.source).toBe("Scorer");
  });

  it("denies dangerous bash commands", () => {
    const result = engine.getPermission("bash", {
      command: "echo data > /dev/sda",
    });
    expect(result.permission).toBe("Deny");
    expect(result.riskScore).toBeDefined();
    expect(result.riskScore.blocked).toBe(true);
  });

  it("allows low-value stripe charges", () => {
    const result = engine.getPermission("http", {
      method: "POST",
      url: "https://api.stripe.com/v1/charges",
      body: { amount: 50, currency: "usd" },
    });
    expect(result.permission).toBe("Allow");
    expect(result.riskScore).toBeDefined();
    expect(result.riskScore.tier).toBe("Minimal");
  });

  it("denies crypto currency charges (gate)", () => {
    const result = engine.getPermission("http", {
      method: "POST",
      url: "https://api.stripe.com/v1/charges",
      body: { amount: 1000, currency: "btc" },
    });
    expect(result.permission).toBe("Deny");
    expect(result.riskScore).toBeDefined();
    expect(result.riskScore.blocked).toBe(true);
  });

  it("returns human-in-the-loop for unknown tools", () => {
    const result = engine.getPermission("unknown_tool", { some: "data" });
    expect(result.permission).toBe("Human");
  });
});

// ── EngineBuilder tests ──

describe("EngineBuilder", () => {
  it("builds engine from YAML files", () => {
    const builder = new EngineBuilder();
    builder.installNormalizerYaml(fs.readFileSync(STRIPE_NORM_YAML, "utf8"));
    builder.installNormalizerYaml(fs.readFileSync(BASH_NORM_YAML, "utf8"));
    builder.installRiskRuleYaml(fs.readFileSync(STRIPE_RISK_YAML, "utf8"));
    builder.installRiskRuleYaml(fs.readFileSync(BASH_RISK_YAML, "utf8"));

    const engine = builder.build();
    expect(engine).toBeDefined();

    const result = engine.getPermission("bash", { command: "ls" });
    expect(result.permission).toBe("Allow");
  });

  it("throws after builder consumed", () => {
    const builder = new EngineBuilder();
    builder.installNormalizerYaml(fs.readFileSync(BASH_NORM_YAML, "utf8"));
    builder.installRiskRuleYaml(fs.readFileSync(BASH_RISK_YAML, "utf8"));
    builder.build();

    expect(() => builder.build()).toThrow("already consumed");
  });
});

// ── DecisionResult structure tests ──

describe("DecisionResult", () => {
  let engine;

  beforeAll(() => {
    engine = Engine.fromPacks(PACKS_DIR);
  });

  it("has normAction with correct fields", () => {
    const result = engine.getPermission("bash", { command: "ls" });
    expect(result.normAction).toBeDefined();
    expect(typeof result.normAction.actionType).toBe("string");
    expect(typeof result.normAction.channel).toBe("string");
    expect(typeof result.normAction.normHash).toBe("string");
    expect(result.normAction.normHash.length).toBe(16);
  });

  it("has riskScore with correct fields", () => {
    // Use a unique command to avoid hitting policy cache from earlier tests
    const result = engine.getPermission("bash", { command: "cat /etc/hostname" });
    expect(result.riskScore).toBeDefined();
    expect(typeof result.riskScore.raw).toBe("number");
    expect(typeof result.riskScore.score).toBe("number");
    expect(result.riskScore.raw).toBeGreaterThanOrEqual(0);
    expect(result.riskScore.raw).toBeLessThanOrEqual(1);
    expect(result.riskScore.score).toBeGreaterThanOrEqual(0);
    expect(result.riskScore.score).toBeLessThanOrEqual(100);
    expect(Array.isArray(result.riskScore.flags)).toBe(true);
  });

  it("has entitiesJson parseable as JSON", () => {
    const result = engine.getPermission("http", {
      method: "POST",
      url: "https://api.stripe.com/v1/charges",
      body: { amount: 5000, currency: "usd" },
    });
    const entities = JSON.parse(result.normAction.entitiesJson);
    expect(typeof entities).toBe("object");
  });
});

// ── checkJson convenience method ──

describe("checkJson", () => {
  let engine;

  beforeAll(() => {
    engine = Engine.fromPacks(PACKS_DIR);
  });

  it("works with JSON string input", () => {
    const payload = JSON.stringify({
      tool_name: "bash",
      parameters: { command: "ls" },
      metadata: {},
    });
    const result = engine.checkJson(payload);
    expect(result.permission).toBe("Allow");
  });

  it("throws on invalid JSON", () => {
    expect(() => engine.checkJson("not json")).toThrow("invalid JSON");
  });
});

// ── Org domain parameter ──

describe("orgDomain", () => {
  let engine;

  beforeAll(() => {
    engine = Engine.fromPacks(PACKS_DIR);
  });

  it("accepts custom org domain", () => {
    const result = engine.getPermission(
      "bash",
      { command: "ls" },
      "acme.com"
    );
    expect(result.permission).toBe("Allow");
  });

  it("works without org domain (uses default)", () => {
    const result = engine.getPermission("bash", { command: "ls" });
    expect(result.permission).toBe("Allow");
  });
});
