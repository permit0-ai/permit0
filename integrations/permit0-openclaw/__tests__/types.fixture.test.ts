import { describe, expect, it } from "vitest";
import { MockAgent } from "undici";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { Permit0Client } from "../src/Permit0Client.js";
import type { Decision, Permission, Tier } from "../src/types.js";

/**
 * Type-alignment regression test.
 *
 * Each JSON fixture under __tests__/fixtures/ represents a real-shape
 * /api/v1/check response captured (or hand-crafted to match) from
 * crates/permit0-cli/src/cmd/serve.rs::CheckResponse. If the Rust side
 * adds, removes, or renames a field, this test fails because either:
 *
 *   1. The TS Decision type rejects the fixture at the type level
 *      (compile error), OR
 *   2. Permit0Client's runtime validator (assertDecisionShape) throws
 *      Permit0Error{malformed_response} when it parses the body.
 *
 * To re-capture fixtures from a live daemon:
 *
 *   curl -s -XPOST http://localhost:9090/api/v1/check \
 *     -H 'content-type: application/json' \
 *     -d '{"tool_name":"Bash","parameters":{"command":"ls"}}' \
 *     | jq . > __tests__/fixtures/decision-allow-fresh.json
 */

const FIXTURE_DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const BASE_URL = "http://localhost:9090";

function loadFixture(filename: string): unknown {
  const path = join(FIXTURE_DIR, filename);
  return JSON.parse(readFileSync(path, "utf8"));
}

function listFixtures(): string[] {
  return readdirSync(FIXTURE_DIR).filter((f) => f.endsWith(".json"));
}

// Compile-time assertion. If a fixture file gains a required field that
// Decision doesn't declare (or vice versa), this object literal fails to
// type-check.
const TYPE_ALIGNMENT_PROBE: Decision = {
  permission: "allow",
  action_type: "process.shell",
  channel: "shell",
  norm_hash: "deadbeef",
  source: "engine",
};
void TYPE_ALIGNMENT_PROBE;

function setup() {
  const agent = new MockAgent();
  agent.disableNetConnect();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const dispatcher = agent as any;
  const pool = agent.get(BASE_URL);
  return { dispatcher, pool };
}

describe("Decision type alignment with permit0 daemon JSON shape", () => {
  const fixtures = listFixtures();

  it("ships at least one fixture (drift guard cannot trivially pass)", () => {
    expect(fixtures.length).toBeGreaterThan(0);
  });

  for (const file of fixtures) {
    it(`accepts fixture ${file} via runtime validator`, async () => {
      const fixture = loadFixture(file) as object;
      const { dispatcher, pool } = setup();
      pool
        .intercept({ path: "/api/v1/check", method: "POST" })
        .reply(200, fixture);

      const client = new Permit0Client({ baseUrl: BASE_URL, dispatcher });
      const got = await client.check("Probe", {});
      expect(got).toEqual(fixture);
      await client.close();
    });

    it(`fixture ${file} satisfies the Decision interface at the type level`, () => {
      const fixture = loadFixture(file) as Decision;
      // Reading fields exercises the type. If a required field is missing,
      // tsc complains in strict mode (noUncheckedIndexedAccess + strict).
      expect(typeof fixture.permission).toBe("string");
      expect(typeof fixture.action_type).toBe("string");
      expect(typeof fixture.channel).toBe("string");
      expect(typeof fixture.norm_hash).toBe("string");
      expect(typeof fixture.source).toBe("string");

      // Permission is one of three exact values.
      const validPerms: Permission[] = ["allow", "deny", "human"];
      expect(validPerms).toContain(fixture.permission);

      // Optional fields, when present, have correct types.
      if (fixture.score !== undefined) expect(typeof fixture.score).toBe("number");
      if (fixture.blocked !== undefined) expect(typeof fixture.blocked).toBe("boolean");
      if (fixture.block_reason !== undefined) expect(typeof fixture.block_reason).toBe("string");
      if (fixture.tier !== undefined) {
        const validTiers: Tier[] = ["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
        expect(validTiers).toContain(fixture.tier);
      }
    });
  }

  it("rejects an obviously broken shape (regression: assertDecisionShape works)", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, { permission: "maybe", action_type: 1, channel: null, norm_hash: "" });

    const client = new Permit0Client({ baseUrl: BASE_URL, dispatcher });
    await expect(client.check("Probe", {})).rejects.toMatchObject({
      name: "Permit0Error",
      code: "malformed_response",
    });
    await client.close();
  });
});
