import { spawn, type ChildProcess } from "node:child_process";
import { request } from "undici";

import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

const WORKSPACE_ROOT = resolve(__dirname, "../../../..");
const PERMIT0_BIN = resolve(WORKSPACE_ROOT, "target/release/permit0");

/**
 * Pick a port in the high range likely to be free. We don't poll for
 * actual freeness — collisions in CI will surface as a startup error
 * caught by the readiness probe below.
 */
function randomPort(): number {
  return 39000 + Math.floor(Math.random() * 1000);
}

export interface LiveDaemon {
  baseUrl: string;
  port: number;
  pid: number;
  stop: () => Promise<void>;
}

/**
 * Spawn `permit0 serve --ui --port <port>` from the workspace root.
 * Workspace root is required so that the daemon picks up `./packs/email/`.
 *
 * Returns once `/api/v1/health` answers 200 (or throws after 10s).
 */
export async function startDaemon(): Promise<LiveDaemon> {
  const port = randomPort();
  const baseUrl = `http://127.0.0.1:${port}`;

  const child: ChildProcess = spawn(
    PERMIT0_BIN,
    ["serve", "--ui", "--port", String(port)],
    {
      cwd: WORKSPACE_ROOT,
      env: {
        ...process.env,
        // Quiet the binary's logs unless the test author opts in.
        RUST_LOG: process.env["RUST_LOG"] ?? "warn",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  let exited = false;
  const exitPromise = new Promise<{ code: number | null; sig: string | null }>(
    (resolveExit) => {
      child.on("exit", (code, sig) => {
        exited = true;
        resolveExit({ code, sig });
      });
    },
  );

  // Capture stderr for failure diagnostics.
  let stderrBuf = "";
  child.stderr?.on("data", (chunk: Buffer) => {
    stderrBuf += chunk.toString("utf8");
  });
  child.stdout?.on("data", () => {
    // Drain so the pipe doesn't fill.
  });

  // Poll /health until ready or timeout.
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (exited) {
      const exit = await exitPromise;
      throw new Error(
        `permit0 daemon exited before ready (code=${exit.code} sig=${exit.sig}): ${stderrBuf}`,
      );
    }
    try {
      const res = await request(`${baseUrl}/api/v1/health`);
      if (res.statusCode === 200) {
        await res.body.dump();
        return {
          baseUrl,
          port,
          pid: child.pid ?? -1,
          async stop() {
            if (child.killed) return;
            child.kill("SIGTERM");
            await Promise.race([
              exitPromise,
              new Promise((r) => setTimeout(r, 2000)),
            ]);
            if (!exited) child.kill("SIGKILL");
          },
        };
      }
      await res.body.dump();
    } catch {
      // Connection refused while binding — keep polling.
    }
    await new Promise((r) => setTimeout(r, 100));
  }

  child.kill("SIGKILL");
  throw new Error(
    `permit0 daemon did not become ready within 10s on port ${port}. stderr: ${stderrBuf}`,
  );
}
