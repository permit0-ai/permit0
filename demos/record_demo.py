"""
permit0 PearX Demo — Automated Recording Script

This script automates the demo recording:
1. Launches the demo server
2. Opens Chrome via Playwright (headed mode for screen recording)
3. Generates AI voiceover with edge-tts
4. Drives the 3 demo scenarios with timed narration
5. Captures screenshots at key moments

Requirements:
  pip install playwright edge-tts
  playwright install chromium
  ANTHROPIC_API_KEY must be set

Usage:
  # Record with OBS/Loom running, then run:
  python demos/record_demo.py

  # Or generate voiceover files only:
  python demos/record_demo.py --voice-only

  # Or generate screenshots only (headless):
  python demos/record_demo.py --screenshots-only
"""
from __future__ import annotations

import argparse
import asyncio
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# ── Config ──────────────────────────────────────────────────

DEMO_URL = "http://localhost:8000"
VOICE = "en-US-AvaMultilingualNeural"  # Expressive, warm female voice
VOICE_RATE = "-5%"  # Slightly slower for clarity
OUTPUT_DIR = Path("demos/recording_output")
SERVER_STARTUP_WAIT = 3

# ── Narration Script ────────────────────────────────────────

@dataclass
class NarrationSegment:
    id: str
    text: str
    pause_after: float = 1.0  # seconds of silence after this segment


OPENING = [
    NarrationSegment(
        "opening_1",
        "AI agents now have real tools. Bank transfers, API calls, file access, email. "
        "But today, permissions are binary. Either everything is allowed, or everything is blocked.",
        pause_after=1.5,
    ),
    NarrationSegment(
        "opening_2",
        "permit0 is a four-layer permission engine. "
        "A deterministic Rust scorer handles the easy calls, with no L.L.M. and microsecond latency. "
        "A constrained L.L.M. reviewer handles the gray zone. It can escalate or deny, but it can never approve. "
        "Humans make the final call on high-stakes decisions. "
        "And hard blocks catch patterns too dangerous for anyone to override.",
        pause_after=1.5,
    ),
    NarrationSegment(
        "opening_3",
        "Let me show you three real attack patterns.",
        pause_after=2.0,
    ),
]

DEMO1_EXFIL = [
    NarrationSegment(
        "exfil_intro",
        "Demo one. Insider Exfiltration. "
        "A task agent is asked to summarize project configuration. "
        "But the request is actually a prompt injection that directs the agent to "
        "read credential files and email them to an external address.",
        pause_after=2.0,
    ),
    NarrationSegment(
        "exfil_unprotected_intro",
        "First, let's run this without permit0.",
        pause_after=1.0,
    ),
    NarrationSegment(
        "exfil_unprotected_result",
        "Without permit0, the agent reads the README, reads credentials dot json, "
        "reads the environment file with all the secrets, "
        "and emails everything to an external address. "
        "Complete exfiltration in four tool calls.",
        pause_after=2.0,
    ),
    NarrationSegment(
        "exfil_protected_intro",
        "Now let's run the same scenario with permit0 protection enabled.",
        pause_after=1.5,
    ),
    NarrationSegment(
        "exfil_step1",
        "README dot M.D. Score 3, Minimal tier. The scorer allows it immediately. "
        "No L.L.M. cost, microsecond decision.",
        pause_after=1.5,
    ),
    NarrationSegment(
        "exfil_step2_scorer",
        "Now the agent tries to read credentials dot json. Watch the decision panel. "
        "The scorer flags it Medium. Score 35. "
        "EXPOSURE, GOVERNANCE, and PRIVILEGE flags fire. "
        "The path contains credentials. That's suspicious.",
        pause_after=1.0,
    ),
    NarrationSegment(
        "exfil_step2_reviewer",
        "This is where the Agent Reviewer activates. "
        "It's a constrained L.L.M. that sees the full context. "
        "The tool call, the risk flags, the task goal: summarize project configuration, "
        "and the session history.",
        pause_after=1.0,
    ),
    NarrationSegment(
        "exfil_step2_result",
        "The reviewer asks: is reading a credentials file consistent with summarizing project config? "
        "No. Credentials are not configuration. "
        "The reviewer returns DENY with 95% confidence.",
        pause_after=2.0,
    ),
    NarrationSegment(
        "exfil_step3",
        "Same pattern for dot env production. DENY by the Agent Reviewer.",
        pause_after=1.5,
    ),
    NarrationSegment(
        "exfil_step4",
        "The email attempt hits the gmail pack's content scanner. "
        "It detects passwords and API keys in the body. Score 100, Critical tier. Hard blocked.",
        pause_after=1.5,
    ),
    NarrationSegment(
        "exfil_key_point",
        "Here's what's important. Without the Agent Reviewer, "
        "the credential reads would have gone to a human reviewer. That works, but it's slow. "
        "The reviewer understood that reading credentials contradicts the task goal "
        "and blocked it instantly. "
        "And the reviewer cannot approve. That's enforced at the Rust type level. "
        "If it's uncertain, it routes to a human. If the L.L.M. fails, it routes to a human. "
        "The safety floor is guaranteed by the compiler.",
        pause_after=3.0,
    ),
]

DEMO2_FRAUD = [
    NarrationSegment(
        "fraud_intro",
        "Demo two. A.P.P. Fraud Defense. "
        "A procurement agent receives six pre-approved supplier invoices. "
        "They look legitimate, but they're fake. "
        "Scattered across six different countries. "
        "This is a classic Authorized Push Payment fraud pattern.",
        pause_after=2.0,
    ),
    NarrationSegment(
        "fraud_unprotected",
        "Without permit0, all six transfers execute. "
        "$85,000 sent to six different countries in under a minute.",
        pause_after=2.0,
    ),
    NarrationSegment(
        "fraud_protected_intro",
        "With permit0 protection enabled:",
        pause_after=1.0,
    ),
    NarrationSegment(
        "fraud_allow",
        "The first two transfers look fine individually. "
        "$12,000 to the UK, $8,500 to Germany. Reasonable amounts, low daily total. "
        "Score 21 to 22, Low tier. Allowed.",
        pause_after=1.5,
    ),
    NarrationSegment(
        "fraud_hitl",
        "Transfer 3. $15,000 to France. The daily total crosses the threshold. "
        "Session rules fire, GOVERNANCE flag added. Score jumps to Medium. "
        "But payments dot transfer is in the always-human list. "
        "The reviewer skips the L.L.M. call and routes straight to a human. "
        "As a reviewer, I can see the risk score, the flags, the session accumulation.",
        pause_after=2.0,
    ),
    NarrationSegment(
        "fraud_approve",
        "I'll approve this one. Paris Logistics is a known vendor.",
        pause_after=2.0,
    ),
    NarrationSegment(
        "fraud_block",
        "But by transfer 5 and 6, permit0 has seen too many different recipients. "
        "The scatter-transfer block rule fires. Six accounts, six countries. "
        "This is a textbook fraud pattern. Hard blocked. "
        "Even a human reviewer cannot override this.",
        pause_after=3.0,
    ),
]

DEMO3_CARD = [
    NarrationSegment(
        "card_intro",
        "Demo three. Card Testing Detection. "
        "A compromised checkout agent fires micro-charges against five different customer cards. "
        "Each charge is under a dollar. Together, it's a card testing attack.",
        pause_after=1.5,
    ),
    NarrationSegment(
        "card_unprotected",
        "Without permit0, all five go through. "
        "The attacker now knows which stolen card numbers are valid.",
        pause_after=2.0,
    ),
    NarrationSegment(
        "card_protected",
        "With permit0: the first two charges are allowed. Low amounts, low risk. "
        "By charge 3, session velocity triggers. The score gets a massive boost "
        "to compensate for the tiny amounts. Human review requested. "
        "I'll reject this. Three micro-charges to three different customers is suspicious.",
        pause_after=2.0,
    ),
    NarrationSegment(
        "card_block",
        "By charge 5, the card testing block rule fires. Hard blocked.",
        pause_after=2.0,
    ),
]

CLOSING = [
    NarrationSegment(
        "closing_1",
        "Four layers. The scorer handles the 70% of calls that are clearly safe or clearly dangerous. "
        "Deterministic, zero L.L.M. cost. "
        "The Agent Reviewer handles the 15% gray zone. It can deny or escalate, but never approve. "
        "Humans review high-stakes decisions with full context. "
        "Hard blocks catch attack patterns nobody should authorize.",
        pause_after=1.5,
    ),
    NarrationSegment(
        "closing_2",
        "Every decision is cryptographically signed into an immutable audit log. "
        "Each entry has a sequence number, a hash chain, and an Ed25519 signature. "
        "Chain integrity is verifiable with one API call.",
        pause_after=1.5,
    ),
    NarrationSegment(
        "closing_3",
        "Adding a new integration is one YAML file. No Rust code needed. "
        "Python and TypeScript bindings ship today. "
        "We're building the permission layer for the agentic stack.",
        pause_after=2.0,
    ),
]

ALL_SEGMENTS = OPENING + DEMO1_EXFIL + DEMO2_FRAUD + DEMO3_CARD + CLOSING


# ── Voice Generation ────────────────────────────────────────

async def generate_voiceover(segments: list[NarrationSegment], output_dir: Path) -> dict[str, Path]:
    """Generate MP3 files for each narration segment using edge-tts."""
    import edge_tts

    voice_dir = output_dir / "voice"
    voice_dir.mkdir(parents=True, exist_ok=True)

    paths: dict[str, Path] = {}
    for seg in segments:
        out_path = voice_dir / f"{seg.id}.mp3"
        if out_path.exists():
            print(f"  [skip] {seg.id} (already exists)")
            paths[seg.id] = out_path
            continue

        print(f"  [tts] {seg.id} ...")
        comm = edge_tts.Communicate(seg.text, VOICE, rate=VOICE_RATE)
        await comm.save(str(out_path))
        paths[seg.id] = out_path

    return paths


# ── Browser Automation ──────────────────────────────────────

async def run_demo_automation(headless: bool = False, screenshots_only: bool = False):
    """Drive the demo UI with Playwright."""
    from playwright.async_api import async_playwright

    screenshot_dir = OUTPUT_DIR / "screenshots"
    screenshot_dir.mkdir(parents=True, exist_ok=True)

    shot_num = [0]

    async def shot(page, label: str = ""):
        shot_num[0] += 1
        name = f"{shot_num[0]:04d}_{label}.png"
        await page.screenshot(path=str(screenshot_dir / name))
        print(f"    📸 {name}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=headless,
            args=["--window-size=1440,900"] if not headless else [],
        )
        context = await browser.new_context(
            viewport={"width": 1440, "height": 900},
            device_scale_factor=2,  # retina for crisp screenshots
        )
        page = await context.new_page()

        # ── Landing page ──
        await page.goto(DEMO_URL)
        await page.wait_for_load_state("networkidle")
        await asyncio.sleep(1)
        await shot(page, "landing")

        # ── Helper: run a scenario ──
        async def run_scenario(
            scenario_id: str,
            protected: bool,
            approval_actions: list[str] | None = None,
            label: str = "",
        ):
            """
            Click a scenario card, run it protected or unprotected,
            handle approval dialogs.

            approval_actions: list of "approve" or "reject" for each
            approval_required event, in order.
            """
            # Click scenario card
            card = page.locator(f"[data-scenario='{scenario_id}']")
            if await card.count() == 0:
                # Try clicking by text
                card = page.locator(f".scenario-card").filter(has_text=scenario_id)
            await card.click()
            await asyncio.sleep(0.5)
            await shot(page, f"{label}_selected")

            # Click protected/unprotected button
            if protected:
                btn = page.locator("button:has-text('Protected')")
            else:
                btn = page.locator("button:has-text('Unprotected')")
            await btn.click()
            await asyncio.sleep(0.5)
            await shot(page, f"{label}_started")

            # Wait for events and handle approvals
            approval_idx = 0
            approvals = approval_actions or []

            # Poll for completion or approval
            max_wait = 120  # seconds
            start = time.time()
            while time.time() - start < max_wait:
                # Check if approval bar is visible
                approval_bar = page.locator("#approvalBar.visible")
                if await approval_bar.count() > 0:
                    await asyncio.sleep(0.5)
                    await shot(page, f"{label}_approval_{approval_idx}")

                    if approval_idx < len(approvals):
                        action = approvals[approval_idx]
                        if action == "approve":
                            await page.locator("button:has-text('✓ Approve')").click()
                        else:
                            await page.locator("button:has-text('✗ Reject')").click()
                        approval_idx += 1
                        await asyncio.sleep(0.5)
                    else:
                        # Default: approve
                        await page.locator("button:has-text('✓ Approve')").click()
                        approval_idx += 1
                        await asyncio.sleep(0.5)

                # Check if done
                done_msg = page.locator(".msg-system:has-text('finished')")
                if await done_msg.count() > 0:
                    break

                await asyncio.sleep(1)

            await asyncio.sleep(1)
            await shot(page, f"{label}_done")

            # Go back to scenario selection (click the logo/title)
            await page.goto(DEMO_URL)
            await page.wait_for_load_state("networkidle")
            await asyncio.sleep(1)

        # ── Demo 1: Insider Exfiltration ──
        print("\n=== Demo 1: Insider Exfiltration ===")

        # Unprotected run
        print("  Running unprotected...")
        await run_scenario("insider_exfil", protected=False, label="exfil_unprotected")

        # Reset
        await page.evaluate("fetch('/api/reset', {method: 'POST'})")
        await asyncio.sleep(1)

        # Protected run
        print("  Running protected...")
        await run_scenario("insider_exfil", protected=True, label="exfil_protected")

        # Reset
        await page.evaluate("fetch('/api/reset', {method: 'POST'})")
        await asyncio.sleep(1)

        # ── Demo 2: APP Fraud ──
        print("\n=== Demo 2: APP Fraud ===")

        # Unprotected
        print("  Running unprotected...")
        await run_scenario("app_fraud", protected=False, label="fraud_unprotected")

        await page.evaluate("fetch('/api/reset', {method: 'POST'})")
        await asyncio.sleep(1)

        # Protected — approve transfers 3-4, let 5-6 get blocked
        print("  Running protected...")
        await run_scenario(
            "app_fraud",
            protected=True,
            approval_actions=["approve", "approve"],
            label="fraud_protected",
        )

        await page.evaluate("fetch('/api/reset', {method: 'POST'})")
        await asyncio.sleep(1)

        # ── Demo 3: Card Testing ──
        print("\n=== Demo 3: Card Testing ===")

        # Unprotected
        print("  Running unprotected...")
        await run_scenario("card_testing", protected=False, label="card_unprotected")

        await page.evaluate("fetch('/api/reset', {method: 'POST'})")
        await asyncio.sleep(1)

        # Protected — reject at first approval
        print("  Running protected...")
        await run_scenario(
            "card_testing",
            protected=True,
            approval_actions=["reject"],
            label="card_protected",
        )

        # Final screenshot: audit trail
        await asyncio.sleep(2)
        await shot(page, "final_audit")

        await browser.close()

    print(f"\n📸 Screenshots saved to {screenshot_dir}/")


# ── Video Assembly ──────────────────────────────────────────

def assemble_video():
    """
    Combine screenshots and voice segments into a final MP4.
    This is a simplified version — for production, use a proper
    video editor or more sophisticated ffmpeg scripting.
    """
    voice_dir = OUTPUT_DIR / "voice"
    screenshot_dir = OUTPUT_DIR / "screenshots"

    if not voice_dir.exists() or not screenshot_dir.exists():
        print("Run --voice-only and demo automation first")
        return

    # Concatenate all voice segments with silence gaps
    segments_file = OUTPUT_DIR / "voice_concat.txt"
    silence_file = OUTPUT_DIR / "silence_1s.mp3"

    # Generate silence
    subprocess.run([
        "ffmpeg", "-y", "-f", "lavfi", "-i",
        "anullsrc=r=24000:cl=mono", "-t", "1.5",
        "-c:a", "libmp3lame", str(silence_file),
    ], capture_output=True)

    with open(segments_file, "w") as f:
        for seg in ALL_SEGMENTS:
            voice_path = voice_dir / f"{seg.id}.mp3"
            if voice_path.exists():
                f.write(f"file '{voice_path.resolve()}'\n")
                if seg.pause_after > 0:
                    f.write(f"file '{silence_file.resolve()}'\n")

    # Concat voice
    full_audio = OUTPUT_DIR / "full_narration.mp3"
    subprocess.run([
        "ffmpeg", "-y", "-f", "concat", "-safe", "0",
        "-i", str(segments_file),
        "-c:a", "libmp3lame", "-q:a", "2",
        str(full_audio),
    ], capture_output=True)

    if full_audio.exists():
        size = full_audio.stat().st_size
        print(f"✅ Full narration: {full_audio} ({size // 1024}KB)")
    else:
        print("❌ Failed to create narration audio")


# ── Main ────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(description="permit0 demo recorder")
    parser.add_argument("--voice-only", action="store_true",
                        help="Only generate voiceover audio files")
    parser.add_argument("--screenshots-only", action="store_true",
                        help="Only capture screenshots (headless)")
    parser.add_argument("--headed", action="store_true",
                        help="Run browser in headed mode (for screen recording)")
    parser.add_argument("--assemble", action="store_true",
                        help="Assemble screenshots + voice into video")
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if args.voice_only:
        print("🎙 Generating voiceover...")
        await generate_voiceover(ALL_SEGMENTS, OUTPUT_DIR)
        print("✅ Voice files generated")
        assemble_video()
        return

    if args.assemble:
        assemble_video()
        return

    # Check server is running
    import urllib.request
    try:
        urllib.request.urlopen(f"{DEMO_URL}/api/scenarios", timeout=3)
    except Exception:
        print(f"❌ Demo server not running at {DEMO_URL}")
        print(f"   Start it: uvicorn demos.demo_app.server:app --port 8000")
        sys.exit(1)

    if args.screenshots_only:
        print("📸 Capturing screenshots (headless)...")
        await run_demo_automation(headless=True, screenshots_only=True)
        return

    # Full run: voice + browser
    print("🎙 Generating voiceover...")
    await generate_voiceover(ALL_SEGMENTS, OUTPUT_DIR)

    print("\n🌐 Running demo automation...")
    if args.headed:
        print("   ⚠ Running in headed mode — start your screen recorder NOW")
        await asyncio.sleep(3)
    await run_demo_automation(headless=not args.headed)

    print("\n🎬 Assembling audio...")
    assemble_video()

    print(f"""
✅ Recording complete!

Output files:
  Voice segments: {OUTPUT_DIR}/voice/
  Screenshots:    {OUTPUT_DIR}/screenshots/
  Full narration: {OUTPUT_DIR}/full_narration.mp3

Next steps:
  1. Import screenshots + narration into a video editor (ScreenFlow, DaVinci, iMovie)
  2. Or use OBS + the narration audio for a live screen recording
  3. Or run with --headed and record your screen manually
""")


if __name__ == "__main__":
    asyncio.run(main())
