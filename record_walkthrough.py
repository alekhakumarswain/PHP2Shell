#!/usr/bin/env python3
"""
Automated Playwright Walkthrough & Video Recorder
Target: CVE-2026-109618 & CVE-2026-109619 Test Environments

Features:
- Live visual playback in browser (headed mode with slow-motion)
- Automatic screen/session video recording saved to 'videos/' folder (.webm)
- Step-by-step explanation of the vulnerability mechanics at each stage
"""

import sys
import os
import time
from playwright.sync_api import sync_playwright

VIDEO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "videos")
os.makedirs(VIDEO_DIR, exist_ok=True)

def print_banner(step: str, title: str, explanation: str):
    print("\n" + "=" * 75)
    print(f"[{step}] {title}")
    print("=" * 75)
    print(explanation)
    print("-" * 75)

def run_walkthrough(base_url="http://localhost:8081", headless=False):
    print("\n" + "#" * 75)
    print(f"[*] Starting Playwright Video Automation for: {base_url}")
    print(f"[*] Output Video Directory: {VIDEO_DIR}")
    print("#" * 75)

    with sync_playwright() as p:
        # Launch browser (prefers installed Chrome or Edge)
        browser = None
        for channel in ["chrome", "msedge"]:
            try:
                browser = p.chromium.launch(
                    channel=channel,
                    headless=headless,
                    slow_mo=1000  # 1 second pause between actions for clear visual pacing
                )
                print(f"[+] Launched browser using channel: '{channel}'")
                break
            except Exception:
                continue

        if not browser:
            print("[-] Standard browser launch fallback...")
            browser = p.chromium.launch(headless=headless, slow_mo=1000)

        # Create browser context with video recording enabled
        context = browser.new_context(
            record_video_dir=VIDEO_DIR,
            record_video_size={"width": 1280, "height": 720},
            viewport={"width": 1280, "height": 720}
        )

        page = context.new_page()

        try:
            # -------------------------------------------------------------
            # STEP 1: Portal Navigation
            # -------------------------------------------------------------
            print_banner(
                "STEP 1",
                "Navigating to Lab Portal (index.php)",
                "EXPLANATION: Accessing the landing page which summarizes the target runtime.\n"
                "- In CVE-2026-109618: Focuses on multipart form handling & memory bounds.\n"
                "- In CVE-2026-109619: Focuses on persistent workers & session persistence."
            )
            page.goto(f"{base_url}/index.php")
            page.wait_for_timeout(2000)

            # -------------------------------------------------------------
            # STEP 2: Accessing Protected Admin Before Login (Security Check)
            # -------------------------------------------------------------
            print_banner(
                "STEP 2",
                "Testing Access Control Guard (admin.php)",
                "EXPLANATION: Attempting to browse directly to admin.php without a session.\n"
                "The server checks $_SESSION['authenticated']. Because no valid session exists,\n"
                "it sends an HTTP 302 redirect back to login.php?msg=auth_required."
            )
            page.goto(f"{base_url}/admin.php")
            page.wait_for_timeout(2000)

            # -------------------------------------------------------------
            # STEP 3: Authentication (login.php)
            # -------------------------------------------------------------
            print_banner(
                "STEP 3",
                "Authentication on login.php",
                "EXPLANATION: Submitting valid credentials ('admin' / 'CyberLab2026!').\n"
                "Upon validation, the backend invokes session_regenerate_id(true) to mitigate\n"
                "session fixation, sets $_SESSION['authenticated'] = true, and issues PHPSESSID."
            )
            page.fill("input#username", "admin")
            page.fill("input#password", "CyberLab2026!")
            page.wait_for_timeout(1000)
            page.click("button#btn-login")
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(2000)

            # -------------------------------------------------------------
            # STEP 4: Admin Dashboard & Telemetry Inspection
            # -------------------------------------------------------------
            print_banner(
                "STEP 4",
                "Admin Dashboard Metrics & Runtime Inspection",
                "EXPLANATION: Inspecting live Zend Engine telemetry on admin.php:\n"
                "- Real-time Memory Usage: Tracked via memory_get_usage(true)\n"
                "- Target Limits: memory_limit (16M / 128M) and post_max_size (32M)\n"
                "- Worker PID: Shows process handling the connection."
            )
            page.wait_for_timeout(2500)

            # -------------------------------------------------------------
            # STEP 5: Executing Defensive Probe
            # -------------------------------------------------------------
            print_banner(
                "STEP 5",
                "Running Defensive Allocation Probe",
                "EXPLANATION: Triggering an internal memory probe.\n"
                "In CVE-2026-109618, out-of-memory bailouts during multipart parsing left\n"
                "half-initialized HashTable buckets. This probe tests safe allocation limits."
            )
            if page.locator("select#test_mb").count() > 0:
                page.select_option("select#test_mb", "4")
                page.wait_for_timeout(1000)
                page.click("button:has-text('Run Allocation Probe')")
                page.wait_for_load_state("networkidle")
                page.wait_for_timeout(2000)
            elif page.locator("button:has-text('Send Sequential Request')").count() > 0:
                page.click("button:has-text('Send Sequential Request')")
                page.wait_for_load_state("networkidle")
                page.wait_for_timeout(2000)

            # -------------------------------------------------------------
            # STEP 6: Session Invalidation (logout.php)
            # -------------------------------------------------------------
            print_banner(
                "STEP 6",
                "Logout & Complete Session Invalidation",
                "EXPLANATION: Clicking logout destroys $_SESSION on the server and invalidates\n"
                "the browser's PHPSESSID cookie, ensuring subsequent requests cannot reuse state."
            )
            page.click("a:has-text('Logout')")
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(2000)

            print("\n[+] Walkthrough completed successfully!")

        except Exception as e:
            print(f"[-] Automation error: {e}")
        finally:
            # Closing the page and context saves the recorded video
            page.close()
            context.close()
            browser.close()

        # Find saved video file
        saved_videos = [f for f in os.listdir(VIDEO_DIR) if f.endswith(".webm")]
        if saved_videos:
            latest_video = max([os.path.join(VIDEO_DIR, f) for f in saved_videos], key=os.path.getmtime)
            print("=" * 75)
            print("[+] VIDEO RECORDED SUCCESSFULLY")
            print(f"Saved to: {latest_video}")
            print("=" * 75)

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8081"
    is_headless = "--headless" in sys.argv
    run_walkthrough(base_url=target, headless=is_headless)
