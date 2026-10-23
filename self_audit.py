#!/usr/bin/env python3
"""
Defensive Self-Audit & Remediation Verification Tool
Target: Any PHP Web Application / Environment

Purpose:
Performs non-intrusive security posture checks to evaluate whether a PHP deployment
adheres to the recommended remediation guidelines for CVE-2026-109618, CVE-2026-109619,
and general session/upload security.

Usage:
  python self_audit.py http://localhost:8081
  python self_audit.py https://example.com/login.php
"""

import sys
import urllib.request
import urllib.parse
import http.client
import ssl

def check_target(target_url: str):
    print("=" * 70)
    print("   PHP SECURITY POSTURE & REMEDIATION SELF-AUDIT")
    print(f"   Target: {target_url}")
    print("=" * 70)

    scorecard = {
        "passed": 0,
        "warnings": 0,
        "failed": 0
    }

    # Disable SSL verification for local dev testing if needed
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # -------------------------------------------------------------
    # 1. Server Signature & Header Disclosure Check
    # -------------------------------------------------------------
    print("\n[*] 1. Server & PHP Version Information Disclosure")
    try:
        req = urllib.request.Request(target_url, headers={"User-Agent": "SelfAuditBot/1.0"})
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            headers = {k.lower(): v for k, v in resp.getheaders()}
            
            x_powered = headers.get("x-powered-by")
            server_hdr = headers.get("server")

            if x_powered:
                print(f"  [WARN] 'X-Powered-By: {x_powered}' header is visible.")
                print("         -> Recommendation: Set 'expose_php = Off' in php.ini.")
                scorecard["warnings"] += 1
            else:
                print("  [PASS] 'X-Powered-By' header is hidden (expose_php = Off).")
                scorecard["passed"] += 1

            if server_hdr:
                print(f"  [INFO] 'Server' banner: {server_hdr}")
    except Exception as e:
        print(f"  [FAIL] Failed initial connection: {e}")
        return

    # -------------------------------------------------------------
    # 2. Session Cookie Security Flags Check
    # -------------------------------------------------------------
    print("\n[*] 2. Session Cookie Hardening (HttpOnly, Secure, SameSite)")
    try:
        req = urllib.request.Request(target_url, headers={"User-Agent": "SelfAuditBot/1.0"})
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            set_cookie_hdrs = [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]
            
            if not set_cookie_hdrs:
                print("  [INFO] No Set-Cookie header issued on initial landing.")
            else:
                for cookie in set_cookie_hdrs:
                    cookie_lower = cookie.lower()
                    print(f"  [COOKIE] {cookie.split(';')[0]}")
                    
                    # HttpOnly check
                    if "httponly" in cookie_lower:
                        print("    -> [PASS] 'HttpOnly' flag is set (blocks JavaScript theft).")
                        scorecard["passed"] += 1
                    else:
                        print("    -> [WARN] Missing 'HttpOnly' flag.")
                        print("              Recommendation: Set 'session.cookie_httponly = 1' in php.ini.")
                        scorecard["warnings"] += 1

                    # SameSite check
                    if "samesite" in cookie_lower:
                        print("    -> [PASS] 'SameSite' attribute configured.")
                        scorecard["passed"] += 1
                    else:
                        print("    -> [WARN] Missing 'SameSite' attribute.")
                        print("              Recommendation: Set 'session.cookie_samesite = Lax' in php.ini.")
                        scorecard["warnings"] += 1
    except Exception as e:
        print(f"  [FAIL] Cookie probe failed: {e}")

    # -------------------------------------------------------------
    # 3. Multipart Parser Resiliency & Delimiter Check
    # -------------------------------------------------------------
    print("\n[*] 3. Multipart Delimiter & Parser Behavior (RFC 1867)")
    try:
        # Test standard semicolon vs non-standard comma separator
        boundary = "----SelfAuditBoundaryXYZ"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="audit_test"\r\n\r\n'
            f"ok\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")

        req = urllib.request.Request(
            target_url,
            data=body,
            headers={
                "Content-Type": f"multipart/form-data, boundary={boundary}",  # Comma separator test
                "User-Agent": "SelfAuditBot/1.0"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            status = resp.getcode()
            if status in [400, 403]:
                print("  [PASS] Non-standard comma delimiter rejected by WAF/Proxy (HTTP 400/403).")
                scorecard["passed"] += 1
            else:
                print(f"  [INFO] Non-standard comma delimiter reached backend (HTTP {status}).")
                print("         -> Recommendation: Ensure WAF normalizes or blocks 'multipart/form-data, boundary='.")
                scorecard["warnings"] += 1
    except urllib.error.HTTPError as e:
        if e.code in [400, 403]:
            print("  [PASS] Non-standard comma delimiter blocked by WAF/Proxy.")
            scorecard["passed"] += 1
        else:
            print(f"  [INFO] HTTP {e.code} received.")
    except Exception as e:
        print(f"  [INFO] Multipart delimiter probe: {e}")

    # -------------------------------------------------------------
    # 4. Verbose Error Disclosure Check (display_errors)
    # -------------------------------------------------------------
    print("\n[*] 4. Error Disclosure Protection")
    try:
        # Trigger an intentionally malformed query parameter to inspect error handling
        req = urllib.request.Request(f"{target_url}?audit_probe[]]=malformed", headers={"User-Agent": "SelfAuditBot/1.0"})
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            content = resp.read().decode("utf-8", errors="replace")
            if "Fatal error" in content or "Warning:" in content or "Notice:" in content:
                print("  [WARN] Verbose PHP error messages detected in response HTML.")
                print("         -> Recommendation: Set 'display_errors = Off' in production php.ini.")
                scorecard["warnings"] += 1
            else:
                print("  [PASS] No raw PHP engine errors/warnings leaked in response.")
                scorecard["passed"] += 1
    except Exception as e:
        print(f"  [INFO] Error check completed: {e}")

    # -------------------------------------------------------------
    # Summary Scorecard
    # -------------------------------------------------------------
    print("\n" + "=" * 70)
    print("   SELF-AUDIT SUMMARY SCORECARD")
    print(f"   [+] Passed Checks:   {scorecard['passed']}")
    print(f"   [!] Warnings / Recs: {scorecard['warnings']}")
    print("=" * 70)

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8081/login.php"
    check_target(url)
