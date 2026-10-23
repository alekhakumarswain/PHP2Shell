# PHP CVE-2026-109618 & CVE-2026-109619 Defensive Security Audit Lab

This repository contains two self-contained security audit and testing environments modeling the vulnerability mechanisms researched in `php-cve-2026-10961x-lab-poc`.

---

## 1. Laboratory Overview

| Environment | Target CVE | Affected Subsystem | Container Port | Default Runtime |
|---|---|---|---|---|
| **[CVE-2026-109618](./CVE-2026-109618/)** | GHSA-w8hw-w9fx-j79w | RFC 1867 Multipart Parsing / HashTable OOM | `http://localhost:8081` | PHP 8.4.26 / Apache Prefork |
| **[CVE-2026-109619](./CVE-2026-109619/)** | GHSA-6wmf-4rv5-p3rp | Persistent Worker Session State / Dangling Globals | `http://localhost:8082` | PHP 8.4.26 / Apache Prefork |

### Default Lab Credentials
- **Username:** `admin`
- **Password:** `CyberLab2026!`

---

## 2. Under-the-Hood Vulnerability Mechanics

### A. CVE-2026-109618: Out-of-Memory Corruption in RFC 1867
* **Affected Versions:** PHP < 8.2.35, < 8.3.36, < 8.4.27, < 8.5.12
* **Where It Occurs:** `ext/standard/rfc1867.c` and `Zend/zend_hash.c`.
* **When It Triggers:** During pre-request parsing (`pre-RINIT`), **before** any PHP scripts (`login.php` or `index.php`) execute.
* **The Core Flaw:** 
  Unpatched PHP violated the *"Allocate-then-Publish"* invariant:
  1. As multipart headers/fields are parsed, internal HashTable element counters (`nNumUsed`) were incremented **before** memory allocation for the bucket was guaranteed.
  2. If memory exhausted the configured `memory_limit`, the engine performed a hard `zend_bailout()` (`longjmp`).
  3. During request shutdown (`php_request_shutdown`), cleanup routines iterated through `nNumUsed` and attempted to dereference half-initialized or unallocated memory slots.
* **The Fix:** In PHP 8.4.27 / 8.5.12, allocation functions return `HASH_NOMEM` before publishing counters, and teardown routines check `ZEND_HAS_OOM()` to abort safely.

---

### B. CVE-2026-109619: Cross-Request Stale Global State in Persistent Workers
* **Affected Versions:** PHP < 8.2.35, < 8.3.36, < 8.4.27, < 8.5.12
* **Where It Occurs:** `ext/session/session.c`, `session.upload_progress`, and serialization buffers (`BG(serialize)`).
* **When It Triggers:** Across multi-request lifecycles in persistent worker processes (Apache Prefork or PHP-FPM).
* **The Core Flaw:**
  1. **Request A:** A request triggers early session processing and subsequently fails or bails out (e.g., OOM).
  2. **The Teardown Gap:** Request-scoped memory is freed, but global session pointers (`PS(id)`, `PS(send_cookie)`) inside the persistent worker process were **not cleared to NULL**.
  3. **Request B:** When the same worker handles a subsequent request, the engine accesses the retained stale pointer before next-request re-initialization, causing a cross-request Use-After-Free (UAF).
* **The Fix:** In PHP 8.4.27 / 8.5.12, session globals are strictly reset to NULL upon bailout, and `PS(in_rfc1867_update)` enforces `incomplete_classes_only` during pre-RINIT execution.

---

## 3. Application Layer vs. Engine Layer

A common question when auditing these vulnerabilities is:
> *"Why does the web app have a regular login page with ID and password?"*

* **The Web Application (`login.php`, `admin.php`):**
  Represents a standard real-world target with session authentication, cookie handling, access control, and diagnostic memory meters.
* **The Vulnerability Target:**
  Neither CVE-2026-109618 nor CVE-2026-109619 is an application logic bug (like SQL injection or hardcoded credentials). They reside in the **C-level PHP engine underneath the application**, operating directly on raw HTTP streams before userland PHP code runs.

---

## 4. Auditing with Burp Suite (No User Credentials)

When using Burp Suite (Repeater / Intruder), security auditors observe how the server handles HTTP payloads at the engine boundary without authenticating:

### Observation 1: Pre-Request SAPI Execution
- Any HTTP `POST` request sent to any endpoint (`/login.php`, `/index.php`, or even non-existent scripts) with `Content-Type: multipart/form-data; boundary=...` is processed by PHP's RFC 1867 parser before routing to application code.

### Observation 2: Inspecting Memory Limit Responses
- In this environment, `memory_limit = 16M` while `post_max_size = 32M`.
- **Standard HTTP Request:** Returns HTTP `200 OK` with normal HTML.
- **OOM Threshold Response:** When request memory exceeds the 16MB threshold, PHP halts execution immediately:
  - If `display_errors = 1`: Displays `Fatal error: Allowed memory size of 16777216 bytes exhausted...`
  - If `display_errors = 0`: Returns an HTTP 500 or truncated response without rendering application templates.

### Observation 3: Monitoring Worker Continuity & Cookie Persistence
- Inspect the response headers across sequential requests to `http://localhost:8082`:
  - Note the `Set-Cookie: PHPSESSID=...` values and inspect whether the worker process ID remains identical (`getmypid()`), confirming that subsequent requests are served by the same worker process.

---

## 5. Playwright Automation & Video Recording

The lab includes an automated Playwright walkthrough script: `record_walkthrough.py`.

### Features:
- Automates portal browsing, unauthenticated guard checks, login, admin diagnostics, and logout.
- **Records a full WebM video** of the browser session into `videos/`.
- Logs explanatory annotations explaining security concepts at each step.

### Running Live (Watch the Browser Play with 1s Delays):
```powershell
python record_walkthrough.py http://localhost:8081
```

### Running Headless (Background Video Recording):
```powershell
python record_walkthrough.py http://localhost:8081 --headless
```

Recorded video files will appear in:
📁 `e:\cyber\demo\videos\*.webm`

---

## 6. Quick Start & Execution

### Starting the Environments via Docker:
```powershell
# Lab 1: CVE-2026-109618 (Port 8081)
cd e:\cyber\demo\CVE-2026-109618
docker compose up --build -d

# Lab 2: CVE-2026-109619 (Port 8082)
cd e:\cyber\demo\CVE-2026-109619
docker compose up --build -d
```

### Automated Verification & Authentication Tests:
```powershell
python e:\cyber\demo\CVE-2026-109618\verify.py http://localhost:8081
python e:\cyber\demo\CVE-2026-109619\verify.py http://localhost:8082
```

### Credential-Free Diagnostic Audits (audit_check.py):
Runs automated boundary, access guard, and process lifecycle audits without credentials:
```powershell
# Audit CVE-2026-109618 (Multipart SAPI & Health)
python e:\cyber\demo\CVE-2026-109618\audit_check.py http://localhost:8081

# Audit CVE-2026-109619 (Worker PID Continuity & Upload Progress)
python e:\cyber\demo\CVE-2026-109619\audit_check.py http://localhost:8082
```

---

## 7. Defensive Remediation & Hardening

1. **Update PHP Runtime:** Upgrade immediately to official releases: **PHP 8.2.35+, 8.3.36+, 8.4.27+, or 8.5.12+**.
2. **Align SAPI Limits:** Ensure `post_max_size` is strictly equal to or lower than `memory_limit` so oversized payloads are rejected early by the web server rather than causing in-engine OOM bailouts.
3. **Session Hardening:**
   - Always call `session_regenerate_id(true)` upon successful user authentication.
   - Enforce `session.use_only_cookies = 1` and `session.cookie_httponly = 1`.
   - Disable `session.upload_progress.enabled` if real-time upload progress tracking is not needed.
4. **Worker Recycling:** Configure `MaxConnectionsPerChild` in Apache Prefork or `pm.max_requests` in PHP-FPM to periodically recycle worker processes.
