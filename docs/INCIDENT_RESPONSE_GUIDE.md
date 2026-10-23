# Incident Response & Detection Playbook: PHP Engine Memory Corruption

This playbook outlines detection procedures, log analysis patterns, and forensic indicators for identifying anomalous activity or scanning attempts targeting **CVE-2026-109618** and **CVE-2026-109619**.

---

## 1. Key Forensic Indicators

When an unpatched PHP engine encounters an exploit or scanning attempt targeting these vulnerabilities, specific artifacts appear in system logs, web server logs, and process crash monitors:

| Indicator | Location | Description |
|---|---|---|
| **Pre-RINIT OOM Error** | PHP Error Log | `Allowed memory size of ... exhausted in Unknown on line 0` |
| **Worker SIGSEGV (Signal 11)** | Apache / PHP-FPM Error Log | `child pid ... exit signal Segmentation fault (11)` |
| **Worker SIGABRT (Signal 6)** | Apache Error Log | `child pid ... exit signal Aborted (6)` |
| **Abnormal Set-Cookie Header** | Reverse Proxy / WAF Log | Responses returning oversized or binary-encoded `PHPSESSID` values |
| **Burst of 500 Responses** | Web Server Access Log | Repeated HTTP 500 errors on endpoints that usually return HTTP 200/302 |

---

## 2. Web Server & PHP Log Analysis

### A. Searching for Pre-Request OOM Crashes
In normal PHP execution, memory exhaustion errors indicate the specific script and line number (e.g., `in /var/www/html/script.php on line 42`). 

When an OOM occurs during SAPI multipart parsing, it logs as **`Unknown on line 0`**:

```bash
# Grep for pre-request memory exhaustion in PHP error logs
grep -E "Allowed memory size of [0-9]+ bytes exhausted.*in Unknown on line 0" /var/log/php/error.log
```

### B. Detecting Apache Worker Crashes
Check Apache error logs for abnormal child process deaths:

```bash
# Search for worker segmentation faults
grep -E "exit signal Segmentation fault \(11\)" /var/log/apache2/error.log

# Search for worker aborts
grep -E "exit signal Aborted \(6\)" /var/log/apache2/error.log
```

### C. Detecting Persistent Worker Crashes in PHP-FPM
```bash
# Search for sudden worker termination in PHP-FPM
grep -E "WARNING: \[pool [^\]]+\] child [0-9]+ exited on signal 11" /var/log/php*-fpm.log
```

---

## 3. Core Dump Forensics (GDB)

If a persistent worker crashes and generates a core dump (`/tmp/core.*` or systemd coredump), security responders can inspect the call stack using GDB:

```bash
gdb /usr/sbin/apache2 /var/crash/core.apache2.*
```

### Suspicious Stack Frames to Look For:
1. **RFC 1867 Teardown Dereference (CVE-2026-109618):**
   ```text
   #0  0x00007f... in zval_ptr_dtor ()
   #1  0x00007f... in zend_hash_destroy ()
   #2  0x00007f... in php_request_shutdown ()
   #3  0x00007f... in php_apache_request_dtor ()
   ```
2. **Cross-Request UAF / Stale Session State (CVE-2026-109619):**
   ```text
   #0  0x00007f... in php_session_decode () or php_var_unserialize ()
   #1  0x00007f... in php_rinit_session ()
   #2  0x00007f... in zend_activate_modules ()
   ```

---

## 4. Triage & Incident Checklist

- [ ] **Step 1: Check Active PHP Version:** Verify if any hosts run PHP `< 8.2.35`, `< 8.3.36`, `< 8.4.27`, or `< 8.5.12`.
- [ ] **Step 2: Inspect Error Logs:** Search for `Unknown on line 0` and worker segmentation faults (`signal 11`).
- [ ] **Step 3: Immediate Mitigation:**
  - Apply the vendor patch release (`apt-get upgrade php8.4`, Docker image update, etc.).
  - If immediate patching is delayed, update `php.ini` to set `session.upload_progress.enabled = 0` and ensure `post_max_size <= memory_limit`.
  - Implement WAF boundary filtering rules to drop malformed multipart requests.
- [ ] **Step 4: Audit Worker Pools:** Restart Apache/PHP-FPM pools to clear any lingering persistent worker memory state.
