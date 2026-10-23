# Defensive Hardening & WAF Mitigation Guide: CVE-2026-109618 & CVE-2026-109619

This guide outlines defensive filtering rules, reverse proxy limits, Web Application Firewall (WAF) configurations, and PHP runtime hardening to mitigate the exploitation of pre-RINIT multipart parser and persistent worker vulnerabilities.

---

## 1. Web Application Firewall (WAF) Rules

Both vulnerabilities require delivering specific HTTP boundary or header patterns to unpatched PHP engines. Implementing WAF filtering prevents these requests from ever reaching the PHP SAPI layer.

### A. ModSecurity / OWASP Core Rule Set (CRS)

#### 1. Content-Type Delimiter Normalization
The PHP SAPI parser in `SAPI.c` trims boundaries on `;`, `,`, and whitespace characters. Attackers may attempt to bypass standard signatures checking for `Content-Type: multipart/form-data;` by using a comma separator:

```apache
# SecRule: Detect non-standard multipart/form-data separators
SecRule REQUEST_HEADERS:Content-Type "@rx (?i)multipart/form-data\s*,\s*boundary=" \
    "id:10961801,\
    phase:1,\
    deny,\
    status:400,\
    log,\
    msg:'Potential WAF bypass attempt via non-standard multipart delimiter'"
```

#### 2. Duplicate Header Detection
In CVE-2026-109618 research, repeating small 6-byte multipart part headers (e.g. `X: a`) was observed to amplify memory allocation by ~52x against PHP's internal `SMART_STR_START_SIZE` buffer:

```apache
# SecRule: Reject excessive repeated multipart sub-headers
SecRule MULTIPART_UNMATCHED_BOUNDARY "@eq 1" \
    "id:10961802,\
    phase:2,\
    deny,\
    status:400,\
    log,\
    msg:'Malformed multipart form boundary structure'"
```

---

## 2. Reverse Proxy Hardening (Nginx & Apache)

Enforcing strict request constraints at the reverse proxy layer prevents malformed streams from reaching PHP-FPM or Apache mod_php workers.

### Nginx Configuration (`nginx.conf`):

```nginx
# 1. Enforce strict request body size limits
client_max_body_size 16M;

# 2. Buffer request bodies to prevent chunked streaming bypasses
client_body_buffer_size 128k;

# 3. Disallow chunked Transfer-Encoding for standard form posts
if ($http_transfer_encoding ~* "chunked") {
    # If the application does not explicitly require streaming chunked uploads:
    return 411;
}

# 4. Limit header count and size
large_client_header_buffers 4 8k;
```

### Apache Front-End Configuration (`httpd.conf`):

```apache
# Limit maximum client request body (e.g. 16 MB)
LimitRequestBody 16777216

# Limit maximum request headers
LimitRequestFields 50
LimitRequestFieldSize 8190
```

---

## 3. PHP Runtime Hardening (`php.ini`)

### A. SAPI Limit Alignment
Ensure that `post_max_size` is strictly aligned with or less than `memory_limit`. If `post_max_size` exceeds `memory_limit`, incoming uploads can exhaust memory before reaching application code:

```ini
; Recommended Production Setting
memory_limit = 128M
post_max_size = 16M
upload_max_filesize = 16M
```

### B. Disable Unused Session Tracking
If your application does not use real-time JavaScript file upload progress bars, disable `session.upload_progress`:

```ini
; Disable upload progress tracking
session.upload_progress.enabled = 0
```

### C. Worker Recycling
To mitigate cross-request stale memory retention in persistent worker environments:

* **In Apache MPM Prefork (`mpm_prefork.conf`):**
  ```apache
  <IfModule mpm_prefork_module>
      # Recycle worker processes after 1000 requests to clear accumulated heap
      MaxConnectionsPerChild 1000
  </IfModule>
  ```

* **In PHP-FPM (`www.conf`):**
  ```ini
  ; Periodically recycle PHP-FPM child workers
  pm.max_requests = 1000
  ```

---

## 4. Verification & Patch Audit Matrix

| Component | Target Version | Remediation Status |
|---|---|---|
| **PHP 8.2** | `8.2.35` or higher | **Patched** (Fixed in emergency release) |
| **PHP 8.3** | `8.3.36` or higher | **Patched** (Fixed in emergency release) |
| **PHP 8.4** | `8.4.27` or higher | **Patched** (Fixed in emergency release) |
| **PHP 8.5** | `8.5.12` or higher | **Patched** (Fixed in emergency release) |
