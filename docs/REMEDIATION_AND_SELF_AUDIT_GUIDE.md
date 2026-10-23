# Remediation & Self-Audit Checklist for PHP Deployments

This guide provides an actionable self-assessment checklist and hardening procedure to help system administrators, DevOps engineers, and security teams verify and remediate their PHP web applications against **CVE-2026-109618**, **CVE-2026-109619**, and related session/upload security weaknesses.

---

## 1. Quick Self-Assessment Scorecard

Review your production server against this checklist:

| Priority | Security Control | Recommended Setting | Audit Command / Check |
|---|---|---|---|
| **CRITICAL** | **PHP Engine Version** | `8.2.35+`, `8.3.36+`, `8.4.27+`, `8.5.12+` | `php -v` |
| **HIGH** | **SAPI Limit Alignment** | `post_max_size <= memory_limit` | `php -i \| grep -E 'post_max_size\|memory_limit'` |
| **HIGH** | **Worker Recycling** | `MaxConnectionsPerChild > 0` or `pm.max_requests > 0` | Check `mpm_prefork.conf` or `www.conf` |
| **MEDIUM** | **Upload Progress** | `session.upload_progress.enabled = 0` | `php -i \| grep upload_progress` |
| **MEDIUM** | **Session Cookie Security** | `HttpOnly = 1`, `SameSite = Lax`, `Secure = 1` | `php -i \| grep session.cookie` |
| **LOW** | **Information Disclosure** | `expose_php = Off`, `display_errors = Off` | `php -i \| grep -E 'expose_php\|display_errors'` |

---

## 2. Step 1: Auditing Your PHP Version

Run in your server terminal:
```bash
php -v
```

### Affected vs Patched Matrix:

| Branch | Vulnerable Versions | Safe / Remediated Releases |
|---|---|---|
| **PHP 8.2** | `< 8.2.35` | **8.2.35** or higher |
| **PHP 8.3** | `< 8.3.36` | **8.3.36** or higher |
| **PHP 8.4** | `< 8.4.27` | **8.4.27** or higher |
| **PHP 8.5** | `< 8.5.12` | **8.5.12** or higher |

If your version is in the vulnerable range, apply package updates immediately:
```bash
# Ubuntu / Debian
sudo apt-get update && sudo apt-get --only-upgrade install php8.4*

# Red Hat / Rocky Linux
sudo dnf upgrade php*
```

---

## 3. Step 2: Runtime Configuration Hardening (`php.ini`)

Edit your production `php.ini` file (`/etc/php/8.4/apache2/php.ini` or `/etc/php/8.4/fpm/php.ini`):

### 1. Harmonize Memory and Post Limits
Ensure `post_max_size` is strictly lower than or equal to `memory_limit`:
```ini
; Prevent pre-request OOM during multipart streaming
memory_limit = 128M
post_max_size = 16M
upload_max_filesize = 16M
```

### 2. Disable Unused Upload Progress Tracking
```ini
; Disable upload progress tracking if not actively used by frontend progress bars
session.upload_progress.enabled = 0
session.upload_progress.cleanup = 1
```

### 3. Enforce Strict Cookie & Session Protections
```ini
; Enforce cookie-only session handling and modern security flags
session.use_only_cookies = 1
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = "Lax"
```

### 4. Suppress Server & Engine Banners
```ini
; Hide PHP version banner from HTTP response headers
expose_php = Off

; Disable verbose runtime error display in production
display_errors = Off
display_startup_errors = Off
log_errors = On
error_log = /var/log/php/error.log
```

---

## 4. Step 3: Web Server Worker Recycling

In persistent worker architectures (Apache Prefork or PHP-FPM), worker processes serve hundreds of consecutive requests without restarting. Configuring worker recycling ensures that worker processes are periodically replaced, clearing accumulated memory structures.

### For Apache MPM Prefork (`mpm_prefork.conf`):
```apache
<IfModule mpm_prefork_module>
    StartServers             5
    MinSpareServers          5
    MaxSpareServers          10
    MaxRequestWorkers        150
    # Recycle each worker process after serving 1000 requests
    MaxConnectionsPerChild   1000
</IfModule>
```

### For PHP-FPM Pool Configuration (`www.conf`):
```ini
; Automatically terminate and respawn child workers after 1000 requests
pm.max_requests = 1000
```

---

## 5. Step 4: Application Code-Level Best Practices

Verify that your application scripts follow secure coding practices:

### 1. Mandatory Session ID Rotation Upon Login
Always invoke `session_regenerate_id(true)` upon successful user authentication to defend against session fixation:

```php
if (password_verify($password, $userHash)) {
    // Regenerate session ID and delete old session storage
    session_regenerate_id(true);
    
    $_SESSION['authenticated'] = true;
    $_SESSION['user_id'] = $user['id'];
}
```

### 2. Isolate Upload Storage
Ensure user-uploaded files are stored in a designated directory outside the web root (`DocumentRoot`) or with execution permissions disabled via `.htaccess`:

```apache
# Prevent execution of any scripts in the uploads folder
<FilesMatch "(?i)\.(php|phtml|phar|inc)$">
    Require all denied
</FilesMatch>
```

---

## 6. Step 5: Running the Automated Self-Audit Tool

This repository provides an automated self-audit script: `self_audit.py`.

Run it against your local or staging server to obtain an automated security scorecard:

```powershell
python self_audit.py http://localhost:8081/login.php
```

### Sample Output:
```text
======================================================================
   PHP SECURITY POSTURE & REMEDIATION SELF-AUDIT
   Target: http://localhost:8081/login.php
======================================================================

[*] 1. Server & PHP Version Information Disclosure
  [PASS] 'X-Powered-By' header is hidden (expose_php = Off).
  [INFO] 'Server' banner: Apache/2.4.69 (Debian)

[*] 2. Session Cookie Hardening (HttpOnly, Secure, SameSite)
  [COOKIE] PHPSESSID=...
    -> [PASS] 'HttpOnly' flag is set (blocks JavaScript theft).
    -> [PASS] 'SameSite' attribute configured.

[*] 3. Multipart Delimiter & Parser Behavior (RFC 1867)
  [PASS] Non-standard comma delimiter blocked by WAF/Proxy.

[*] 4. Error Disclosure Protection
  [PASS] No raw PHP engine errors/warnings leaked in response.

======================================================================
   SELF-AUDIT SUMMARY SCORECARD
   [+] Passed Checks:   4
   [!] Warnings / Recs: 0
======================================================================
```
