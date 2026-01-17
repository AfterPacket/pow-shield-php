# pow-shield-php

[![License: GPL-3.0](https://img.shields.io/badge/license-GPLv3-green.svg)](https://opensource.org/licenses/GPL-3.0)
[![PHP 8+](https://img.shields.io/badge/php-8+-blue.svg)](https://www.php.net/)
[![Apache 2.4+](https://img.shields.io/badge/apache-2.4+-red.svg)](https://httpd.apache.org/)

A lightweight **Proof-of-Work (PoW)** gateway for PHP sites that reduces abusive traffic **without CAPTCHAs**.  
It issues a signed cookie (`abp`) after a browser completes a **SHA-256** work check, then allows normal access.

## ✨ What's Included

This repository includes:

- ✅ PoW challenge page: `__ab/pow.php`
- ✅ PoW verifier + signed cookie: `__ab/pow-verify.php`
- ✅ ModSecurity rate limits for PoW endpoints: `modsecurity/ab_pow_ratelimit.conf`
- ✅ Apache vhost examples (sanitized to `example.com`) with PoW "skip" rules + clean URL option
- ✅ Cloudflare compatibility notes (cache bypass + real client IP restore)
- ✅ Secret rotation script + systemd service/timer examples

This repository intentionally excludes:

- ❌ TLS certificates / private keys
- ❌ secrets (your `AB_POW_SECRET`)
- ❌ server logs / user data

---

## 🔄 How it works (request flow)

1. A client requests a protected URL and **does not** have cookie `abp`
2. Apache rewrites/redirects them to:
   ```
   /__ab/pow.php?next=/original/path&qs=original=query
   ```
3. `pow.php` runs PoW in the browser:
   - compute `sha256(TOKEN + "." + counter)` until it has enough leading zero bits
4. Browser submits the solution to:
   ```
   /__ab/pow-verify.php
   ```
5. Server verifies:
   - token integrity (HMAC)
   - user-agent binding (light)
   - PoW difficulty (leading zero bits)
6. Server sets cookie:
   - `abp=<signed value>` (Secure, HttpOnly, SameSite=Lax)
7. Browser is redirected back to the original URL

**Goal:** make abusive traffic expensive while normal visitors pass quickly.

---

## 🔴 Live Production Example

A live deployment of **pow-shield-php** is running in production here:

**https://lassiter.eu**

This site uses:
- Proof-of-Work (PoW) gateway for unauthenticated traffic
- ModSecurity rate limiting on PoW endpoints
- Apache connection-level protections (Slowloris / low-and-slow mitigation)
- Cloudflare as CDN + TLS terminator (no bot challenges, no CAPTCHA)

> ⚠️ **Note**: Configuration values, secrets, and thresholds used on the live site are intentionally not published in this repository.

---

## 📋 Requirements

### Automatic Installation
The installer handles all dependencies automatically. Simply run:
```bash
sudo ./install.sh
```

### Manual Requirements
If installing manually, you need:

### Origin
- PHP **8+**
- HTTPS (required for Secure cookie + WebCrypto)
- Apache 2.4+

### Optional / recommended
- **ModSecurity** (Apache connector + CRS optional) for rate-limiting `/__ab/*`
- If behind Cloudflare: Apache `mod_remoteip` configured to restore the **real client IP**

### Secret (required)
- `AB_POW_SECRET` must be set in the environment
- **Minimum:** 48 characters  
- **Recommended:** 64+ characters

---

## 📂 Repository layout

```
pow-shield-php/
├─ __ab/
│  ├─ pow.php
│  └─ pow-verify.php
├─ modsecurity/
│  └─ ab_pow_ratelimit.conf
├─ apache/
│  └─ sites-available/
│     ├─ example.com-redirect.conf.example
│     └─ example.com.conf.example
├─ scripts/
│  └─ rotate-pow-secret.sh.example
├─ systemd/
│  ├─ rotate-pow-secret.service.example
│  └─ rotate-pow-secret.timer.example
├─ assets/img/
│  ├─ README.md
│  └─ .gitkeep
├─ docs/
│  ├─ cloudflare-notes.md
│  ├─ installation-checklist.md
│  └─ modsecurity-global-notes.md
├─ install.sh              # 🆕 Automated installer
├─ uninstall.sh            # 🆕 Automated uninstaller
└─ README.md
```

---

## 🚀 Quick Installation

We provide automated installation scripts for easy setup:

### Option A: Automated Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/AfterPacket/pow-shield-php.git
cd pow-shield-php

# Make scripts executable
chmod +x install.sh uninstall.sh

# Run interactive installer
sudo ./install.sh
```

> 📖 **Full Installation Guide**: See [INSTALL.md](INSTALL.md) for detailed instructions, troubleshooting, and advanced configuration options.

The installer will:
- ✅ Install all required dependencies (Apache, PHP, OpenSSL)
- ✅ Generate secure PoW secret automatically
- ✅ Deploy PoW endpoints and assets
- ✅ Configure Apache virtual hosts
- ✅ Set up ModSecurity rate limiting (optional)
- ✅ Configure Let's Encrypt SSL (optional)
- ✅ Set up automatic secret rotation

### Installation Options

**Interactive Mode (Default)**
```bash
sudo ./install.sh
```
Follow the prompts to configure your installation.

**Non-Interactive with Let's Encrypt**
```bash
sudo ./install.sh -d example.com -w /var/www/html -l admin@example.com -e
```

**Non-Interactive with Existing SSL**
```bash
sudo ./install.sh -d example.com -w /var/www/html \
  -c /etc/ssl/certs/cert.pem -k /etc/ssl/private/key.pem -e
```

**Skip ModSecurity**
```bash
sudo ./install.sh -d example.com -w /var/www/html -s
```

### Installation Flags

| Flag | Description |
|------|-------------|
| `-d, --domain` | Domain name (e.g., example.com) |
| `-w, --webroot` | Web root directory path |
| `-c, --cert` | SSL certificate path (optional) |
| `-k, --key` | SSL key path (optional) |
| `-l, --letsencrypt` | Use Let's Encrypt with email |
| `-e, --enable` | Enable site with a2ensite after install |
| `-s, --skip-modsec` | Skip ModSecurity installation |
| `-n, --non-interactive` | Run without prompts |
| `-h, --help` | Show help message |

---

## 🗑️ Uninstallation

To completely remove pow-shield-php:

```bash
# Interactive uninstaller
sudo ./uninstall.sh

# Force removal without prompts
sudo ./uninstall.sh -d example.com -w /var/www/html -f

# Keep the PoW secret file
sudo ./uninstall.sh -d example.com -w /var/www/html -k

# Also remove ModSecurity rules
sudo ./uninstall.sh -d example.com -w /var/www/html -m
```

The uninstaller will:
- ✅ Backup all files before removal
- ✅ Disable and remove virtual hosts
- ✅ Remove PoW endpoints
- ✅ Remove systemd rotation (optional)
- ✅ Remove ModSecurity rules (optional)
- ✅ Test Apache config before reload

---

## 🛠️ Manual Installation

If you prefer manual installation:

### 1) Deploy `/__ab/` endpoints

Copy the following files into your site webroot:
- `__ab/pow.php`
- `__ab/pow-verify.php`

They must resolve at:
- `https://example.com/__ab/pow.php`
- `https://example.com/__ab/pow-verify.php`

> ✅ **Tip**: keep `/__ab/` excluded from caching and from other WAF rules that might block POST.

---

### 2) Add the image used by `pow.php` (optional UI)

Your `pow.php` references:
```
/assets/img/clank.jpg
```

To keep this path:
- place the image at `assets/img/clank.jpg` in your webroot

Or update `$MEME_SRC` inside `__ab/pow.php`.

---

## 🔐 Secret management (recommended): `/etc/apache2/pow.env`

Instead of embedding secrets in vhost configs, load them from a root-owned include file:

- `/etc/apache2/pow.env` (root-owned, mode `600`)
- included in your HTTPS vhost via:
  ```apache
  IncludeOptional /etc/apache2/pow.env
  ```

### Create the initial env file

```bash
sudo install -d -m 0755 /etc/apache2

sudo bash -c 'umask 077; SECRET="$(openssl rand -base64 64 | tr -d "\n")"; \
  printf "%s\n" "# Managed by pow-shield-php" "SetEnv AB_POW_SECRET \"$SECRET\"" > /etc/apache2/pow.env'

sudo chown root:root /etc/apache2/pow.env
sudo chmod 600 /etc/apache2/pow.env

sudo apachectl -t
sudo systemctl reload apache2
```

> ⚠️ **Never commit secrets to git.**

---

## 🔄 Secret rotation (optional): script + systemd service + timer

Rotating the PoW secret reduces replay value if a cookie/token leaks.
To avoid breaking in-flight challenges, rotate with overlap:

- New secret stored as `AB_POW_SECRET`
- Old secret preserved as `AB_POW_SECRET_PREV`

✅ For this to work, your `pow-verify.php` should accept either secret when validating.

### A) Rotation script

Save as:
```
/usr/local/sbin/rotate-pow-secret.sh
```

```bash
#!/bin/bash
set -euo pipefail

OUT="/etc/apache2/pow.env"
TMP="$(mktemp)"
umask 077

# Pull current secret (if any) from existing file
CURRENT=""
if [[ -f "$OUT" ]]; then
  CURRENT="$(awk -F'"' '/SetEnv[[:space:]]+AB_POW_SECRET[[:space:]]+"/ {print $2; exit}' "$OUT" || true)"
fi

NEW="$(openssl rand -base64 64 | tr -d '\n')"

{
  echo '# Managed by rotate-pow-secret.sh'
  echo "SetEnv AB_POW_SECRET \"$NEW\""
  if [[ -n "${CURRENT}" ]]; then
    echo "SetEnv AB_POW_SECRET_PREV \"$CURRENT\""
  fi
} > "$TMP"

chown root:root "$TMP"
chmod 600 "$TMP"
mv -f "$TMP" "$OUT"

# Safety: verify Apache config first
apachectl -t

# Reload, not restart (keeps connections)
systemctl reload apache2
```

Install + test:

```bash
sudo install -m 0755 /usr/local/sbin/rotate-pow-secret.sh /usr/local/sbin/rotate-pow-secret.sh
sudo /usr/local/sbin/rotate-pow-secret.sh
```

### B) systemd service

Create:
```
/etc/systemd/system/rotate-pow-secret.service
```

```ini
[Unit]
Description=Rotate AB_POW_SECRET for pow-shield-php and reload Apache
Wants=apache2.service
After=apache2.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/rotate-pow-secret.sh
User=root
Group=root

# Hardening (safe defaults)
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/apache2/pow.env
```

### C) systemd timer (hourly)

Create:
```
/etc/systemd/system/rotate-pow-secret.timer
```

```ini
[Unit]
Description=Hourly rotation for AB_POW_SECRET (pow-shield-php)

[Timer]
OnCalendar=hourly
Persistent=true
RandomizedDelaySec=120
Unit=rotate-pow-secret.service

[Install]
WantedBy=timers.target
```

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now rotate-pow-secret.timer
sudo systemctl list-timers --all | grep rotate-pow-secret
```

Manual trigger:

```bash
sudo systemctl start rotate-pow-secret.service
sudo systemctl status rotate-pow-secret.service --no-pager
```

---

## 🌐 Install: Apache vhost (PoW gating + skip rules)

Use the sanitized examples in `apache/sites-available/`.

Two common patterns:

**Option A — Redirect to `/__ab/pow.php` (visible PoW URL)**
- simplest
- user sees `/__ab/pow.php?...`

**Option B — Internal rewrite (clean URL)**
- keeps the original URL in the address bar
- uses `[PT]` internally to serve `pow.php`

In both options, always skip:
- `/__ab/*` (prevents loops)
- `/status/*` (your private panels/JSON)
- static assets
- non-GET/HEAD methods

---

## 🛡️ ModSecurity: rate-limit only the PoW endpoints (recommended)

Rules are provided in:
```
modsecurity/ab_pow_ratelimit.conf
```

### A) Install ModSecurity (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y libapache2-mod-security2
sudo a2enmod security2
sudo systemctl reload apache2
```

Confirm:

```bash
apachectl -M | grep -i security
```

### B) Enable engine

In `/etc/modsecurity/modsecurity.conf`:

```apache
SecRuleEngine On
SecRequestBodyAccess On
```

Reload:

```bash
sudo systemctl reload apache2
```

### C) Include PoW rules

Copy:

```bash
sudo mkdir -p /etc/modsecurity
sudo cp modsecurity/ab_pow_ratelimit.conf /etc/modsecurity/ab_pow_ratelimit.conf
```

Then include it in your vhost or global `security2` config:

```apache
IncludeOptional /etc/modsecurity/ab_pow_ratelimit.conf
Header always set Retry-After "30" env=AB_RL
```

### D) Verify enforcement

```bash
for i in $(seq 1 80); do
  curl -sk https://example.com/__ab/pow.php?next=/ >/dev/null -w "%{http_code}\n"
done
```

You should see `429` once the limit triggers.

---

## 🚨 Additional DDoS Mitigation (Apache-level)

PoW is application-layer cost. It helps with:
- Basic bot spam
- Naive request floods
- Large-scale scraping (makes it expensive per request)

It does not stop all L7 attacks by itself. Pair it with:
- ModSecurity rate limiting (especially on `/__ab/pow-verify.php`)
- `mod_reqtimeout` (Slowloris mitigation)
- Connection limits / MPM tuning
- Correct real-IP restoration when behind Cloudflare

> 📝 **Note**: Pattern matters more than specific values; deploy thresholds appropriate to your traffic.

---

## ☁️ Cloudflare (recommended configuration)

See `docs/cloudflare-notes.md`.

Important settings:
- ❌ **Bot Fight Mode / "Stop Bot Attack"**: OFF (can interfere with PoW)
- 🚫 **Cache bypass for:**
  - `/__ab/pow.php`
  - `/__ab/pow-verify.php`
- 🌍 **Restore real client IP** at the origin using `mod_remoteip`

---

## 🔧 Troubleshooting

### Infinite "Checking your browser…" loop

**Common causes:**
- Cloudflare caching PoW endpoints
- Cloudflare bot challenges enabled
- Cookies blocked by browser
- WAF blocking `/__ab/pow-verify.php`
- Using PoW as an `ErrorDocument 403` (can recurse)

**Fix:**
- Disable Bot Fight / Stop Bot Attack
- Bypass cache for PoW endpoints
- Confirm `Set-Cookie: abp=...` is issued over HTTPS
- Don't use PoW as 403 handler; use a static error page instead

### LibreWolf / hardened Firefox shows "slow-device"

- Lower difficulty for hardened UAs (or remove the "hard fail")
- Extend TTL for challenge tokens
- Ensure cookies aren't blocked for the site

### Getting HTTP 429 during testing

- ModSecurity limits are working as intended
- Wait for the window to expire (often 60 seconds)

---

## 🔒 Security notes

- `AB_POW_SECRET` must be long and random (>= 48 chars; 64+ recommended)
- Never commit secrets to git
- Consider rotating the secret with overlap (`AB_POW_SECRET_PREV`) to reduce replay value
- Keep PoW endpoints uncached and allow POST to `/__ab/pow-verify.php`
- If behind Cloudflare, configure real IP restoration before using per-IP rate limits

---

## 🧩 Contributing

Contributions are welcome! To participate:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-enhancement`
3. Commit your changes: `git commit -m "Add: your feature"`
4. Push to your fork: `git push origin feature/your-enhancement`
5. Open a Pull Request

---

## 🐛 Issues & Support

Found a bug or have a feature request? Please [open an issue](https://github.com/YourUsername/pow-shield-php/issues) with:

- Steps to reproduce
- Expected vs actual behavior
- PHP and Apache versions
- Operating system

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0**.  
See the [LICENSE](LICENSE) file for full details.

---

**Enjoy Fighting BOTS** 🤖🛡️
