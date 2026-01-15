# pow-shield-php

A lightweight **Proof-of-Work (PoW)** gateway for PHP sites that reduces abusive traffic **without CAPTCHAs**.  
It issues a signed cookie (`abp`) after a browser completes a **SHA-256** work check, then allows normal access.

This repository includes:
- ✅ PoW challenge page: `__ab/pow.php`
- ✅ PoW verifier + signed cookie: `__ab/pow-verify.php`
- ✅ ModSecurity rate limits for PoW endpoints: `modsecurity/ab_pow_ratelimit.conf`
- ✅ Apache vhost examples (sanitized to `example.com`) with PoW "skip" rules
- ✅ Cloudflare compatibility notes (cache bypass + real client IP restore)

This repository intentionally excludes:
- ❌ TLS certificates / private keys
- ❌ secrets (your `AB_POW_SECRET`)
- ❌ server logs / user data

---

## How it works (request flow)

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
   - user-agent binding
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

The deployment demonstrates real-world behavior under normal traffic
conditions and during active bot pressure.

> ⚠️ Note  
> Configuration values, secrets, and thresholds used on the live site are
> intentionally not published in this repository.

## Requirements

### Origin
- PHP **8+**
- HTTPS
- Apache
- Recommended: **ModSecurity v3** (OWASP CRS optional)

### Optional (if behind Cloudflare)
- Apache `mod_remoteip` configured to restore the **real client IP**

### Secret (required)
- `AB_POW_SECRET` must be set in the environment
- **Minimum:** 48 characters  
- **Recommended:** 64+ characters

---

## Repository layout
```
pow-shield-php/
├─ __ab/
│  ├─ pow.php
│  └─ pow-verify.php
├─ modsecurity/
│  └─ ab_pow_ratelimit.conf
├─ apache/
│  ├─ conf-available/
│  │  ├─ security2.conf.example
│  │  └─ cloudflare-realip.conf.example
│  └─ sites-available/
│     ├─ example.com-redirect.conf.example
│     └─ example.com.conf.example
├─ assets/img/
│  ├─ README.md
│  └─ .gitkeep
└─ docs/
   ├─ cloudflare-notes.md
   ├─ installation-checklist.md
   └─ modsecurity-global-notes.md
```

---

## Install: PoW endpoints

### 1) Deploy `/__ab/` endpoints
Copy the following files into your site webroot:
- `__ab/pow.php`
- `__ab/pow-verify.php`

They must resolve at:
- `https://example.com/__ab/pow.php`
- `https://example.com/__ab/pow-verify.php`

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

### 3) Set the PoW secret (required)

Set a long random value in your environment:
```bash
export AB_POW_SECRET="REPLACE_WITH_A_LONG_RANDOM_SECRET_64_CHARS_MIN"
```

Common places to set this:
- systemd service environment
- Apache env vars (`/etc/apache2/envvars` or `SetEnv`)
- hosting control panel environment settings

> ⚠️ **Never commit secrets to git.**

---

## Install: Apache vhost (PoW gating + skip rules)

Use the sanitized examples provided:

**HTTP → HTTPS redirect:**
```
apache/sites-available/example.com-redirect.conf.example
```

**HTTPS vhost with PoW gate:**
```
apache/sites-available/example.com.conf.example
```

The HTTPS vhost gates only when:
- request method is `GET` or `HEAD`
- request is not under `/status/` or `/__ab/`
- request is not a static asset (`.css`, `.js`, `.png`, etc.)
- cookie `abp` is missing

---

## Install: ModSecurity (full process)

ModSecurity is used only to protect the PoW endpoints from abuse.

### What ModSecurity does here
- Rate-limits `/__ab/pow.php`
- Rate-limits `/__ab/pow-verify.php`
- Returns `429 Too Many Requests` on abuse

Rules are provided in:
```
modsecurity/ab_pow_ratelimit.conf
```

### A) Install ModSecurity + Apache connector (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install -y libapache2-mod-security2
```

Enable the module:
```bash
sudo a2enmod security2
sudo systemctl reload apache2
```

Verify it is loaded:
```bash
apachectl -M | grep -i security
```

### B) Enable the ModSecurity engine

Edit your ModSecurity config (commonly `/etc/modsecurity/modsecurity.conf`) and ensure:
```apache
SecRuleEngine On
SecRequestBodyAccess On
```

Reload Apache:
```bash
sudo systemctl reload apache2
```

### C) Install the PoW rate-limit rules
```bash
sudo mkdir -p /etc/apache2/conf/modsecurity
sudo cp modsecurity/ab_pow_ratelimit.conf /etc/apache2/conf/modsecurity/ab_pow_ratelimit.conf
```

### D) Include the PoW rules in Apache

Use the provided example:
```
apache/conf-available/security2.conf.example
```

Typical setup:
```bash
sudo cp apache/conf-available/security2.conf.example /etc/apache2/conf-available/security2.conf
sudo a2enconf security2
sudo systemctl reload apache2
```

### E) Verify ModSecurity enforcement

Test for rate limiting:
```bash
for i in $(seq 1 80); do
  curl -sk https://example.com/__ab/pow.php >/dev/null -w "%{http_code}\n"
done
```

You should see `429` responses once the limit is exceeded.

---

## Additional DDoS Mitigation (Apache-level)

In addition to PoW + ModSecurity rate limiting, this deployment uses Apache-level connection defenses to reduce impact from common low-and-slow attacks (e.g., Slowloris / request header drip).

Typical hardening includes:
- limiting request header/body read timeouts
- limiting concurrent connections per IP
- keeping keep-alive behavior conservative under load
- ensuring reverse proxy/CDN IP restoration is correct (if applicable)

> Note: Specific values are deployment-specific and intentionally not published verbatim in this repo.
> The goal is to provide the pattern, not a fingerprintable configuration.

### Apache modules commonly used for slow/connection attacks

Depending on your distro and Apache build, the following may be used:
- `mod_reqtimeout` (request read timeouts; strong Slowloris mitigation)
- `mod_remoteip` (real client IP behind Cloudflare)
- MPM tuning (worker/event/prefork) for connection handling under pressure

These sit *alongside*:
- PoW (application-layer cost)
- ModSecurity rules (endpoint rate limiting + WAF-style controls)


## Cloudflare (recommended configuration)

See `docs/cloudflare-notes.md`.

Required settings:
- ❌ **Bot Fight Mode / "Stop Bot Attack"**: OFF
- 🚫 **Cache bypass for:**
  - `/__ab/pow.php`
  - `/__ab/pow-verify.php`
- 🌍 **Restore real client IP** at the origin using Apache `mod_remoteip`
  - see `apache/conf-available/cloudflare-realip.conf.example`

---

## Troubleshooting

### Infinite "Checking your browser…" loop

Common causes:
- Cloudflare caching PoW endpoints
- Cloudflare bot challenges enabled
- Cookies blocked by browser
- WAF blocking `/__ab/pow-verify.php`

Fix:
- disable Bot Fight / Stop Bot Attack
- bypass cache for PoW endpoints
- confirm `Set-Cookie: abp=...` is issued over HTTPS

### Getting HTTP 429 during testing

- ModSecurity rate limits are working as intended
- Wait for the rule window to expire (typically 60 seconds)

---

## License

GNU GENERAL PUBLIC LICENSE— see [LICENSE](LICENSE).

---

**Enjoy Fighting BOTS** 🤖🛡️
