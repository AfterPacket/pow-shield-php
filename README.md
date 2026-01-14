# pow-shield-php

A lightweight Proof-of-Work (PoW) gateway for PHP sites that reduces abusive traffic without CAPTCHAs.
It issues a signed cookie (`abp`) after a browser completes a SHA-256 PoW check.

Includes:
- PoW endpoints (`/__ab/pow.php` + `/__ab/pow-verify.php`)
- Cloudflare-friendly ModSecurity rate limiting for PoW endpoints
- Apache vhost examples (sanitized to `example.com`)
- Cloudflare configuration notes (cache bypass + Bot Fight OFF)
- Cloudflare real client IP restoration for Apache (`mod_remoteip`)

This repository intentionally excludes:
- TLS certificates / private keys
- secrets (`AB_POW_SECRET`)
- server logs / user data

---

## How it works

1) Client requests a protected URL without cookie `abp`  
2) Apache redirects to `/__ab/pow.php?next=...`  
3) Browser runs PoW:
   - compute `sha256(TOKEN + "." + counter)` until it has enough leading zero bits
4) Browser POSTs `token`, `counter`, and `next` to `/__ab/pow-verify.php`
5) Server verifies PoW + token integrity, then sets signed cookie `abp`
6) Client is redirected back to the original URL

---

## Requirements

- PHP 8+
- HTTPS
- Apache (examples provided)
- Recommended: ModSecurity
- Recommended (if behind Cloudflare): `mod_remoteip` configured to restore real client IP
- Environment variable: `AB_POW_SECRET` (>= 48 chars; 64+ recommended)

---

## Install (quick)

### 1) Deploy endpoints
Place these files under your site webroot:
- `__ab/pow.php`
- `__ab/pow-verify.php`

### 2) Add the image used by `pow.php` (optional UI)
Your `pow.php` references:
`$MEME_SRC = '/assets/img/clank.jpg';`

Put the image at:
- `assets/img/clank.jpg` (web path `/assets/img/clank.jpg`)

Or change `$MEME_SRC` in `__ab/pow.php`.

### 3) Set the secret
Set a strong secret in your web server env (do not commit):
- `AB_POW_SECRET="YOUR_LONG_RANDOM_SECRET"`

### 4) ModSecurity rate limits
Install:
- `modsecurity/ab_pow_ratelimit.conf` → `/etc/apache2/conf/modsecurity/ab_pow_ratelimit.conf`

Then include it via:
- `apache/conf-available/security2.conf.example`

### 5) Apache vhosts
Enable:
- `apache/sites-available/example.com-redirect.conf.example`
- `apache/sites-available/example.com.conf.example`

### 6) If using Cloudflare
- Bot Fight Mode / “Stop Bot Attack” MUST be OFF
- Cache bypass MUST be enabled for `/__ab/pow.php` and `/__ab/pow-verify.php`
- Configure `mod_remoteip` with Cloudflare IP ranges

See: `docs/cloudflare-notes.md` and `apache/conf-available/cloudflare-realip.conf.example`

---

## Notes

- The vhost example skips PoW for:
  - `/status/`
  - `/__ab/`
  - non-GET/HEAD methods
  - common static assets
- PoW endpoints send strict no-cache headers
- Debug mode in `pow.php` is locked
