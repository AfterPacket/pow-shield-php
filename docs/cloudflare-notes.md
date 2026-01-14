# Cloudflare Notes — PoW Shield Compatibility & Origin IP Handling

This document describes the Cloudflare configuration required for **pow-shield-php**
to function correctly **without interfering** with the Proof-of-Work flow.

---

## ❌ Bot Fight Mode / Stop Bot Attack — MUST BE OFF

- **Bot Fight Mode**: OFF  
- **“Stop Bot Attack”**: OFF  

**Why**
- Cloudflare bot challenges inject JavaScript and heuristics that can conflict with PoW
- Can cause cookie (`abp`) set failures and “Checking your browser…” loops
- PoW already provides a deterministic challenge

---

## 🚫 Cache Rules — CRITICAL

Cloudflare caching must be bypassed for:

```text
/__ab/pow.php
/__ab/pow-verify.php



Why

PoW challenges are per-request and time-bound

Cached challenges expire and fail verification

Verify endpoint sets cookies and must never be cached

Recommended settings:

Cache status: Bypass

Respect origin headers: Yes

Edge TTL: Disabled

🌍 Restore Real Client IP at the Origin (Apache)

If you proxy through Cloudflare, Apache will normally see Cloudflare edge IPs.

To restore real client IPs:

enable Apache mod_remoteip

trust Cloudflare IP ranges

use header CF-Connecting-IP

See:

apache/conf-available/cloudflare-realip.conf.example

Why this matters

correct ModSecurity per-IP rate limiting

correct logging / attribution

avoids every visitor sharing the same “client IP”

✅ Expected Request Flow
Client (real IP)
  ↓
Cloudflare (CDN / TLS)
  ↓
Apache (mod_remoteip restores real IP)
  ↓
ModSecurity (rate limits PoW endpoints)
  ↓
PoW (pow.php → pow-verify.php)
  ↓
Cookie issued (abp)
  ↓
Protected content
