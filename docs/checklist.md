
---

# `docs/modsecurity-global-notes.md`

```md
# ModSecurity global config notes (sanitized)

This repo does not ship a full `/etc/modsecurity/modsecurity.conf`.
It documents the minimum global settings expected for the PoW gate.

## Required
- `SecRuleEngine On` (or `DetectionOnly` during staged rollout)

## Recommended
Enable JSON request body processor for `application/json` if needed by other parts of your site.
The PoW endpoint limiter runs in `phase:1` and keys off `REQUEST_URI`, so it does not rely on body parsing.

Example:
```apache
SecRuleEngine On

SecRule REQUEST_HEADERS:Content-Type "application/json" \
  "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"



---

# `docs/installation-checklist.md`

```md
# Installation Checklist

## Files
- [ ] `__ab/pow.php` deployed
- [ ] `__ab/pow-verify.php` deployed
- [ ] `modsecurity/ab_pow_ratelimit.conf` installed at:
      `/etc/apache2/conf/modsecurity/ab_pow_ratelimit.conf`

## Secret
- [ ] `AB_POW_SECRET` set (64+ chars recommended)

## Cloudflare (if used)
- [ ] Bot Fight Mode OFF
- [ ] Cache bypass for:
  - `/__ab/pow.php`
  - `/__ab/pow-verify.php`

## Real IP (if used with Cloudflare)
- [ ] `a2enmod remoteip`
- [ ] `cloudflare-realip.conf` enabled
- [ ] Apache reloaded

## Validation
- [ ] A protected URL without cookie `abp` redirects to `/__ab/pow.php`
- [ ] PoW completes and sets cookie `abp`
- [ ] Abuse triggers 429 on PoW endpoints (ModSecurity)



---

# `docs/installation-checklist.md`

```md
# Installation Checklist

## Files
- [ ] `__ab/pow.php` deployed
- [ ] `__ab/pow-verify.php` deployed
- [ ] `modsecurity/ab_pow_ratelimit.conf` installed at:
      `/etc/apache2/conf/modsecurity/ab_pow_ratelimit.conf`

## Secret
- [ ] `AB_POW_SECRET` set (64+ chars recommended)

## Cloudflare (if used)
- [ ] Bot Fight Mode OFF
- [ ] Cache bypass for:
  - `/__ab/pow.php`
  - `/__ab/pow-verify.php`

## Real IP (if used with Cloudflare)
- [ ] `a2enmod remoteip`
- [ ] `cloudflare-realip.conf` enabled
- [ ] Apache reloaded

## Validation
- [ ] A protected URL without cookie `abp` redirects to `/__ab/pow.php`
- [ ] PoW completes and sets cookie `abp`
- [ ] Abuse triggers 429 on PoW endpoints (ModSecurity)
