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
