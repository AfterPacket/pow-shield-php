<?php
declare(strict_types=1);

/**
 * /__ab/pow.php
 * JS proof-of-work challenge page that sets a signed cookie via /__ab/pow-verify.php.
 * Fixes:
 * - LibreWolf/strict privacy browsers: lower difficulty + no time-based hard fail
 * - Debug is locked down (env + allowlist)
 * - Better cookie test (Secure on https)
 * - bfcache handling for Safari/mobile
 */

$SECRET = getenv('AB_POW_SECRET') ?: 'CHANGE_ME_LONG_RANDOM_SECRET_64+CHARS';

// Force HTTPS (needed for WebCrypto)
function is_https_request(): bool {
  if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') return true;

  $xfp = strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''));
  if ($xfp === 'https') return true;

  $cfv = (string)($_SERVER['HTTP_CF_VISITOR'] ?? '');
  if ($cfv !== '' && strpos($cfv, '"https"') !== false) return true;

  return false;
}

if (!is_https_request()) {
  $host = (string)($_SERVER['HTTP_HOST'] ?? 'lassiter.eu');
  $uri  = (string)($_SERVER['REQUEST_URI'] ?? '/__ab/pow.php');
  header("Location: https://{$host}{$uri}", true, 302);
  exit;
}
// Refuse to run with default/weak secret
if ($SECRET === 'CHANGE_ME_LONG_RANDOM_SECRET_64+CHARS' || strlen($SECRET) < 48) {
  http_response_code(500);
  header('Content-Type: text/plain; charset=utf-8');
  echo "PoW misconfigured: set AB_POW_SECRET (>=48 chars).";
  exit;
}

$COOKIE_NAME   = 'abp';
$COOKIE_TTL    = 60 * 60 * 6;     // verify.php should use same
$CHALLENGE_TTL = 120;

$BITS_DESKTOP  = 20;              // normal desktop
$BITS_MOBILE   = 18;              // mobile
$BITS_PRIVACY  = 16;              // LibreWolf/strict privacy browsers (lower = fewer false positives)

$MEME_SRC = '/assets/img/clank.jpg';

// ---- helpers ----
function b64url_enc(string $bin): string { return rtrim(strtr(base64_encode($bin), '+/', '-_'), '='); }
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
function hmac_sig(string $payload, string $secret): string { return b64url_enc(hash_hmac('sha256', $payload, $secret, true)); }

function ua_str(): string { return (string)($_SERVER['HTTP_USER_AGENT'] ?? ''); }

function is_mobile_ua(): bool {
  $ua = strtolower(ua_str());
  foreach (['mobile','android','iphone','ipad','ipod','iemobile','windows phone','opera mini','silk','kindle'] as $n) {
    if (strpos($ua, $n) !== false) return true;
  }
  return false;
}

function is_privacy_ua(): bool {
  $ua = strtolower(ua_str());
  if (strpos($ua, 'librewolf') !== false) return true;
  // add more if you want:
  // if (strpos($ua, 'waterfox') !== false) return true;
  return false;
}



function safe_rel_url(string $u): string {
  $u = trim($u);
  if ($u === '' || $u[0] !== '/') return '/';
  if (str_starts_with($u, '//')) return '/';
  if (str_contains($u, "\r") || str_contains($u, "\n")) return '/';
  if (str_starts_with($u, '/__ab/')) return '/';
  return $u;
}

/**
 * Debug LOCKDOWN:
 * - must have AB_POW_DEBUG=1
 * - and the request IP must be in allowlist
 */
function client_ip(): string {
  // If you have Apache mod_remoteip configured, REMOTE_ADDR will be the real client.
  // Otherwise behind Cloudflare it’ll be a CF edge IP.
  return (string)($_SERVER['REMOTE_ADDR'] ?? '');
}
$ALLOW_DEBUG = (getenv('AB_POW_DEBUG') === '1');
$DEBUG_ALLOWLIST = array_filter(array_map('trim', explode(',', (string)(getenv('AB_POW_DEBUG_ALLOWLIST') ?: ''))));
$debug = false;
if ($ALLOW_DEBUG && isset($_GET['debug']) && $_GET['debug'] === '1') {
  $ip = client_ip();
  if ($DEBUG_ALLOWLIST && in_array($ip, $DEBUG_ALLOWLIST, true)) $debug = true;
}

$next = safe_rel_url((string)($_GET['next'] ?? '/'));
$qs   = ltrim((string)($_GET['qs'] ?? ''), '?');
$target = $next . ($qs !== '' ? (str_contains($next, '?') ? '&' : '?') . $qs : '');

// Tune difficulty/ttl
$isMobile  = is_mobile_ua();
$isPrivacy = is_privacy_ua();

$BITS = $isMobile ? $BITS_MOBILE : $BITS_DESKTOP;
if ($isPrivacy) $BITS = min($BITS, $BITS_PRIVACY);

$challengeTtl = $CHALLENGE_TTL;
if ($isMobile)  $challengeTtl = max(180, $challengeTtl);
if ($isPrivacy) $challengeTtl = max(300, $challengeTtl);

// challenge payload: ts.exp.bits.salt.uaHash
$ts = time();
$exp = $ts + $challengeTtl;
$salt = b64url_enc(random_bytes(18));
$uaHash = b64url_enc(hash('sha256', ua_str(), true));

$payload = $ts . '.' . $exp . '.' . $BITS . '.' . $salt . '.' . $uaHash;
$token   = $payload . '.' . hmac_sig($payload, $SECRET);

// No-cache + safe headers
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

// CSP: allow inline only here
header(
  "Content-Security-Policy: ".
  "default-src 'none'; ".
  "base-uri 'none'; ".
  "frame-ancestors 'none'; ".
  "form-action 'none'; ".
  "img-src 'self' data:; ".
  "style-src 'unsafe-inline'; ".
  "script-src 'unsafe-inline'; ".
  "connect-src 'self';"
);
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>Checking your browser…</title>
  <style>
    :root{
      color-scheme: dark;
      --bg:#070a14;
      --card:rgba(255,255,255,.06);
      --border:rgba(255,255,255,.12);
      --text:#e8eefc;
      --muted:rgba(232,238,252,.72);
      --danger:#fca5a5;
      --ok:#86efac;
      --grad:linear-gradient(90deg,#60a5fa,#a78bfa,#fb7185);
    }
    html,body{height:100%}
    body{
      margin:0;
      font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
      background:
        radial-gradient(1200px 800px at 20% 15%, rgba(168,85,247,.18), transparent 60%),
        radial-gradient(1000px 700px at 80% 30%, rgba(59,130,246,.14), transparent 65%),
        var(--bg);
      color:var(--text);
      display:flex; align-items:center; justify-content:center;
      padding:20px;
      -webkit-font-smoothing:antialiased;
      text-rendering:geometricPrecision;
    }
    .wrap{width:min(860px,100%)}
    .card{
      background:var(--card);
      border:1px solid var(--border);
      border-radius:18px;
      padding:16px;
      box-shadow:0 18px 55px rgba(0,0,0,.35);
      overflow:hidden;
    }
    .hero{display:flex;flex-direction:column;gap:14px;align-items:center;text-align:center}
    .meme{
      width:100%;
      border-radius:16px;
      overflow:hidden;
      border:1px solid rgba(255,255,255,.10);
      background:rgba(0,0,0,.28);
      aspect-ratio:16/9;
      max-height:380px;
    }
    .meme img{
      display:block;
      width:100%;
      height:100%;
      object-fit:contain;
      object-position:center;
      background:rgba(0,0,0,.15);
    }
    .title{font-weight:950;letter-spacing:.01em;font-size:20px;margin-top:4px}
    .sub{color:var(--muted);font-size:14px;line-height:1.45;max-width:60ch}
    .bar{
      width:min(560px,100%);
      height:10px;border-radius:999px;
      background:rgba(255,255,255,.10);
      overflow:hidden;border:1px solid rgba(255,255,255,.10);
      margin-top:6px;
    }
    .bar>div{height:100%;width:0%;background:var(--grad);transition:width .12s ease}
    .row{
      width:min(560px,100%);
      display:flex;align-items:center;justify-content:space-between;gap:10px;
      margin-top:10px;flex-wrap:wrap;
    }
    .chip{
      font-size:12px;color:rgba(255,255,255,.80);
      background:rgba(255,255,255,.06);
      border:1px solid rgba(255,255,255,.10);
      border-radius:999px;padding:6px 10px;
      font-weight:800;letter-spacing:.08em;text-transform:uppercase;
    }
    .muted{color:var(--muted);font-size:13px}
    .danger{color:var(--danger);font-size:13px}
    .ok{color:var(--ok);font-size:13px}
    button{
      appearance:none;
      border:1px solid rgba(255,255,255,.15);
      background:rgba(255,255,255,.08);
      color:#fff;font-weight:900;
      border-radius:12px;padding:10px 14px;cursor:pointer
    }
    button:active{transform:scale(.99)}
    button:focus-visible{outline:2px solid rgba(168,85,247,.85);outline-offset:2px}
    .actions{display:flex;gap:10px;flex-wrap:wrap;justify-content:center;margin-top:10px}
    .diag{
      width:min(560px,100%);
      text-align:left;
      font-family:ui-monospace,Menlo,Consolas,monospace;
      font-size:12px;
      background:rgba(0,0,0,.30);
      border:1px solid rgba(255,255,255,.10);
      border-radius:14px;
      padding:10px;
      color:rgba(232,238,252,.82);
      display:none;
      overflow:auto;
      max-height:220px;
    }
    .pow-footer{margin-top:14px;display:flex;justify-content:center}
    .pow-credit{
      display:inline-flex;align-items:center;gap:10px;
      padding:10px 12px;border-radius:999px;
      background:rgba(255,255,255,.06);
      border:1px solid rgba(255,255,255,.12);
      box-shadow:0 12px 40px rgba(0,0,0,.25);
      backdrop-filter:blur(10px);
      -webkit-backdrop-filter:blur(10px);
      max-width:100%;
    }
    .pow-credit .mark{width:18px;height:18px;flex:0 0 auto}
    .pow-credit .txt{font-size:12px;color:rgba(232,238,252,.78);white-space:nowrap}
    .pow-credit a{color:rgba(147,197,253,.92);text-decoration:none;font-weight:900}
    .pow-credit a:hover{text-decoration:underline}
    @media (max-width:420px){.pow-credit .txt{font-size:11px;white-space:normal}}
    @media (prefers-reduced-motion: reduce){.bar>div{transition:none}}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="hero">

        <div class="meme" aria-hidden="true">
          <img src="<?= h($MEME_SRC) ?>" alt="">
        </div>

        <div class="title">Checking your browser…</div>
        <div class="sub">
          This site uses a lightweight proof-of-work check to reduce abusive traffic.
          It should complete quickly for normal visitors.
        </div>

        <div class="bar" aria-label="Progress"><div id="pbar"></div></div>

        <div class="row">
          <span class="chip" id="modeChip"><?= $isMobile ? "Mobile mode" : ($isPrivacy ? "Privacy mode" : "Standard mode") ?></span>
          <span class="muted" id="etaText">Starting…</span>
        </div>

        <noscript>
          <div class="danger" style="margin-top:10px">JavaScript is required to continue.</div>
        </noscript>

        <div class="actions">
          <button id="retry" type="button" style="display:none">Retry</button>
        </div>

        <div id="diag" class="diag" aria-live="polite"></div>

        <div class="muted" style="margin-top:6px">
          Difficulty: <strong><?= (int)$BITS ?></strong> • Challenge TTL: <strong><?= (int)$challengeTtl ?>s</strong>
        </div>

        <div class="pow-footer" role="contentinfo">
          <div class="pow-credit">
            <svg class="mark" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
              <defs>
                <linearGradient id="apg" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0" stop-color="#60a5fa"/>
                  <stop offset="0.5" stop-color="#a78bfa"/>
                  <stop offset="1" stop-color="#fb7185"/>
                </linearGradient>
              </defs>
              <path fill="url(#apg)" d="M12 2.4c.2 0 .3 0 .5.1l7 2.7c.4.1.7.6.7 1v6.4c0 5-3.2 8.7-7.7 10.4-.3.1-.7.1-1 0C7 21.3 3.8 17.6 3.8 12.6V6.2c0-.4.3-.8.7-1l7-2.7c.2-.1.3-.1.5-.1z"/>
              <path fill="rgba(7,10,20,.92)" d="M13.2 6.6 8.8 13h3.1l-1 4.4 4.4-6.4h-3.1l1-4.4z"/>
            </svg>
            <span class="txt">
                PoW Shield • Created By&nbsp;
<a href="https://github.com/AfterPacket" target="_blank" rel="noopener noreferrer nofollow">
  AfterPacket
</a>

            </span>
          </div>
        </div>

      </div>
    </div>
  </div>

<script>
(() => {
  const TOKEN  = <?= json_encode($token, JSON_UNESCAPED_SLASHES) ?>;
  const TARGET = <?= json_encode($target, JSON_UNESCAPED_SLASHES) ?>;
  const DEBUG  = <?= $debug ? 'true' : 'false' ?>;

  const pbar  = document.getElementById('pbar');
  const retry = document.getElementById('retry');
  const eta   = document.getElementById('etaText');
  const diag  = document.getElementById('diag');

  // bfcache: prevent "stuck" restores
  window.addEventListener('pageshow', (e) => { if (e.persisted) location.reload(); });

  function setEta(t, cls){
    if (!eta) return;
    eta.className = (cls || 'muted');
    eta.textContent = t;
  }

  function logDiag(msg){
    if (!DEBUG || !diag) return;
    diag.style.display = 'block';
    diag.textContent += msg + "\n";
  }

  // WebCrypto/TextEncoder check
  if (!window.crypto || !crypto.subtle || !window.TextEncoder) {
    setEta("This browser can’t run the check (WebCrypto/TextEncoder missing).", "danger");
    retry.style.display = "inline-block";
    retry.onclick = () => location.reload();
    logDiag("Missing: " + JSON.stringify({
      crypto: !!window.crypto,
      subtle: !!(window.crypto && crypto.subtle),
      textEncoder: !!window.TextEncoder
    }));
    return;
  }

  // Cookie check (Secure when https)
  function hasCookie(name){
    return document.cookie.split(";").some(c => c.trim().startsWith(name + "="));
  }
  try {
    const secure = (location.protocol === "https:") ? "; Secure" : "";
    document.cookie = "__ab_ct=1; Path=/; SameSite=Lax" + secure;
  } catch {}

  if (!hasCookie("__ab_ct")) {
    setEta("Cookies appear blocked. Enable site cookies to continue.", "danger");
    retry.style.display = "inline-block";
    retry.onclick = () => location.reload();
    logDiag("Cookie test failed. document.cookie=" + document.cookie);
    return;
  }

  const enc = new TextEncoder();

  function hasLeadingZeroBits(buf, bits) {
    const bytes = new Uint8Array(buf);
    const full = Math.floor(bits / 8);
    const rem  = bits % 8;

    for (let i = 0; i < full; i++) if (bytes[i] !== 0) return false;
    if (rem === 0) return true;

    const mask = 0xFF << (8 - rem);
    return (bytes[full] & mask) === 0;
  }

  async function sha256(str) {
    return await crypto.subtle.digest('SHA-256', enc.encode(str));
  }

  async function solve(bits) {
    let counter = 0;
    let lastUI = performance.now();
    const start = performance.now();

    // NOTE: No more "slow-device" hard fail.
    // We just warn after ~15s and keep going.
    let warned = false;

    while (true) {
      counter++;

      const h = await sha256(TOKEN + "." + counter);
      if (hasLeadingZeroBits(h, bits)) return counter;

      const now = performance.now();
      if (now - lastUI > 120) {
        lastUI = now;

        const pct = Math.min(95, Math.round((Math.log(counter) / Math.log(700000)) * 95));
        pbar.style.width = pct + "%";

        const elapsed = Math.max(0.1, (now - start) / 1000);

        if (!warned && elapsed > 15) {
          warned = true;
          setEta("Still working… this browser is running in a hardened/slow mode. Hang tight.", "muted");
        } else {
          setEta(`Working… ${elapsed.toFixed(1)}s`, "muted");
        }

        await new Promise(r => setTimeout(r, 0));
      }

      if (counter > 4000000) throw new Error("too-hard");
    }
  }

  async function postSolution(counter) {
    const body = new URLSearchParams();
    body.set("token", TOKEN);
    body.set("counter", String(counter));
    body.set("next", TARGET);

    const resp = await fetch("/__ab/pow-verify.php", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
      credentials: "include",
      redirect: "follow",
      cache: "no-store",
    });

    const txt = await resp.text().catch(() => "");
    if (!resp.ok) {
      throw new Error("verify-http-" + resp.status + ":" + (txt.slice(0, 160) || ""));
    }

    try {
      const obj = JSON.parse(txt);
      if (obj && obj.ok && obj.to) return obj.to;
    } catch {}

    return TARGET;
  }

  async function run() {
    try {
      const parts = TOKEN.split(".");
      const bits = parseInt(parts[2], 10) || 20;

      logDiag("UA=" + navigator.userAgent);
      logDiag("bits=" + bits);
      logDiag("cookiesEnabled=" + (navigator.cookieEnabled ? "yes" : "no"));

      setEta("Working…", "muted");
      const counter = await solve(bits);

      pbar.style.width = "98%";
      setEta("Verifying…", "muted");

      const to = await postSolution(counter);

      pbar.style.width = "100%";
      setEta("Done. Redirecting…", "ok");
      location.replace(to);

    } catch (e) {
      pbar.style.width = "0%";

      const msg = String(e && e.message || e);
      logDiag("Error: " + msg);

      if (msg.startsWith("verify-http-429")) {
        setEta("Verify endpoint is rate-limiting you (429). Wait a moment and retry.", "danger");
      } else if (msg.startsWith("verify-http-403")) {
        setEta("Verify request blocked (403). A blocker/WAF may be stopping /__ab/pow-verify.php.", "danger");
      } else {
        setEta("Couldn’t complete the check. Please retry.", "danger");
      }

      retry.style.display = "inline-block";
      retry.onclick = () => location.reload();
    }
  }

  run();
})();
</script>
</body>
</html>
