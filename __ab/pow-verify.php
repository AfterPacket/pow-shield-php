<?php
declare(strict_types=1);

/**
 * /__ab/pow-verify.php
 * Verifies PoW solution for token from pow.php, then sets signed cookie "abp".
 *
 * Expects POST (application/x-www-form-urlencoded):
 * - token   : ts.exp.bits.salt.uaHash.sig
 * - counter : integer
 * - next    : relative URL (starts with /)
 */

$SECRET = getenv('AB_POW_SECRET') ?: 'CHANGE_ME_LONG_RANDOM_SECRET_64+CHARS';

// Refuse to run with default/weak secret
if ($SECRET === 'CHANGE_ME_LONG_RANDOM_SECRET_64+CHARS' || strlen($SECRET) < 48) {
  http_response_code(500);
  header('Content-Type: text/plain; charset=utf-8');
  echo "PoW misconfigured: set AB_POW_SECRET (>=48 chars).";
  exit;
}

$COOKIE_NAME = 'abp';
$COOKIE_TTL  = 60 * 60 * 6; // must match pow.php's intent

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

function b64url_enc(string $bin): string { return rtrim(strtr(base64_encode($bin), '+/', '-_'), '='); }

function json_fail(int $code, string $msg): void {
  http_response_code($code);
  echo json_encode(['ok' => false, 'error' => $msg], JSON_UNESCAPED_SLASHES);
  exit;
}

function safe_rel_url(string $u): string {
  $u = trim($u);
  if ($u === '' || $u[0] !== '/') return '/';
  if (str_starts_with($u, '//')) return '/';
  if (str_contains($u, "\r") || str_contains($u, "\n")) return '/';
  if (str_starts_with($u, '/__ab/')) return '/';
  return $u;
}

function leading_zero_bits(string $hashBin): int {
  $bits = 0;
  $len = strlen($hashBin);
  for ($i = 0; $i < $len; $i++) {
    $b = ord($hashBin[$i]);
    if ($b === 0) { $bits += 8; continue; }
    for ($k = 7; $k >= 0; $k--) {
      if (($b >> $k) & 1) return $bits;
      $bits++;
    }
    return $bits;
  }
  return $bits;
}

$token   = (string)($_POST['token'] ?? '');
$counter = $_POST['counter'] ?? null;
$next    = safe_rel_url((string)($_POST['next'] ?? '/'));

if ($token === '') json_fail(400, 'Missing token.');
if ($counter === null || (!is_int($counter) && !ctype_digit((string)$counter))) json_fail(400, 'Invalid counter.');
$counter = (int)$counter;
if ($counter < 0) json_fail(400, 'Invalid counter.');

$parts = explode('.', $token);
if (count($parts) !== 6) json_fail(400, 'Bad token format.');

[$ts, $exp, $bits, $salt, $uaHash, $sig] = $parts;

// Basic field checks
if (!ctype_digit($ts) || !ctype_digit($exp) || !ctype_digit($bits)) json_fail(400, 'Bad token fields.');

$tsI   = (int)$ts;
$expI  = (int)$exp;
$bitsI = (int)$bits;

$now = time();
if ($expI <= 0 || $now > $expI) json_fail(403, 'Token expired.');
if ($bitsI < 16 || $bitsI > 26) json_fail(400, 'Bits out of range.');

// Verify UA hash matches current UA
$ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
$uaHashNow = b64url_enc(hash('sha256', $ua, true));
if (!hash_equals($uaHashNow, $uaHash)) json_fail(403, 'UA mismatch.');

// Verify HMAC signature over payload
$payload = $ts . '.' . $exp . '.' . $bits . '.' . $salt . '.' . $uaHash;
$expectedSig = b64url_enc(hash_hmac('sha256', $payload, $SECRET, true));
if (!hash_equals($expectedSig, $sig)) json_fail(403, 'Bad token signature.');

// Verify PoW: sha256(TOKEN + "." + counter) must have >= bits leading zeros
$hashBin = hash('sha256', $token . '.' . $counter, true);
if (leading_zero_bits($hashBin) < $bitsI) json_fail(403, 'PoW invalid.');

// Issue signed cookie: issued.exp.rand.sig (sig binds to UA)
$issued = $now;
$cookieExp = $now + $COOKIE_TTL;
$rand = bin2hex(random_bytes(16));

$claims = $issued . '.' . $cookieExp . '.' . $rand;
$cookieSig = b64url_enc(hash_hmac('sha256', $claims . '|' . $ua, $SECRET, true));
$cookieVal = $claims . '.' . $cookieSig;

setcookie($COOKIE_NAME, $cookieVal, [
  'expires'  => $cookieExp,
  'path'     => '/',
  'secure'   => true,
  'httponly' => true,
  'samesite' => 'Lax',
]);

echo json_encode(['ok' => true, 'to' => $next], JSON_UNESCAPED_SLASHES);
