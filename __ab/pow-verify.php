<?php
declare(strict_types=1);

/**
 * /__ab/pow-verify.php
 * Verifies PoW solution and sets signed cookie "abp".
 *
 * Token v2 verification:
 *   token = p64.sig
 *   payload = json_decode(b64url_dec(p64))
 *   sig = HMAC(p64)
 *
 * Cookie value format (v2):
 *   abp = "v2." + b64url(payload_json) + "." + b64url(hmac_sha256(b64url(payload_json), key))
 *
 * Note: Apache rewrite checks cookie presence only; the *real* trust comes from server-side verification.
 */

$COOKIE_NAME = 'abp';
$COOKIE_TTL  = 60 * 60 * 6; // 6 hours

// -------------------- helpers --------------------
function b64url_enc(string $bin): string {
  return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}
function b64url_dec(string $s): string {
  $s = strtr($s, '-_', '+/');
  $pad = strlen($s) % 4;
  if ($pad) $s .= str_repeat('=', 4 - $pad);
  $out = base64_decode($s, true);
  return is_string($out) ? $out : '';
}
function hmac_b64(string $data, string $key): string {
  return b64url_enc(hash_hmac('sha256', $data, $key, true));
}
function ua_hash_b64(): string {
  $ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
  return b64url_enc(hash('sha256', $ua, true));
}

function pow_keys(): array {
  $cur  = (string)(getenv('AB_POW_SECRET') ?: '');
  $prev = (string)(getenv('AB_POW_SECRET_PREV') ?: '');
  $kid  = (string)(getenv('AB_POW_KID') ?: 'A');
  $kidPrev = (string)(getenv('AB_POW_KID_PREV') ?: 'B');

  $keys = [];
  if ($cur !== '')  $keys[$kid] = $cur;
  if ($prev !== '') $keys[$kidPrev] = $prev;
  return $keys;
}

function safe_rel_url(string $u): string {
  $u = trim($u);
  if ($u === '' || $u[0] !== '/') return '/';
  if (strpos($u, '//') === 0) return '/';
  if (strpos($u, "\r") !== false || strpos($u, "\n") !== false) return '/';
  if (strpos($u, '/__ab/') === 0) return '/';
  return $u;
}

function token_parse_and_verify_v2(string $token): array {
  $parts = explode('.', $token);
  if (count($parts) !== 2) return [false, null, 'bad-token'];

  [$p64, $sig] = $parts;
  $json = b64url_dec($p64);
  if ($json === '') return [false, null, 'bad-payload'];

  $payload = json_decode($json, true);
  if (!is_array($payload) || (int)($payload['v'] ?? 0) !== 2) return [false, null, 'bad-v'];

  $kid = (string)($payload['kid'] ?? '');
  $keys = pow_keys();
  if (!$keys) return [false, null, 'no-secret'];

  // Choose by kid first, else try all
  $candidates = [];
  if ($kid !== '' && isset($keys[$kid])) $candidates[] = $keys[$kid];
  foreach ($keys as $k) $candidates[] = $k;
  $candidates = array_values(array_unique($candidates));

  $okSig = false;
  foreach ($candidates as $k) {
    if (hash_equals(hmac_b64($p64, $k), $sig)) { $okSig = true; break; }
  }
  if (!$okSig) return [false, null, 'sig'];

  $now = time();
  $iat = (int)($payload['iat'] ?? 0);
  $exp = (int)($payload['exp'] ?? 0);
  if ($exp < $now || $iat > ($now + 60)) return [false, null, 'expired'];

  $uah = (string)($payload['uah'] ?? '');
  if ($uah === '' || !hash_equals($uah, ua_hash_b64())) return [false, null, 'ua-mismatch'];

  $bits = (int)($payload['bits'] ?? 0);
  if ($bits < 16 || $bits > 24) return [false, null, 'bits-range'];

  return [true, $payload, null];
}

function leading_zero_bits_ok(string $hashBin, int $bits): bool {
  $bytes = unpack('C*', $hashBin);
  if (!$bytes) return false;

  $full = intdiv($bits, 8);
  $rem  = $bits % 8;

  for ($i = 1; $i <= $full; $i++) {
    if (($bytes[$i] ?? 255) !== 0) return false;
  }
  if ($rem === 0) return true;

  $next = $bytes[$full + 1] ?? 255;
  $mask = (0xFF << (8 - $rem)) & 0xFF;
  return (($next & $mask) === 0);
}

// -------------------- response headers --------------------
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
  http_response_code(405);
  echo json_encode(['ok'=>false,'error'=>'method'], JSON_UNESCAPED_SLASHES);
  exit;
}

$token   = (string)($_POST['token'] ?? '');
$counter = (string)($_POST['counter'] ?? '');
$next    = safe_rel_url((string)($_POST['next'] ?? '/'));

if ($token === '' || $counter === '' || !ctype_digit($counter)) {
  http_response_code(400);
  echo json_encode(['ok'=>false,'error'=>'bad-input'], JSON_UNESCAPED_SLASHES);
  exit;
}

[$okTok, $tok, $err] = token_parse_and_verify_v2($token);
if (!$okTok || !is_array($tok)) {
  http_response_code(400);
  echo json_encode(['ok'=>false,'error'=>$err ?: 'bad-token'], JSON_UNESCAPED_SLASHES);
  exit;
}

$bitsI = (int)$tok['bits'];

// Verify PoW: sha256(token + "." + counter) has leading $bitsI zero bits
$hashBin = hash('sha256', $token.'.'.$counter, true);
if (!leading_zero_bits_ok($hashBin, $bitsI)) {
  http_response_code(400);
  echo json_encode(['ok'=>false,'error'=>'pow'], JSON_UNESCAPED_SLASHES);
  exit;
}

// Issue signed pass cookie (v2)
// Payload for cookie: {"v":2,"iat":..,"exp":..,"uah":"..","kid":"..","n":".."}
$keys = pow_keys();
$kid = (string)($tok['kid'] ?? (string)(getenv('AB_POW_KID') ?: array_key_first($keys)));
$key = $keys[$kid] ?? reset($keys);

$iat = time();
$exp = $iat + $COOKIE_TTL;
$cookiePayload = [
  'v'   => 2,
  'kid' => $kid,
  'iat' => $iat,
  'exp' => $exp,
  'uah' => (string)$tok['uah'],
  'n'   => b64url_enc(random_bytes(12)),
];

$json = json_encode($cookiePayload, JSON_UNESCAPED_SLASHES);
if (!is_string($json)) {
  http_response_code(500);
  echo json_encode(['ok'=>false,'error'=>'cookie-json'], JSON_UNESCAPED_SLASHES);
  exit;
}

$p64 = b64url_enc($json);
$sig = hmac_b64($p64, $key);
$cookieVal = 'v2.' . $p64 . '.' . $sig;

// Set cookie
setcookie($COOKIE_NAME, $cookieVal, [
  'expires'  => time() + $COOKIE_TTL,
  'path'     => '/',
  'secure'   => true,
  'httponly' => true,
  'samesite' => 'Lax',
]);

echo json_encode(['ok'=>true,'to'=>$next], JSON_UNESCAPED_SLASHES);
