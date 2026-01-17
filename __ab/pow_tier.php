<?php
declare(strict_types=1);

/**
 * Adaptive PoW tiering (Cloudflare-safe if mod_remoteip is enabled).
 *
 * Stores short-lived counters in APCu if available, otherwise in /tmp.
 * Tier 0: trusted (very easy / skip)
 * Tier 1: normal
 * Tier 2: suspicious
 * Tier 3: known-bad (hardest)
 */

const POW_STATE_DIR = '/tmp/ab_pow_state';
const POW_TTL_BURST = 60;      // 1 min burst window
const POW_TTL_FAILS = 900;     // 15 min fail window
const POW_TTL_TRUST = 86400;   // 24h trust window

function pow_client_ip(): string {
  // If you enabled Apache mod_remoteip, REMOTE_ADDR is already the real visitor.
  $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');
  return $ip !== '' ? $ip : '0.0.0.0';
}

function pow_state_get(string $key): ?array {
  if (function_exists('apcu_fetch') && ini_get('apc.enabled')) {
    $ok = false;
    $v = apcu_fetch($key, $ok);
    return ($ok && is_array($v)) ? $v : null;
  }
  $path = POW_STATE_DIR . '/' . hash('sha256', $key) . '.json';
  if (!is_file($path)) return null;
  $raw = @file_get_contents($path);
  if ($raw === false) return null;
  $v = json_decode($raw, true);
  return is_array($v) ? $v : null;
}

function pow_state_set(string $key, array $val, int $ttl): void {
  $val['_exp'] = time() + $ttl;

  if (function_exists('apcu_store') && ini_get('apc.enabled')) {
    apcu_store($key, $val, $ttl);
    return;
  }

  if (!is_dir(POW_STATE_DIR)) @mkdir(POW_STATE_DIR, 0700, true);
  $path = POW_STATE_DIR . '/' . hash('sha256', $key) . '.json';
  @file_put_contents($path, json_encode($val), LOCK_EX);
  @chmod($path, 0600);
}

function pow_state_bump(string $key, int $ttl, string $field='n'): int {
  $v = pow_state_get($key);
  if ($v && isset($v['_exp']) && (int)$v['_exp'] < time()) $v = null;

  $n = (int)($v[$field] ?? 0);
  $n++;
  $v = [$field => $n];
  pow_state_set($key, $v, $ttl);
  return $n;
}

function pow_state_read_int(string $key, string $field='n'): int {
  $v = pow_state_get($key);
  if (!$v) return 0;
  if (isset($v['_exp']) && (int)$v['_exp'] < time()) return 0;
  return (int)($v[$field] ?? 0);
}

function pow_is_datacenter_asn_hint(): bool {
  // Cheap heuristic only (don’t hard-block on this). You can replace with your own ASN logic.
  // If you already have server-side ASN enrichment, plug it in here.
  return false;
}

function pow_hits_bot_paths(): bool {
  $uri = (string)($_SERVER['REQUEST_URI'] ?? '');
  $bad = ['/.env', '/wp-login.php', '/xmlrpc.php', '/admin', '/phpmyadmin', '/.git', '/server-status'];
  foreach ($bad as $p) {
    if (stripos($uri, $p) !== false) return true;
  }
  return false;
}

function pow_risk_score(string $ip): int {
  $score = 0;

  // Burst
  $burst = pow_state_bump("pow:burst:$ip", POW_TTL_BURST);
  if ($burst > 30) $score += 20;
  if ($burst > 80) $score += 35;

  // Recent failures
  $fails = pow_state_read_int("pow:fails:$ip");
  if ($fails >= 3)  $score += 25;
  if ($fails >= 10) $score += 45;

  // Botty paths
  if (pow_hits_bot_paths()) $score += 25;

  // Optional heuristic
  if (pow_is_datacenter_asn_hint()) $score += 10;

  // Trust cookie (yours) — if present/valid, reduce risk hard.
  // (You can set this after a successful verify.)
  $trust = pow_state_read_int("pow:trust:$ip");
  if ($trust > 0) $score -= 40;

  if ($score < 0) $score = 0;
  if ($score > 100) $score = 100;
  return $score;
}

function pow_tier_from_score(int $score): int {
  if ($score >= 80) return 3;
  if ($score >= 50) return 2;
  if ($score >= 20) return 1;
  return 0;
}

function pow_bits_for_tier(int $tier): int {
  // Tune these to your target solve-time.
  return match ($tier) {
    0 => 18, // trusted / easy
    1 => 20, // normal
    2 => 22, // suspicious
    default => 24, // known-bad (cap it)
  };
}

function pow_message_for_tier(int $tier): array {
  return match ($tier) {
    0 => ["Verifying your session…", "Quick integrity check. No CAPTCHA, no tracking."],
    1 => ["Checking your browser…", "A lightweight proof-of-work check to deter scrapers."],
    2 => ["Running an integrity check…", "Extra verification due to unusual traffic patterns."],
    default => ["Checking for clanker-grade automation…", "This helps keep the site usable for humans."],
  };
}

/** Call on successful PoW verify */
function pow_mark_trusted(string $ip): void {
  pow_state_set("pow:trust:$ip", ['n' => 1], POW_TTL_TRUST);
  // decay failures
  pow_state_set("pow:fails:$ip", ['n' => 0], POW_TTL_FAILS);
}

/** Call on failed PoW verify */
function pow_mark_failed(string $ip): void {
  pow_state_bump("pow:fails:$ip", POW_TTL_FAILS);
}
