#!/usr/bin/env php
<?php

/**
 * NexoVirt Host Agent: heartbeat + host stats + job queue
 * (write_snippet, ensure_storage, download_image, delete_image, apply_nat,
 *  clear_nat, read_firewall, read_system, read_pve, read_logs, read_pve_logs,
 *  probe_sdn_dhcp, ensure_sdn_dhcp, ensure_sdn_egress, set_ip_forward,
 *  lxc_root_ssh, lxc_set_password, scan_ips, dyndns_configure, apply_wireguard, read_wireguard,
 *  apt_refresh, apt_simulate, apt_upgrade_start, apt_upgrade_status)
 *
 * A standalone PHP 8.0+ CLI script. No CodeIgniter dependency.
 * Install on a Proxmox VE host and point it at your NexoVirt panel.
 *
 * Configuration (env vars or config file, in priority order):
 *   NEXOVIRT_URL            : panel base URL, MUST be https://, e.g. https://panel.example.com
 *   NEXOVIRT_AGENT_TOKEN    : bearer token printed by `php spark agent:register`
 *   NEXOVIRT_CA_BUNDLE      : (optional) path to CA bundle for self-signed certs
 *   NEXOVIRT_ALLOW_INSECURE : (optional) 1 = allow a plain http:// panel URL (dev only, loud warning)
 *   INTERVAL                : seconds between heartbeats (default: 15)
 *   SNIPPETS_DIR            : (optional) dir for write_snippet jobs (default: /var/lib/vz/snippets)
 *
 * Usage:
 *   php nexovirt-agent.php            # runs forever
 *   php nexovirt-agent.php --once     # single heartbeat then exit
 */

declare(strict_types=1);

const AGENT_VERSION        = '0.24.1';
const DEFAULT_INTERVAL     = 15;
const CONNECT_TIMEOUT      = 10;   // seconds for connection
const REQUEST_TIMEOUT      = 30;   // seconds for full request
const DEFAULT_SNIPPETS_DIR = '/var/lib/vz/snippets';
const MAX_SNIPPET_BYTES    = 65536;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

function loadConfig(): array
{
    // 1. Try a sidecar config file. Check next to the script first, then /etc: the
    //    onboarder writes /etc/nexovirt-agent.conf, manual installs may use either.
    foreach ([__DIR__ . '/nexovirt-agent.conf', '/etc/nexovirt-agent.conf'] as $confFile) {
        if (! is_file($confFile) || ! is_readable($confFile)) {
            continue;
        }
        foreach (file($confFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            [$key, $value] = explode('=', $line, 2) + [1 => ''];
            $key   = trim($key);
            $value = trim($value);
            if ($key !== '' && getenv($key) === false) {
                // First file wins; don't overwrite an already-set value.
                putenv("{$key}={$value}");
            }
        }
    }

    $url      = getenv('NEXOVIRT_URL');
    $token    = getenv('NEXOVIRT_AGENT_TOKEN');
    $caBundle = getenv('NEXOVIRT_CA_BUNDLE') ?: null;
    $interval = (int) (getenv('INTERVAL') ?: DEFAULT_INTERVAL);

    if (! $url || ! $token) {
        fwrite(STDERR, "[nexovirt-agent] ERROR: NEXOVIRT_URL and NEXOVIRT_AGENT_TOKEN must be set.\n");
        exit(1);
    }
    $allowInsecure = getenv('NEXOVIRT_ALLOW_INSECURE') === '1';
    $urlError      = nexovirt_validate_panel_url($url, $allowInsecure);
    if ($urlError !== '') {
        fwrite(STDERR, "[nexovirt-agent] ERROR: {$urlError}\n");
        exit(1);
    }
    if ($allowInsecure && stripos($url, 'https://') !== 0) {
        fwrite(STDERR, "[nexovirt-agent] WARNING: NEXOVIRT_ALLOW_INSECURE=1 - the agent token and job payloads "
            . "(incl. root passwords) are sent UNENCRYPTED over http. Never use this in production.\n");
    }

    return [
        'url'      => rtrim($url, '/'),
        'token'    => $token,
        'caBundle' => $caBundle,
        'interval' => max(5, $interval), // enforce a floor of 5 s
    ];
}

/**
 * The panel URL must be https:// (the bearer token + job payloads, incl. root passwords, travel over
 * it). http:// is only accepted with the explicit NEXOVIRT_ALLOW_INSECURE=1 opt-in. Returns '' when ok.
 */
function nexovirt_validate_panel_url(string $url, bool $allowInsecure): string
{
    if (preg_match('#^https://[^/\s]+#i', $url) === 1) {
        return '';
    }
    if ($allowInsecure && preg_match('#^http://[^/\s]+#i', $url) === 1) {
        return '';
    }
    return 'NEXOVIRT_URL must start with https:// (set NEXOVIRT_ALLOW_INSECURE=1 to allow http:// for local dev only).';
}

// ---------------------------------------------------------------------------
// Stats collection: defensive: guard /proc reads (not available on macOS)
// ---------------------------------------------------------------------------

function collectStats(): array
{
    $stats = [
        'hostname' => gethostname() ?: 'unknown',
    ];

    // Uptime (Linux only via /proc/uptime)
    if (is_readable('/proc/uptime')) {
        $raw = @file_get_contents('/proc/uptime');
        if ($raw !== false) {
            [$uptimeSeconds] = explode(' ', trim($raw));
            $stats['uptime'] = (int) $uptimeSeconds;
        }
    }

    // Load averages (available cross-platform via PHP)
    $load = @sys_getloadavg();
    if ($load !== false) {
        $stats['loadavg'] = array_map(fn ($v) => round($v, 2), $load);
    }

    // Memory (Linux only via /proc/meminfo)
    if (is_readable('/proc/meminfo')) {
        $raw = @file_get_contents('/proc/meminfo');
        if ($raw !== false) {
            preg_match('/MemTotal:\s+(\d+)\s+kB/i', $raw, $total);
            preg_match('/MemAvailable:\s+(\d+)\s+kB/i', $raw, $avail);
            if ($total && $avail) {
                $totalKb         = (int) $total[1];
                $availableKb     = (int) $avail[1];
                $stats['mem_total_kb'] = $totalKb;
                $stats['mem_used_kb']  = $totalKb - $availableKb;
                $stats['mem_free_kb']  = $availableKb;
            }
        }
    }

    // Image cache report (0.24.0): the panel's per-node image status comes from here.
    // A failure here must never stop the heartbeat (the agent would crash-loop and go offline).
    try {
        if (is_dir(nexovirt_images_iso_dir())) {
            $stats['images'] = nexovirt_images_report();
            $free = @disk_free_space(nexovirt_images_iso_dir());
            if ($free !== false) {
                $stats['images_free'] = (int) $free;
            }
        }
    } catch (\Throwable $e) {
        fwrite(STDERR, '[nexovirt-agent] image report failed: ' . $e->getMessage() . PHP_EOL);
    }

    return $stats;
}

// ---------------------------------------------------------------------------
// Job dispatch: constrained vocabulary, agent-enforced validation
// ---------------------------------------------------------------------------

/** Allow only a plain PVE storage id (must start alphanumeric, no leading dash/dot). */
function nexovirt_validate_storage_name(string $name): bool
{
    return preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]*$/', $name) === 1;
}

/** Allow only an absolute path with no traversal. */
function nexovirt_validate_storage_path(string $path): bool
{
    return $path !== '' && $path[0] === '/' && ! str_contains($path, '..') && preg_match('#^[A-Za-z0-9._/-]+$#', $path) === 1;
}

/**
 * Idempotently create a PVE `dir` storage. Returns ['ok'=>bool,'error'=>string].
 * No-op (ok) if the storage already exists. Inputs are pre-validated by the caller.
 */
function nexovirt_ensure_storage(string $storage, string $path, string $content): array
{
    $s = escapeshellarg($storage);
    $p = escapeshellarg($path);
    $c = escapeshellarg($content);
    $cmd = "pvesm status --storage {$s} >/dev/null 2>&1 || pvesm add dir {$s} --path {$p} --content {$c} --mkdir 1 2>&1";
    $out  = [];
    $code = 0;
    exec($cmd, $out, $code);
    return $code === 0 ? ['ok' => true, 'error' => ''] : ['ok' => false, 'error' => trim(implode("\n", $out))];
}

/** Allow only flat YAML filenames, no path separators, no traversal. */
function nexovirt_validate_snippet_name(string $name): bool
{
    return preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$/', $name) === 1;
}

/** PVE snippet reference the panel uses for cicustom, e.g. local:snippets/ci.yml */
function nexovirt_snippet_ref(string $storage, string $name): string
{
    return $storage . ':snippets/' . $name;
}

function nexovirt_snippets_dir(): string
{
    $dir = getenv('SNIPPETS_DIR');
    return $dir !== false && $dir !== '' ? $dir : DEFAULT_SNIPPETS_DIR;
}

/**
 * Validate + atomically write a snippet. Returns ['ok'=>bool, 'error'=>string].
 * Never writes outside $dir (the name is validated to a flat filename).
 */
function nexovirt_write_snippet(string $dir, string $name, string $content): array
{
    if (! nexovirt_validate_snippet_name($name)) {
        return ['ok' => false, 'error' => 'invalid snippet filename'];
    }
    if ($content === '' || strlen($content) > MAX_SNIPPET_BYTES) {
        return ['ok' => false, 'error' => 'snippet content empty or too large'];
    }
    if (! is_dir($dir) && ! @mkdir($dir, 0755, true) && ! is_dir($dir)) {
        return ['ok' => false, 'error' => 'cannot create snippets dir'];
    }
    $final = rtrim($dir, '/') . '/' . $name;
    $tmp   = rtrim($dir, '/') . '/.' . $name . '.tmp';
    if (@file_put_contents($tmp, $content) === false) {
        return ['ok' => false, 'error' => 'write failed'];
    }
    @chmod($tmp, 0644);
    if (! @rename($tmp, $final)) {
        @unlink($tmp);
        return ['ok' => false, 'error' => 'atomic rename failed'];
    }
    return ['ok' => true, 'error' => ''];
}

// ---------------------------------------------------------------------------
// DynDNS (nxvdns.link): token + endpoints from the panel, periodic update calls
// ---------------------------------------------------------------------------

const DEFAULT_DYNDNS_DIR     = '/etc';
const DYNDNS_HOST_SUFFIX     = '.nexovirt.com';
const DYNDNS_UPDATE_INTERVAL = 300;

function nexovirt_dyndns_dir(): string
{
    $d = getenv('DYNDNS_DIR');

    return $d !== false && $d !== '' ? rtrim($d, '/') : DEFAULT_DYNDNS_DIR;
}

/** Only https://<host>.nexovirt.com[/path]: no userinfo, port, query, fragment or whitespace. */
function nexovirt_valid_dyndns_url(string $url): bool
{
    if (preg_match('#^https://([a-z0-9.-]+)(/[A-Za-z0-9/_-]*)?$#D', $url, $m) !== 1) {
        return false;
    }

    return str_ends_with($m[1], DYNDNS_HOST_SUFFIX) && strlen($m[1]) > strlen(DYNDNS_HOST_SUFFIX);
}

/** @return array{ok:bool,error:string} */
function nexovirt_validate_dyndns_payload(array $p): array
{
    $enabled = $p['enabled'] ?? null;
    if ($enabled === false) {
        return ['ok' => true, 'error' => ''];
    }
    if ($enabled !== true) {
        return ['ok' => false, 'error' => 'enabled must be true or false'];
    }
    if (preg_match('/^[A-Za-z0-9]{64}$/D', (string) ($p['token'] ?? '')) !== 1) {
        return ['ok' => false, 'error' => 'invalid token format'];
    }
    foreach (['endpoint_v4', 'endpoint_v6'] as $k) {
        if (! nexovirt_valid_dyndns_url((string) ($p[$k] ?? ''))) {
            return ['ok' => false, 'error' => 'invalid ' . $k];
        }
    }

    return ['ok' => true, 'error' => ''];
}

/** Atomic write with mode 0600 from the first byte (umask 077). */
function nexovirt_write_private(string $path, string $content): bool
{
    $tmp = $path . '.tmp';
    $old = umask(0077);
    try {
        if (@file_put_contents($tmp, $content) === false) {
            return false;
        }
        @chmod($tmp, 0600);
        if (! @rename($tmp, $path)) {
            @unlink($tmp);

            return false;
        }

        return true;
    } finally {
        umask($old);
    }
}

/** @return array{ok:bool,error:string} Caller has validated $p. */
function nexovirt_dyndns_configure(array $p): array
{
    $dir  = nexovirt_dyndns_dir();
    $hdr  = $dir . '/nexovirt-dyndns.hdr';
    $conf = $dir . '/nexovirt-dyndns.conf';
    if ($p['enabled'] === false) {
        @unlink($hdr);
        @unlink($conf);

        return ['ok' => true, 'error' => ''];
    }
    if (! nexovirt_write_private($hdr, 'Authorization: Bearer ' . $p['token'] . "\n")) {
        return ['ok' => false, 'error' => 'cannot write dyndns token file'];
    }
    $json = json_encode(['endpoint_v4' => $p['endpoint_v4'], 'endpoint_v6' => $p['endpoint_v6']], JSON_UNESCAPED_SLASHES);
    if (! nexovirt_write_private($conf, (string) $json)) {
        return ['ok' => false, 'error' => 'cannot write dyndns config file'];
    }

    return ['ok' => true, 'error' => ''];
}

function nexovirt_dyndns_cmd(string $url, int $family, string $hdrPath): string
{
    return 'curl -fsS ' . ($family === 6 ? '-6' : '-4') . ' --max-time 10 -X POST -H ' . escapeshellarg('@' . $hdrPath) . ' ' . escapeshellarg($url);
}

/** @return array<int,string> family => output (DRYRUN: the command). Re-validates the conf: a tampered file is ignored. */
function nexovirt_dyndns_update(): array
{
    $dir  = nexovirt_dyndns_dir();
    $raw  = @file_get_contents($dir . '/nexovirt-dyndns.conf');
    $conf = $raw === false ? null : json_decode($raw, true);
    if (! is_array($conf) || ! is_file($dir . '/nexovirt-dyndns.hdr')) {
        return [];
    }
    $out = [];
    foreach ([4 => 'endpoint_v4', 6 => 'endpoint_v6'] as $family => $key) {
        $url = (string) ($conf[$key] ?? '');
        if (! nexovirt_valid_dyndns_url($url)) {
            continue;
        }
        $cmd          = nexovirt_dyndns_cmd($url, $family, $dir . '/nexovirt-dyndns.hdr');
        $out[$family] = getenv('NEXOVIRT_AGENT_DRYRUN') === '1' ? $cmd : nexovirt_run_cmd($cmd);
    }

    return $out;
}

/** Main-loop hook: every DYNDNS_UPDATE_INTERVAL seconds. Failures are logged locally and retried next cycle. */
function nexovirt_dyndns_tick(int $last, int $now): int
{
    if ($now - $last < DYNDNS_UPDATE_INTERVAL) {
        return $last;
    }
    foreach (nexovirt_dyndns_update() as $family => $output) {
        if (getenv('NEXOVIRT_AGENT_DRYRUN') !== '1' && strpos((string) $output, '"ok":true') === false) {
            fwrite(STDERR, '[' . date('Y-m-d H:i:s') . "] DynDNS v{$family} update failed: " . substr((string) $output, 0, 200) . "\n");
        }
    }

    return $now;
}

/** Allowed disk-image extensions for download_image/delete_image (case-insensitive). */
const IMAGE_EXTENSIONS = ['img', 'qcow2', 'qcow', 'raw', 'vmdk', 'vhd', 'vhdx', 'iso'];

/** Allow only a flat image filename (no path separators, no traversal) ending in a known image ext. */
function nexovirt_validate_image_filename(string $f): bool
{
    if ($f === '' || preg_match('/^[A-Za-z0-9._-]+$/', $f) !== 1) {
        return false;
    }
    $ext = strtolower((string) pathinfo($f, PATHINFO_EXTENSION));
    return in_array($ext, IMAGE_EXTENSIONS, true);
}

/** The managed nexovirt-images storage's iso directory (where PVE keeps importable images). */
function nexovirt_images_iso_dir(): string
{
    $base = getenv('NEXOVIRT_IMAGES_DIR');
    $base = $base !== false && $base !== '' ? $base : '/var/lib/nexovirt/images';
    return rtrim($base, '/') . '/template/iso';
}

/** The managed nexovirt-images storage name (must match the panel's ProxmoxService::IMAGE_STORAGE). */
const NEXOVIRT_IMAGES_STORAGE = 'nexovirt-images';

/** The managed storage's vztmpl directory (where PVE keeps CT templates: <base>/template/cache). */
function nexovirt_images_vztmpl_dir(): string
{
    $base = getenv('NEXOVIRT_IMAGES_DIR');
    $base = $base !== false && $base !== '' ? $base : '/var/lib/nexovirt/images';
    return rtrim($base, '/') . '/template/cache';
}

/** Allow only a flat CT template filename ending in .tar.zst / .tar.gz / .tar.xz (no traversal). */
function nexovirt_validate_template_filename(string $f): bool
{
    return preg_match('/^[A-Za-z0-9._-]+\.tar\.(zst|gz|xz)$/', $f) === 1;
}

/** True when the packed address $packed starts with the $bits-bit prefix of packed $net (same family). */
function nexovirt_packed_in_prefix(string $packed, string $net, int $bits): bool
{
    if (strlen($packed) !== strlen($net)) {
        return false;
    }
    $full = intdiv($bits, 8);
    if (strncmp($packed, $net, $full) !== 0) {
        return false;
    }
    $rem = $bits % 8;
    if ($rem === 0) {
        return true;
    }
    $mask = (0xFF << (8 - $rem)) & 0xFF;
    return (ord($packed[$full]) & $mask) === (ord($net[$full]) & $mask);
}

/**
 * True if an IP literal is NOT a plain public unicast address: loopback / link-local / private
 * (RFC1918, ULA) / CGNAT / cloud-metadata / multicast / reserved / documentation / benchmarking /
 * translation ranges: the targets an SSRF would try to reach. Works on inet_pton bytes so every
 * textual form (incl. hex IPv4-mapped IPv6 like ::ffff:7f00:1) is normalized first. Fail-closed.
 */
function nexovirt_ip_is_internal(string $ip): bool
{
    $packed = @inet_pton($ip);
    if ($packed === false) {
        return true; // unparseable: fail closed
    }

    if (strlen($packed) === 16) {
        // IPv4-mapped (::ffff:0:0/96) or IPv4-compatible (::/96): judge the embedded IPv4.
        if (strncmp($packed, str_repeat("\0", 10) . "\xff\xff", 12) === 0
            || strncmp($packed, str_repeat("\0", 12), 12) === 0) {
            return nexovirt_ip_is_internal((string) inet_ntop(substr($packed, 12)));
        }
        $v6 = [
            ['::', 128],            // unspecified
            ['::1', 128],           // loopback
            ['fc00::', 7],          // unique-local
            ['fe80::', 10],         // link-local
            ['fec0::', 10],         // site-local (deprecated)
            ['ff00::', 8],          // multicast
            ['2002::', 16],         // 6to4 (embeds an arbitrary IPv4)
            ['64:ff9b::', 96],      // NAT64 well-known (embeds an arbitrary IPv4)
            ['64:ff9b:1::', 48],    // NAT64 local-use
            ['2001::', 32],         // Teredo
            ['2001:db8::', 32],     // documentation
            ['100::', 64],          // discard-only
        ];
        foreach ($v6 as [$net, $bits]) {
            if (nexovirt_packed_in_prefix($packed, (string) inet_pton($net), $bits)) {
                return true;
            }
        }
        return false;
    }

    $v4 = [
        ['0.0.0.0', 8],         // "this host"
        ['10.0.0.0', 8],        // private
        ['100.64.0.0', 10],     // CGNAT / Tailscale
        ['127.0.0.0', 8],       // loopback
        ['169.254.0.0', 16],    // link-local + 169.254.169.254 metadata
        ['172.16.0.0', 12],     // private
        ['192.0.0.0', 24],      // IETF protocol assignments
        ['192.0.2.0', 24],      // documentation
        ['192.168.0.0', 16],    // private
        ['198.18.0.0', 15],     // benchmarking
        ['198.51.100.0', 24],   // documentation
        ['203.0.113.0', 24],    // documentation
        ['224.0.0.0', 4],       // multicast
        ['240.0.0.0', 4],       // reserved + 255.255.255.255 broadcast
    ];
    foreach ($v4 as [$net, $bits]) {
        if (nexovirt_packed_in_prefix($packed, (string) inet_pton($net), $bits)) {
            return true;
        }
    }
    return false;
}

/**
 * SSRF guard for download_image: resolve the URL's host ONCE and validate every address. Returns
 * ['error'=>string, 'host'=>string, 'port'=>int, 'ip'=>string]. error '' = allowed; 'ip' is the
 * validated address the download MUST be pinned to (curl --resolve) so a DNS rebind between this
 * check and the transfer cannot swap in an internal target. 'ip' is '' for a literal-IP URL (no
 * DNS involved). Fail-closed: an unresolvable host is rejected.
 *
 * @return array{error:string, host:string, port:int, ip:string}
 */
function nexovirt_url_resolve_target(string $url): array
{
    $parts  = parse_url($url);
    $host   = is_array($parts) ? (string) ($parts['host'] ?? '') : '';
    $scheme = is_array($parts) ? strtolower((string) ($parts['scheme'] ?? '')) : '';
    $port   = is_array($parts) && isset($parts['port']) ? (int) $parts['port'] : ($scheme === 'http' ? 80 : 443);
    $deny   = static fn (string $why): array => ['error' => $why, 'host' => '', 'port' => 0, 'ip' => ''];

    if ($host === '') {
        return $deny('invalid url host');
    }
    $host = trim($host, '[]'); // strip IPv6 brackets

    // Obvious internal hostnames (no DNS round-trip needed).
    $lhost = strtolower(rtrim($host, '.'));
    if ($lhost === 'localhost' || str_ends_with($lhost, '.localhost') || str_ends_with($lhost, '.local')
        || str_ends_with($lhost, '.internal') || $lhost === 'metadata' || $lhost === 'metadata.google.internal') {
        return $deny('internal host not allowed');
    }

    // Literal IP: check directly (no DNS, nothing to pin).
    if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
        return nexovirt_ip_is_internal($host)
            ? $deny('internal address not allowed')
            : ['error' => '', 'host' => $host, 'port' => $port, 'ip' => ''];
    }
    // Only plain DNS names reach the resolver (rejects odd forms like decimal/octal IPv4 "2130706433").
    if (preg_match('/^(?=.*[a-z])[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/', $lhost) !== 1) {
        return $deny('invalid url host');
    }

    // Hostname: resolve A + AAAA; refuse if ANY resolved address is internal (fail-closed on no records).
    $ips = [];
    $a   = @gethostbynamel($host);
    if (is_array($a)) {
        $ips = array_merge($ips, $a);
    }
    if (function_exists('dns_get_record')) {
        $aaaa = @dns_get_record($host, DNS_AAAA);
        if (is_array($aaaa)) {
            foreach ($aaaa as $rec) {
                if (! empty($rec['ipv6'])) {
                    $ips[] = $rec['ipv6'];
                }
            }
        }
    }
    if ($ips === []) {
        return $deny('host did not resolve');
    }
    foreach ($ips as $ip) {
        if (nexovirt_ip_is_internal($ip)) {
            return $deny('host resolves to an internal address');
        }
    }

    return ['error' => '', 'host' => $host, 'port' => $port, 'ip' => $ips[0]];
}

/** Back-compat wrapper: '' when the URL target is allowed, else a short reason. */
function nexovirt_url_target_blocked(string $url): string
{
    return nexovirt_url_resolve_target($url)['error'];
}

/** Hard cap on a downloaded image (64 GiB). */
const MAX_IMAGE_BYTES = 68719476736;
/** Minimum free space required in the target dir before a download starts (2 GiB). */
const MIN_FREE_BYTES = 2147483648;
/** Max redirects followed for one download; every hop is re-validated against the SSRF rules. */
const MAX_IMAGE_REDIRECTS = 5;
/** Marker line curl --write-out appends so the HTTP status + redirect target can be parsed. */
const CURL_WRITE_OUT_MARKER = 'NXHTTP';

/**
 * Build the constrained curl download command. PURE (no side effects). No redirects are followed
 * (SSRF: only the first, validated hop is ever contacted) and --resolve pins the connection to the
 * address that was validated. --write-out prints the status + redirect target so a 3xx (which curl
 * -f treats as success) is detected by the caller instead of saving the redirect body as an image.
 *
 * @param array{host:string, port:int, ip:string} $target
 */
function nexovirt_build_download_cmd(string $url, string $part, array $target, array $opt = []): string
{
    // Cache downloads ($opt['resume']) continue a partial file and have no total time cap (a big
    // Windows image can take hours); a stall guard aborts a transfer that stays under 1 KiB/s for 5 min.
    $time = ! empty($opt['resume']) ? ' -C - --speed-limit 1024 --speed-time 300' : ' --max-time 1800';
    $cmd  = 'curl -fsS --proto ' . escapeshellarg('=http,https') . ' --max-redirs 0'
        . ' --connect-timeout 20' . $time . ' --max-filesize ' . MAX_IMAGE_BYTES;
    if (($opt['headers'] ?? '') !== '') {
        $cmd .= ' -D ' . escapeshellarg((string) $opt['headers']);
    }
    if (($target['ip'] ?? '') !== '') {
        $ip   = (string) $target['ip'];
        $ip   = str_contains($ip, ':') ? '[' . $ip . ']' : $ip;
        $cmd .= ' --resolve ' . escapeshellarg($target['host'] . ':' . (int) $target['port'] . ':' . $ip);
    }
    $cmd .= ' -w ' . escapeshellarg('\n' . CURL_WRITE_OUT_MARKER . ':%{http_code}:%{redirect_url}\n')
        . ' -o ' . escapeshellarg($part) . ' ' . escapeshellarg($url) . ' 2>&1';
    return $cmd;
}

/**
 * Interpret curl's exit code + output. Returns '' on a real 200 download, else the error text.
 * PURE. A 3xx is a failure (we never follow redirects) and names the redirect target.
 */
function nexovirt_download_error(int $code, string $output): string
{
    $status   = 0;
    $redirect = '';
    if (preg_match('/^' . CURL_WRITE_OUT_MARKER . ':(\d{3}):(.*)$/m', $output, $m) === 1) {
        $status   = (int) $m[1];
        $redirect = trim($m[2]);
    }
    $msg = trim((string) preg_replace('/^' . CURL_WRITE_OUT_MARKER . ':.*$/m', '', $output));
    $msg = implode(' ', array_slice(array_filter(explode("\n", $msg), 'strlen'), -3));

    if ($code !== 0) {
        return 'curl exit ' . $code . ($status > 0 ? ' (HTTP ' . $status . ')' : '') . ($msg !== '' ? ': ' . $msg : '');
    }
    if ($status >= 300 && $status < 400) {
        return 'HTTP ' . $status . ' redirect not followed' . ($redirect !== '' ? ' (to ' . $redirect . '); use the final URL' : '');
    }
    if ($status !== 200 && $status !== 206) { // 206 = a resumed partial download
        return 'unexpected HTTP status ' . $status;
    }
    return '';
}

/** HTTP status + redirect target from curl's --write-out marker line. PURE. @return array{0:int,1:string} */
function nexovirt_download_status(string $output): array
{
    if (preg_match('/^' . CURL_WRITE_OUT_MARKER . ':(\d{3}):(.*)$/m', $output, $m) === 1) {
        return [(int) $m[1], trim($m[2])];
    }
    return [0, ''];
}

/**
 * Next hop for a redirect, or '' when it must not be followed: only absolute http(s) URLs without
 * whitespace/control chars, and never a downgrade from https to http. PURE.
 */
function nexovirt_redirect_target(string $from, string $location): string
{
    if (preg_match('#^https?://#i', $location) !== 1 || preg_match('/[\s\x00-\x1f]/', $location) === 1) {
        return '';
    }
    if (stripos($from, 'https://') === 0 && stripos($location, 'https://') !== 0) {
        return '';
    }
    return $location;
}

/**
 * Sanity-check a downloaded file before it is reported as a usable image. Returns '' when it looks
 * right, else the reason. Catches the classic failure where an HTML page (error page, redirect
 * body, login wall) is saved under an image name. qcow2 must carry the qcow2 magic, compressed
 * templates their compression magic; other formats (raw/img/iso) just must not be HTML/empty.
 */
function nexovirt_image_content_error(string $path, string $filename, bool $isTemplate): string
{
    $fh   = @fopen($path, 'rb');
    $head = $fh !== false ? (string) fread($fh, 512) : '';
    if ($fh !== false) {
        fclose($fh);
    }
    if ($head === '') {
        return 'downloaded file is empty';
    }
    $lead = strtolower(ltrim(substr($head, 0, 256)));
    if (str_starts_with($lead, '<!doctype') || str_starts_with($lead, '<html') || str_starts_with($lead, '<?xml')
        || str_starts_with($lead, '<head') || str_starts_with($lead, '<body')) {
        return 'downloaded file is an HTML/XML page, not a disk image (check the image URL)';
    }
    $name  = strtolower($filename);
    $magic = [
        '.qcow2'   => "QFI\xfb",
        '.tar.zst' => "\x28\xb5\x2f\xfd",
        '.tar.gz'  => "\x1f\x8b",
        '.tgz'     => "\x1f\x8b",
        '.tar.xz'  => "\xfd7zXZ\x00",
    ];
    foreach ($magic as $ext => $sig) {
        if (str_ends_with($name, $ext) && ! str_starts_with($head, $sig)) {
            return 'downloaded file is not a valid ' . ltrim($ext, '.') . ' file (not a disk image)';
        }
    }
    return '';
}

/**
 * Run a shell command, invoking $tick roughly every $tickEvery seconds while it runs (used to send
 * "busy" heartbeats during long downloads so the panel does not mark the agent stale). Returns
 * ['code'=>int, 'out'=>string] (stdout; callers merge stderr with 2>&1). Falls back to a plain
 * blocking exec() when proc_open is unavailable (no ticks then).
 *
 * @return array{code:int, out:string}
 */
function nexovirt_run_with_ticks(string $cmd, ?callable $tick, int $tickEvery = 60): array
{
    if (! function_exists('proc_open')) {
        $lines = [];
        $code  = 0;
        exec($cmd, $lines, $code);
        return ['code' => $code, 'out' => implode("\n", $lines)];
    }

    $proc = proc_open($cmd, [1 => ['pipe', 'w']], $pipes);
    if (! is_resource($proc)) {
        return ['code' => -1, 'out' => 'proc_open failed'];
    }
    stream_set_blocking($pipes[1], false);
    $out      = '';
    $lastTick = time();
    $code     = -1;
    while (true) {
        $chunk = stream_get_contents($pipes[1]);
        if (is_string($chunk)) {
            $out .= $chunk;
        }
        $st = proc_get_status($proc);
        if (! $st['running']) {
            $code = (int) $st['exitcode'];
            break;
        }
        if ($tick !== null && time() - $lastTick >= $tickEvery) {
            $lastTick = time();
            try {
                $stop = $tick() === false; // a tick may return false to stop the command
            } catch (\Throwable $e) {
                $stop = false; // a failed busy heartbeat must never abort the job
            }
            if ($stop) {
                proc_terminate($proc);
                fclose($pipes[1]);
                proc_close($proc);
                return ['code' => -2, 'out' => $out . "\naborted"];
            }
        }
        usleep(250000);
    }
    $rest = stream_get_contents($pipes[1]);
    $out .= is_string($rest) ? $rest : '';
    fclose($pipes[1]);
    proc_close($proc); // exit code already captured from proc_get_status (proc_close returns -1 after it)
    return ['code' => $code, 'out' => $out];
}

/**
 * Parse the `content` value of one storage from /etc/pve/storage.cfg text. PURE.
 *
 * @return list<string>
 */
function nexovirt_storage_cfg_content(string $cfg, string $storage): array
{
    $in = false;
    foreach (explode("\n", $cfg) as $line) {
        if (preg_match('/^\S+:\s*(\S+)\s*$/', $line, $m) === 1) {
            $in = $m[1] === $storage;
            continue;
        }
        if ($in && preg_match('/^\s+content\s+(\S+)/', $line, $m) === 1) {
            return array_values(array_filter(explode(',', $m[1]), 'strlen'));
        }
    }
    return [];
}

/**
 * Make the managed storage advertise vztmpl (needed for `pct create` from a downloaded template)
 * WITHOUT dropping any content type an admin added: `pvesm set --content` replaces the list, so the
 * current list is read and merged first. Best-effort; skipped when already present.
 */
function nexovirt_ensure_vztmpl_content(): void
{
    $cfg     = is_readable('/etc/pve/storage.cfg') ? (string) @file_get_contents('/etc/pve/storage.cfg') : '';
    $current = nexovirt_storage_cfg_content($cfg, NEXOVIRT_IMAGES_STORAGE);
    if (in_array('vztmpl', $current, true)) {
        return;
    }
    $merged = array_values(array_unique(array_merge($current, ['import', 'iso', 'vztmpl'])));
    $list = implode(',', array_filter($merged, static fn ($c) => preg_match('/^[a-z]+$/', $c) === 1));
    @exec('pvesm set ' . escapeshellarg(NEXOVIRT_IMAGES_STORAGE) . ' --content ' . escapeshellarg($list) . ' 2>&1');
}

/**
 * Download an image to the managed iso dir via a constrained curl. Returns ['ok'=>bool,'result'=>string].
 * Validates the filename + url scheme + an SSRF deny-list (no internal/metadata targets, DNS pinned);
 * downloads to a `.part` then atomically renames on success. $tick is called periodically while the
 * transfer runs (busy heartbeats).
 */
function nexovirt_download_image(string $url, string $filename, string $content = 'iso', ?callable $tick = null, ?callable $runner = null, array $opt = []): array
{
    // $opt (cache downloads): resume (keep + continue an existing .part), headers (curl -D file),
    // min_free (bytes required before starting). Without $opt this is the legacy per-VM download.
    $resume = ! empty($opt['resume']);
    $isTemplate = $content === 'vztmpl';

    $validName = $isTemplate
        ? nexovirt_validate_template_filename($filename)
        : nexovirt_validate_image_filename($filename);
    if (! $validName) {
        return ['ok' => false, 'result' => 'invalid filename'];
    }
    if (preg_match('#^https?://#i', $url) !== 1 || preg_match('/[\s\x00-\x1f]/', $url) === 1) {
        return ['ok' => false, 'result' => 'invalid url'];
    }
    $target = nexovirt_url_resolve_target($url);
    if ($target['error'] !== '') {
        return ['ok' => false, 'result' => $target['error']];
    }

    if ($isTemplate) {
        nexovirt_ensure_vztmpl_content();
    }

    $dir = $isTemplate ? nexovirt_images_vztmpl_dir() : nexovirt_images_iso_dir();
    @mkdir($dir, 0755, true);

    $free    = @disk_free_space($dir);
    $minFree = max(MIN_FREE_BYTES, (int) ($opt['min_free'] ?? 0));
    if ($free !== false && $free < $minFree) {
        return ['ok' => false, 'result' => 'not enough free disk space in ' . $dir . ' (need at least ' . round($minFree / 1073741824, 1) . ' GiB)'];
    }

    $final = rtrim($dir, '/') . '/' . $filename;
    $part  = $final . '.part';

    // $runner is a test seam: fn(string $url, string $part, array $target, array $opt): array{code:int,out:string}.
    // `exec` makes curl replace the shell so an aborting tick really stops the transfer.
    $runner ??= static fn (string $u, string $p, array $t, array $o = []): array => nexovirt_run_with_ticks('exec ' . nexovirt_build_download_cmd($u, $p, $t, $o), $tick, $resume ? 5 : 60);

    // curl never follows redirects itself (--max-redirs 0): each hop is resolved + SSRF-validated +
    // DNS-pinned here, so a redirect can't lead the root agent to an internal/metadata address.
    $current  = $url;
    $err      = '';
    $restarts = 0;
    for ($hop = 0; ; $hop++) {
        clearstatcache(true, $part);
        $before = is_file($part) ? (int) filesize($part) : 0;
        $run    = $runner($current, $part, $target, ['resume' => $resume, 'headers' => (string) ($opt['headers'] ?? '')]);
        [$status, $location] = nexovirt_download_status($run['out']);
        // The server cannot resume this partial (no range support / range not satisfiable): start over once.
        if ($resume && $restarts === 0 && $before > 0 && ($run['code'] === 33 || $status === 416)) {
            $restarts++;
            @unlink($part);
            $hop--;
            continue;
        }
        if ($run['code'] !== 0 || $status < 300 || $status >= 400 || $location === '') {
            $err = nexovirt_download_error($run['code'], $run['out']);
            break;
        }
        // The redirect body is never kept: cut it off a resumed partial, drop it otherwise.
        if ($before > 0) {
            $fh = @fopen($part, 'r+');
            if ($fh !== false) {
                ftruncate($fh, $before);
                fclose($fh);
            }
        } else {
            @unlink($part);
        }
        if ($hop >= MAX_IMAGE_REDIRECTS) {
            $err = 'too many redirects (more than ' . MAX_IMAGE_REDIRECTS . ')';
            break;
        }
        $next = nexovirt_redirect_target($current, $location);
        if ($next === '') {
            $err = 'redirect to ' . $location . ' refused (must be http(s), no https-to-http downgrade)';
            break;
        }
        $target = nexovirt_url_resolve_target($next);
        if ($target['error'] !== '') {
            $err = 'redirect to ' . $location . ' refused: ' . $target['error'];
            break;
        }
        $current = $next;
    }

    if ($err === '') {
        $err = nexovirt_image_content_error($part, $filename, $isTemplate);
    }
    if ($err === '' && @rename($part, $final)) {
        return ['ok' => true, 'result' => 'downloaded ' . @filesize($final) . ' bytes' . ($current !== $url ? ' (via redirect)' : '')];
    }

    if (! $resume || $run['code'] === 0) {
        @unlink($part); // keep an interrupted cache download for the next resume, nothing else
    }
    return ['ok' => false, 'result' => $err !== '' ? $err : 'could not move the downloaded file into place'];
}

/** Delete a managed image/template (idempotent: a missing file is still ok). Returns ['ok'=>bool,'result'=>string]. */
function nexovirt_delete_image(string $filename, string $content = 'iso'): array
{
    $isTemplate = $content === 'vztmpl';
    $validName  = $isTemplate
        ? nexovirt_validate_template_filename($filename)
        : nexovirt_validate_image_filename($filename);
    if (! $validName) {
        return ['ok' => false, 'result' => 'invalid filename'];
    }
    $dir = $isTemplate ? nexovirt_images_vztmpl_dir() : nexovirt_images_iso_dir();
    if (! $isTemplate) {
        nexovirt_image_cache_forget($filename); // a cached image: stop its download, drop its state
    }
    @unlink(rtrim($dir, '/') . '/' . $filename);
    @unlink(rtrim($dir, '/') . '/' . $filename . '.part');
    return ['ok' => true, 'result' => 'deleted'];
}

// ---------------------------------------------------------------------------
// Image cache (0.24.0): one stable file per OS template in the managed iso dir, downloaded by a
// DETACHED child (systemd-run) so the agent loop never blocks, resumable, checksum-verified and
// reported in every heartbeat (stats.images). State per file: <images>/.nexovirt-state/<file>.json.
// ---------------------------------------------------------------------------

/** Free space kept on top of the remaining download size. */
const IMAGE_FREE_MARGIN = 1073741824;
/** Max image entries reported per heartbeat. */
const IMAGE_REPORT_MAX = 100; // agents.last_stats is TEXT (64 KB): ~250 bytes per entry
/** A .part file untouched this long without a live download is swept. */
const IMAGE_PART_MAX_AGE = 86400;
/** A queued download whose child never started is reported as interrupted after this long. */
const IMAGE_QUEUED_GRACE = 180;

/** Cache filenames: nxc-<templateId>-<10 hex>.<image ext>. */
function nexovirt_validate_cache_filename(string $f): bool
{
    return preg_match('/^nxc-\d{1,10}-[a-f0-9]{10}\.[A-Za-z0-9]+$/', $f) === 1 && nexovirt_validate_image_filename($f);
}

function nexovirt_image_state_dir(): string
{
    $base = getenv('NEXOVIRT_IMAGES_DIR');
    $base = $base !== false && $base !== '' ? $base : '/var/lib/nexovirt/images';
    return rtrim($base, '/') . '/.nexovirt-state';
}

/** @return array<string,mixed>|null */
function nexovirt_image_state_read(string $filename): ?array
{
    $raw = @file_get_contents(nexovirt_image_state_dir() . '/' . $filename . '.json');
    $s   = is_string($raw) ? json_decode($raw, true) : null;
    return is_array($s) ? $s : null;
}

/** @param array<string,mixed> $state */
function nexovirt_image_state_write(string $filename, array $state): bool
{
    $dir = nexovirt_image_state_dir();
    if (! is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    $state['updated_at'] = time();
    return nexovirt_write_private($dir . '/' . $filename . '.json', nexovirt_json($state));
}

function nexovirt_image_unit(string $filename): string
{
    return 'nexovirt-img-' . substr(sha1($filename), 0, 12);
}

/** True while the process that owns a download state is alive. */
function nexovirt_image_pid_alive(int $pid): bool
{
    if ($pid <= 0) {
        return false;
    }
    if (function_exists('posix_kill')) {
        return @posix_kill($pid, 0);
    }
    return is_dir('/proc/' . $pid);
}

/** Total size of the file being downloaded from a curl -D header dump (last response wins). PURE. */
function nexovirt_header_total(string $headers, int $offset): int
{
    $blocks = preg_split('/(?=^HTTP\/)/mi', $headers) ?: [];
    $last   = (string) end($blocks);
    if (preg_match('/^content-range:\s*bytes\s+\d+-\d+\/(\d+)/mi', $last, $m) === 1) {
        return (int) $m[1];
    }
    if (preg_match('/^content-length:\s*(\d+)/mi', $last, $m) === 1) {
        return (int) $m[1] + $offset;
    }
    return 0;
}

/** '' when $free covers the rest of the download plus the margin; unknown total = no verdict. PURE. */
function nexovirt_image_space_error(int $free, int $total, int $have): string
{
    if ($total <= 0) {
        return '';
    }
    $need = max(0, $total - $have) + IMAGE_FREE_MARGIN;
    return $free >= $need ? '' : 'not enough free disk space on the node: the image needs '
        . round($need / 1073741824, 1) . ' GiB (incl. 1 GiB reserve), ' . round($free / 1073741824, 1) . ' GiB free';
}

/**
 * Job image_cache_start: validate, record a queued state + the download spec, launch the detached
 * child. Returns quickly; progress arrives through stats.images. Idempotent while a download runs.
 *
 * @param array<string,mixed> $p {url, filename, expected_sha256?}
 * @return array{ok:bool, result:string}
 */
function nexovirt_image_cache_start(array $p): array
{
    $url      = (string) ($p['url'] ?? '');
    $filename = (string) ($p['filename'] ?? '');
    $sha      = strtolower((string) ($p['expected_sha256'] ?? ''));
    if (! nexovirt_validate_cache_filename($filename)) {
        return ['ok' => false, 'result' => 'invalid filename'];
    }
    if ($sha !== '' && preg_match('/^[a-f0-9]{64}$/', $sha) !== 1) {
        return ['ok' => false, 'result' => 'invalid sha256'];
    }
    if (preg_match('#^https?://#i', $url) !== 1 || preg_match('/[\s\x00-\x1f]/', $url) === 1) {
        return ['ok' => false, 'result' => 'invalid url'];
    }
    if ($sha === '' && stripos($url, 'https://') !== 0) {
        return ['ok' => false, 'result' => 'an http image URL needs a SHA-256 checksum (or use https)'];
    }
    $target = nexovirt_url_resolve_target($url);
    if ($target['error'] !== '') {
        return ['ok' => false, 'result' => $target['error']];
    }

    $state = nexovirt_image_state_read($filename);
    if ((in_array($state['state'] ?? '', ['running', 'verifying'], true) && nexovirt_image_pid_alive((int) ($state['pid'] ?? 0)))
        || (($state['state'] ?? '') === 'queued' && time() - (int) ($state['started_at'] ?? 0) <= IMAGE_QUEUED_GRACE)) {
        return ['ok' => true, 'result' => 'already downloading'];
    }

    $spec = ['url' => $url, 'filename' => $filename, 'expected_sha256' => $sha];
    if (! nexovirt_image_state_write($filename, ['state' => 'queued', 'started_at' => time()])
        || ! nexovirt_write_private(nexovirt_image_state_dir() . '/' . $filename . '.spec', nexovirt_json($spec))) {
        return ['ok' => false, 'result' => 'could not write the download state in ' . nexovirt_image_state_dir()];
    }

    $env = getenv('NEXOVIRT_IMAGES_DIR');
    $cmd = 'systemd-run --unit=' . nexovirt_image_unit($filename) . ' --collect --quiet'
        . ($env !== false && $env !== '' ? ' --setenv=NEXOVIRT_IMAGES_DIR=' . escapeshellarg($env) : '')
        . ' ' . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__) . ' --image-download ' . escapeshellarg($filename);
    if (getenv('NEXOVIRT_AGENT_DRYRUN') === '1') {
        return ['ok' => true, 'result' => $cmd];
    }
    @exec('systemctl stop ' . escapeshellarg(nexovirt_image_unit($filename)) . ' 2>/dev/null'); // a dead previous run
    $out  = [];
    $code = 0;
    exec($cmd . ' 2>&1', $out, $code);
    if ($code !== 0) {
        nexovirt_image_state_write($filename, ['state' => 'error', 'error' => 'could not start the download: ' . substr(implode(' ', $out), 0, 300)]);
        return ['ok' => false, 'result' => 'could not start the download: ' . substr(implode(' ', $out), 0, 300)];
    }
    return ['ok' => true, 'result' => 'started'];
}

/**
 * The detached child (`--image-download <file>`): resumable download, live progress + free-space
 * guard in the state file, sha256 verification. $runner is the test seam of nexovirt_download_image.
 *
 * @return array{ok:bool, result:string}
 */
function nexovirt_image_cache_run(string $filename, ?callable $runner = null): array
{
    if (! nexovirt_validate_cache_filename($filename)) {
        return ['ok' => false, 'result' => 'invalid filename'];
    }
    $raw  = @file_get_contents(nexovirt_image_state_dir() . '/' . $filename . '.spec');
    $spec = is_string($raw) ? json_decode($raw, true) : null;
    if (! is_array($spec)) {
        nexovirt_image_state_write($filename, ['state' => 'error', 'error' => 'download spec missing']);
        return ['ok' => false, 'result' => 'download spec missing'];
    }
    $expected = (string) ($spec['expected_sha256'] ?? '');
    $dir      = nexovirt_images_iso_dir();
    $part     = $dir . '/' . $filename . '.part';
    $hdr      = nexovirt_image_state_dir() . '/' . $filename . '.hdr';
    $started  = time();
    $pid      = getmypid() ?: 0;
    $total    = 0;
    $abort    = '';
    @unlink($hdr);
    nexovirt_image_state_write($filename, ['state' => 'running', 'pid' => $pid, 'started_at' => $started]);

    $tick = static function () use ($filename, $part, $hdr, $pid, $started, $dir, &$total, &$abort): bool {
        clearstatcache(true, $part);
        $have = is_file($part) ? (int) filesize($part) : 0;
        $t    = nexovirt_header_total((string) @file_get_contents($hdr), 0);
        $total = $t > 0 ? $t : $total;
        $free  = @disk_free_space($dir);
        $abort = $free === false ? '' : nexovirt_image_space_error((int) $free, $total, $have);
        nexovirt_image_state_write($filename, ['state' => 'running', 'pid' => $pid, 'started_at' => $started, 'bytes' => $have, 'total' => $total]);
        return $abort === '';
    };
    // ponytail: the Content-Range total covers a resumed partial; a plain 200 total is the full size.
    $wrapped = $runner === null ? null : static function (string $u, string $p, array $t, array $o = []) use ($runner, $tick): array {
        $r = $runner($u, $p, $t, $o);
        $tick();
        return $r;
    };

    $r = nexovirt_download_image((string) ($spec['url'] ?? ''), $filename, 'iso', $tick, $wrapped, ['resume' => true, 'headers' => $hdr]);
    @unlink($hdr);
    if (! $r['ok']) {
        $err = $abort !== '' ? $abort : $r['result'];
        nexovirt_image_state_write($filename, ['state' => 'error', 'error' => $err, 'total' => $total]);
        return ['ok' => false, 'result' => $err];
    }

    $final = $dir . '/' . $filename;
    nexovirt_image_state_write($filename, ['state' => 'verifying', 'pid' => $pid, 'started_at' => $started, 'total' => (int) @filesize($final)]);
    $sha = (string) @hash_file('sha256', $final);
    if ($expected !== '' && ! hash_equals($expected, $sha)) {
        @unlink($final);
        $err = 'checksum mismatch: the downloaded image does not match the SHA-256 of the template';
        nexovirt_image_state_write($filename, ['state' => 'error', 'error' => $err]);
        return ['ok' => false, 'result' => $err];
    }
    $size = (int) @filesize($final);
    nexovirt_image_state_write($filename, ['state' => 'ready', 'size' => $size, 'sha256' => $sha, 'finished_at' => time()]);
    @unlink(nexovirt_image_state_dir() . '/' . $filename . '.spec');
    return ['ok' => true, 'result' => 'ready ' . $size . ' bytes'];
}

/** Stop a running cache download and drop its state/spec/header files (delete_image). */
function nexovirt_image_cache_forget(string $filename): void
{
    if (! nexovirt_validate_image_filename($filename)) {
        return;
    }
    $state = nexovirt_image_state_read($filename);
    if ($state !== null && getenv('NEXOVIRT_AGENT_DRYRUN') !== '1'
        && in_array($state['state'] ?? '', ['queued', 'running', 'verifying'], true)) {
        @exec('systemctl stop ' . escapeshellarg(nexovirt_image_unit($filename)) . ' 2>/dev/null');
    }
    foreach (['.json', '.spec', '.hdr'] as $ext) {
        @unlink(nexovirt_image_state_dir() . '/' . $filename . $ext);
    }
}

/**
 * The cache as reported in every heartbeat: each image file in the managed iso dir plus every
 * download state without a finished file. state: ready | queued | running | verifying | error |
 * other (an image file the cache does not manage, e.g. an old per-VM leftover).
 *
 * @return list<array{name:string, size:int, state:string, bytes:int, total:int, sha256:string, error:string}>
 */
function nexovirt_images_report(): array
{
    $dir   = nexovirt_images_iso_dir();
    $names = [];
    foreach ((array) @scandir($dir) as $f) {
        if (is_string($f) && nexovirt_validate_image_filename($f)) {
            $names[$f] = true;
        }
    }
    foreach ((array) @scandir(nexovirt_image_state_dir()) as $f) {
        if (is_string($f) && str_ends_with($f, '.json') && nexovirt_validate_cache_filename(substr($f, 0, -5))) {
            $names[substr($f, 0, -5)] = true;
        }
    }
    ksort($names);

    $out = [];
    foreach (array_slice(array_keys($names), 0, IMAGE_REPORT_MAX) as $name) {
        $name  = (string) $name;
        $file  = $dir . '/' . $name;
        $state = nexovirt_image_state_read($name);
        $st    = (string) ($state['state'] ?? (is_file($file) ? 'other' : 'error'));
        $err   = (string) ($state['error'] ?? '');
        if (in_array($st, ['running', 'verifying'], true) && ! nexovirt_image_pid_alive((int) ($state['pid'] ?? 0))) {
            [$st, $err] = ['error', 'download interrupted (the node or the download process stopped); download it again to resume'];
        }
        if ($st === 'queued' && time() - (int) ($state['started_at'] ?? 0) > IMAGE_QUEUED_GRACE) {
            [$st, $err] = ['error', 'download did not start'];
        }
        if ($st === 'ready' && ! is_file($file)) {
            [$st, $err] = ['error', 'the image file is missing on the node'];
        }
        $part = $file . '.part';
        $out[] = [
            'name'   => $name,
            'size'   => is_file($file) ? (int) @filesize($file) : 0,
            'state'  => $st,
            'bytes'  => is_file($part) ? (int) @filesize($part) : (int) ($state['bytes'] ?? 0),
            'total'  => (int) ($state['total'] ?? 0),
            'sha256' => (string) ($state['sha256'] ?? ''),
            'error'  => substr($err, 0, 300), // byte cut: PVE's php-cli has no mbstring
        ];
    }
    return $out;
}

/** Delete .part files untouched for IMAGE_PART_MAX_AGE that no live download owns. */
function nexovirt_images_sweep(int $now): void
{
    $dir = nexovirt_images_iso_dir();
    foreach ((array) @scandir($dir) as $f) {
        if (! is_string($f) || ! str_ends_with($f, '.part') || ! nexovirt_validate_image_filename(substr($f, 0, -5))) {
            continue;
        }
        $state = nexovirt_image_state_read(substr($f, 0, -5));
        if (in_array($state['state'] ?? '', ['running', 'verifying'], true) && nexovirt_image_pid_alive((int) ($state['pid'] ?? 0))) {
            continue;
        }
        if ($now - (int) @filemtime($dir . '/' . $f) > IMAGE_PART_MAX_AGE) {
            @unlink($dir . '/' . $f);
        }
    }
}

/**
 * The FIXED in-container script that enables root SSH login (password + key) on an LXC.
 * Contains NO user input: the vmid is passed to `pct exec` (escapeshellarg'd by the caller),
 * never into this script. Each branch is best-effort (`|| true`): we install openssh-server if a
 * package manager is present, force PermitRootLogin/PasswordAuthentication to "yes" in
 * sshd_config (sed an existing line OR append when absent), then enable+restart sshd across the
 * init systems CT templates use (systemd, OpenRC, sysv).
 */
function nexovirt_lxc_root_ssh_script(): string
{
    return <<<'SH'
set -e
# Best-effort install of an SSH server (only if not already present).
if ! command -v sshd >/dev/null 2>&1 && [ ! -x /usr/sbin/sshd ]; then
  { command -v apt-get >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server; } \
    || { command -v apk >/dev/null 2>&1 && apk add --no-cache openssh; } \
    || { command -v dnf >/dev/null 2>&1 && dnf install -y openssh-server; } \
    || { command -v yum >/dev/null 2>&1 && yum install -y openssh-server; } \
    || true
fi
CFG=/etc/ssh/sshd_config
if [ -f "$CFG" ]; then
  if grep -Eq '^[[:space:]]*#?[[:space:]]*PermitRootLogin' "$CFG"; then
    sed -i 's/^[[:space:]]*#\?[[:space:]]*PermitRootLogin.*/PermitRootLogin yes/' "$CFG"
  else
    echo 'PermitRootLogin yes' >> "$CFG"
  fi
  if grep -Eq '^[[:space:]]*#?[[:space:]]*PasswordAuthentication' "$CFG"; then
    sed -i 's/^[[:space:]]*#\?[[:space:]]*PasswordAuthentication.*/PasswordAuthentication yes/' "$CFG"
  else
    echo 'PasswordAuthentication yes' >> "$CFG"
  fi
fi
# Enable + (re)start sshd across init systems: tolerate the branches that don't apply.
# Disable socket-activation FIRST: modern Debian 12 / Ubuntu 24.04 ship ssh.socket enabled, and
# enabling ssh.service on top means both fight over port 22 on the next boot → both die → no SSH.
# Disabling the socket leaves exactly one listener (the classic ssh.service) → clean SSH on reboot.
{ systemctl disable --now ssh.socket 2>/dev/null; } || true
{ systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd 2>/dev/null; } || true
{ rc-update add sshd default 2>/dev/null && rc-service sshd restart 2>/dev/null; } || true
{ service ssh restart 2>/dev/null || service sshd restart 2>/dev/null; } || true
exit 0
SH;
}

/**
 * Enable root SSH login (password + key) inside an LXC container. Ensures the CT is running first
 * (starts it + waits briefly, bounded) then runs the FIXED enable script via `pct exec`. The
 * $vmid is the ONLY interpolated value and is escapeshellarg'd. Returns ['ok'=>bool,'result'=>str].
 * Best-effort: as long as the exec ran we report ok (individual in-container branches tolerate
 * failure themselves).
 */
function nexovirt_lxc_root_ssh(int $vmid): array
{
    if ($vmid < 1) {
        return ['ok' => false, 'result' => 'invalid vmid'];
    }
    $id = escapeshellarg((string) $vmid);

    // Ensure the CT is running (the password-set + console depend on a booted container).
    $statusOut = [];
    exec("pct status {$id} 2>&1", $statusOut);
    $status = strtolower(trim(implode("\n", $statusOut)));
    if (strpos($status, 'running') === false) {
        exec("pct start {$id} 2>&1");
        // Bounded wait for boot: poll status up to ~10s.
        for ($i = 0; $i < 10; $i++) {
            sleep(1);
            $s = [];
            exec("pct status {$id} 2>&1", $s);
            if (strpos(strtolower(trim(implode("\n", $s))), 'running') !== false) {
                break;
            }
        }
    }

    $script = nexovirt_lxc_root_ssh_script();
    $cmd    = "pct exec {$id} -- sh -c " . escapeshellarg($script) . ' 2>&1';
    $out    = [];
    $code   = 0;
    exec($cmd, $out, $code);

    return $code === 0
        ? ['ok' => true, 'result' => 'root ssh enabled']
        : ['ok' => false, 'result' => 'pct exec failed: ' . trim(implode(' ', array_slice($out, -3)))];
}

/**
 * Set the root password inside an LXC container. PVE has no config API for this (the config schema
 * rejects `password` on an existing CT), so it's done on the host via `pct exec … chpasswd`.
 * The $vmid is the ONLY interpolated value (escapeshellarg'd + int-cast); the password is written to
 * chpasswd's STDIN and NEVER touches the command line. Ensures the CT is running first.
 * Returns ['ok'=>bool,'result'=>str].
 */
function nexovirt_lxc_set_password(int $vmid, string $password): array
{
    if ($vmid < 1) {
        return ['ok' => false, 'result' => 'invalid vmid'];
    }
    if ($password === '') {
        return ['ok' => false, 'result' => 'empty password'];
    }
    // chpasswd is line-based: a CR/LF would start a second `user:password` record (e.g. set another
    // account's password) and NUL truncates. ':' is fine (chpasswd splits on the FIRST colon only).
    if (strpbrk($password, "\r\n\0") !== false) {
        return ['ok' => false, 'result' => 'password contains invalid characters'];
    }
    $id = escapeshellarg((string) $vmid);

    // Ensure the CT is running (chpasswd needs a booted container).
    $statusOut = [];
    exec("pct status {$id} 2>&1", $statusOut);
    if (strpos(strtolower(trim(implode("\n", $statusOut))), 'running') === false) {
        exec("pct start {$id} 2>&1");
        for ($i = 0; $i < 10; $i++) {
            sleep(1);
            $s = [];
            exec("pct status {$id} 2>&1", $s);
            if (strpos(strtolower(trim(implode("\n", $s))), 'running') !== false) {
                break;
            }
        }
    }

    // chpasswd reads `user:password` from STDIN: keeps the secret off argv and out of the process list.
    $desc = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open("pct exec {$id} -- chpasswd 2>&1", $desc, $pipes);
    if (! is_resource($proc)) {
        return ['ok' => false, 'result' => 'proc_open failed'];
    }
    fwrite($pipes[0], 'root:' . $password . "\n");
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);

    return $code === 0
        ? ['ok' => true, 'result' => 'password set']
        : ['ok' => false, 'result' => 'chpasswd failed: ' . (trim($out) !== '' ? trim($out) : ('exit ' . $code))];
}

// ---------------------------------------------------------------------------
// NAT / port-forwarding: host firewall mutation, dedicated NEXOVIRT chains only.
//
// SAFETY CONTRACT (do not weaken):
//  - The agent owns exactly four chains: NEXOVIRT-PRE (nat/PREROUTING),
//    NEXOVIRT-POST (nat/POSTROUTING), NEXOVIRT-FWD (filter/FORWARD) and
//    NEXOVIRT-RAW (raw/PREROUTING: conntrack zone for PVE firewall bridges).
//  - It jumps into them from the built-ins IDEMPOTENTLY (-C || -I) and FLUSHES
//    ONLY its own chains (-F NEXOVIRT-*). It NEVER flushes a built-in chain and
//    NEVER touches any non-NEXOVIRT rule (incl. the PVE firewall).
//  - Every value is validated; the whole job is rejected on ANY bad field.
//  - Every interpolated value is escapeshellarg'd.
//  - The MASQUERADE source CIDR MUST be RFC1918 private (the agent checks itself).
// ---------------------------------------------------------------------------

const NAT_SCRIPT_PATH  = '/usr/local/sbin/nexovirt-nat.sh';
const NAT_UNIT_PATH    = '/etc/systemd/system/nexovirt-nat.service';
const NAT_SYSCTL_PATH  = '/etc/sysctl.d/99-nexovirt-nat.conf';
const NAT_MODULES_PATH = '/etc/modules-load.d/nexovirt-nat.conf';

/** A Linux network interface name: 1..15 chars, letters/digits/dot/underscore/hyphen. */
function nexovirt_validate_iface(string $i): bool
{
    return preg_match('/^[A-Za-z0-9._-]{1,15}$/', $i) === 1;
}

/** Only tcp or udp (lowercase). */
function nexovirt_validate_proto(string $p): bool
{
    return $p === 'tcp' || $p === 'udp';
}

/** A TCP/UDP port number: integer 1..65535. */
function nexovirt_validate_port($p): bool
{
    if (! is_int($p) && (! is_string($p) || ! ctype_digit($p))) {
        return false;
    }
    $n = (int) $p;
    return $n >= 1 && $n <= 65535;
}

/** A probe target: an IPv4/IPv6 literal or a DNS name (labels a-z0-9-, no leading/trailing hyphen, <= 253 chars). */
function nexovirt_validate_probe_host(string $h): bool
{
    if ($h === '' || strlen($h) > 253) {
        return false;
    }
    if (filter_var($h, FILTER_VALIDATE_IP) !== false) {
        return true;
    }

    return preg_match('/^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/', $h) === 1;
}

/**
 * TCP reachability probe for migration pre-flight (can THIS node reach the target's API port?).
 * Fail-closed validation; fsockopen with a short timeout; no shell involved.
 *
 * @return array{ok:bool,result:string}
 */
function nexovirt_probe_tcp(string $host, $port): array
{
    if (! nexovirt_validate_probe_host($host) || ! nexovirt_validate_port($port)) {
        return ['ok' => false, 'result' => 'invalid probe_tcp payload'];
    }
    $target = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? '[' . $host . ']' : $host;
    $errno  = 0;
    $errstr = '';
    $fh     = @fsockopen($target, (int) $port, $errno, $errstr, 5.0);
    if ($fh === false) {
        return ['ok' => true, 'result' => nexovirt_json(['reachable' => false, 'error' => $errstr !== '' ? $errstr : ('connect failed (' . $errno . ')')])];
    }
    fclose($fh);

    return ['ok' => true, 'result' => nexovirt_json(['reachable' => true, 'error' => ''])];
}

/**
 * `pct unlock` / `qm unlock` command for a guest, or null for an invalid type/vmid. PURE.
 * PVE leaves a remote-migration source locked ('migrate') and its API cannot remove a container
 * lock, so the panel asks the node agent. Only the two fixed binaries, vmid digits only.
 */
function nexovirt_guest_unlock_cmd(string $type, $vmid): ?string
{
    $bin = ['lxc' => 'pct', 'qemu' => 'qm'][$type] ?? null;
    $v   = is_int($vmid) ? (string) $vmid : (is_string($vmid) ? $vmid : '');
    if ($bin === null || preg_match('/^[1-9][0-9]{2,8}$/', $v) !== 1) {
        return null;
    }

    return $bin . ' unlock ' . escapeshellarg($v) . ' 2>&1';
}

/** @return array{ok:bool,result:string} */
function nexovirt_guest_unlock(string $type, $vmid): array
{
    $cmd = nexovirt_guest_unlock_cmd($type, $vmid);
    if ($cmd === null) {
        return ['ok' => false, 'result' => 'invalid guest_unlock payload'];
    }
    $out  = [];
    $code = 0;
    exec($cmd, $out, $code);

    return ['ok' => $code === 0, 'result' => $code === 0 ? 'unlocked' : nexovirt_cap_output(implode("\n", $out))];
}

/**
 * A valid IPv4 CIDR whose WHOLE range lies inside ONE RFC1918 block (10/8, 172.16/12, 192.168/16):
 * the prefix must be at least the block's prefix (so 192.168.0.0/0 or 10.0.0.0/1, which would
 * MASQUERADE / DNAT the entire internet, are rejected) and the masked network must be in the block.
 * Host bits may be set (e.g. the bridge address form 10.0.10.1/24, which the panel prefills from the
 * PVE bridge config): the range it denotes is identical to 10.0.10.0/24 and iptables masks it the
 * same way, so rejecting it would only break existing configs without adding safety.
 * The RFC1918 check is done here so the agent never trusts the panel for the private-range guarantee.
 */
function nexovirt_validate_nat_cidr(string $c): bool
{
    if (preg_match('#^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$#', $c, $m) !== 1) {
        return false;
    }
    $prefix = (int) $m[2];
    if ($prefix > 32 || filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        return false;
    }
    $ip = ip2long($m[1]);
    if ($ip === false) {
        return false;
    }
    $mask    = $prefix === 0 ? 0 : ((0xFFFFFFFF << (32 - $prefix)) & 0xFFFFFFFF);
    $network = $ip & $mask;

    $blocks = [['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16]];
    foreach ($blocks as [$base, $bits]) {
        $blockMask = (0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF;
        if ($prefix >= $bits && ($network & $blockMask) === (ip2long($base) & $blockMask)) {
            return true;
        }
    }
    return false;
}

/** True when $ip is a valid IPv4 address inside $cidr (which need not itself be private here). */
function nexovirt_nat_ip_in_cidr(string $ip, string $cidr): bool
{
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        return false;
    }
    if (! str_contains($cidr, '/')) {
        return false;
    }
    [$net, $bits] = explode('/', $cidr, 2);
    if ($bits === '' || ! ctype_digit($bits)) {
        return false;
    }
    $prefix = (int) $bits;
    if ($prefix < 0 || $prefix > 32) {
        return false;
    }
    if (filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        return false;
    }

    $ipLong  = ip2long($ip) & 0xFFFFFFFF;
    $netLong = ip2long($net) & 0xFFFFFFFF;
    $mask    = $prefix === 0 ? 0 : ((0xFFFFFFFF << (32 - $prefix)) & 0xFFFFFFFF);

    return ($ipLong & $mask) === ($netLong & $mask);
}

/**
 * Validate a whole NAT config. Returns ['ok'=>bool,'error'=>string].
 * Rejects on ANY bad field (fail-closed). Pure (no side effects).
 *
 * @param array{wan_iface?:string, private_cidr?:string, masquerade?:bool, forwards?:array} $config
 */
function nexovirt_validate_nat_config(array $config): array
{
    $wan  = (string) ($config['wan_iface'] ?? '');
    $cidr = (string) ($config['private_cidr'] ?? '');

    if (! nexovirt_validate_iface($wan)) {
        return ['ok' => false, 'error' => 'invalid wan_iface'];
    }
    if (! nexovirt_validate_nat_cidr($cidr)) {
        return ['ok' => false, 'error' => 'invalid or non-private private_cidr'];
    }

    $forwards = $config['forwards'] ?? [];
    if (! is_array($forwards)) {
        return ['ok' => false, 'error' => 'invalid forwards'];
    }

    // A port-forward may target a guest on an isolated SDN project subnet, not just private_cidr. The
    // panel passes those subnets in allowed_dest_cidrs. Re-validate each here (fail-closed): only
    // RFC1918 ranges are accepted, so a bad/compromised panel can't DNAT to an arbitrary public IP.
    $destCidrs = [$cidr];
    $allowed   = $config['allowed_dest_cidrs'] ?? [];
    if (is_array($allowed)) {
        foreach ($allowed as $a) {
            $a = (string) $a;
            if ($a !== '' && nexovirt_validate_nat_cidr($a)) {
                $destCidrs[] = $a;
            }
        }
    }

    foreach ($forwards as $f) {
        if (! is_array($f)) {
            return ['ok' => false, 'error' => 'invalid forward'];
        }
        $proto = (string) ($f['proto'] ?? '');
        $pub   = $f['public_port'] ?? null;
        $end   = $f['public_port_end'] ?? null;
        $dip   = (string) ($f['dest_ip'] ?? '');
        $dport = $f['dest_port'] ?? null;

        if (! nexovirt_validate_proto($proto)) {
            return ['ok' => false, 'error' => 'invalid proto'];
        }
        if (! nexovirt_validate_port($pub)) {
            return ['ok' => false, 'error' => 'invalid port'];
        }
        if ($end !== null) {
            if (! nexovirt_validate_port($end) || (int) $end < (int) $pub) {
                return ['ok' => false, 'error' => 'invalid port range'];
            }
        } elseif (! nexovirt_validate_port($dport)) {
            return ['ok' => false, 'error' => 'invalid port'];
        }
        $inAllowed = false;
        foreach ($destCidrs as $dc) {
            if (nexovirt_nat_ip_in_cidr($dip, $dc)) {
                $inAllowed = true;
                break;
            }
        }
        if (! $inAllowed) {
            return ['ok' => false, 'error' => 'dest_ip outside allowed CIDRs'];
        }
    }

    return ['ok' => true, 'error' => ''];
}

/**
 * Content of the persisted NAT sysctl file (/etc/sysctl.d/99-nexovirt-nat.conf). PURE.
 *
 * Only ip_forward. Agents <= 0.17 ALSO wrote `net.bridge.bridge-nf-call-iptables = 0` here; that
 * silently disabled the Proxmox firewall's filtering of bridged guest traffic (every per-guest
 * firewall rule the panel manages stopped applying) and fought pve-firewall, which sets it back to 1.
 * It is no longer needed: see nexovirt_build_nat_script() for the conntrack-zone fix that makes NAT
 * work with bridge-nf-call-iptables=1.
 */
function nexovirt_nat_sysctl_content(): string
{
    return "# Managed by nexovirt-agent - required for NexoVirt NAT (nexovirt-nat.service).\n"
        . "net.ipv4.ip_forward = 1\n";
}

/** True when a sysctl file body pins bridge-nf-call-iptables to 0 (written by agents <= 0.17). PURE. */
function nexovirt_sysctl_disables_bridge_nf(string $body): bool
{
    return preg_match('/^\s*net\.bridge\.bridge-nf-call-iptables\s*=\s*0\s*$/m', $body) === 1;
}

/**
 * Undo what agents <= 0.17 did: if OUR sysctl file pinned bridge-nf-call-iptables=0, set it back to 1
 * live (the kernel + Proxmox default, which re-enables per-guest firewall filtering). The caller
 * rewrites/removes the file itself. Best-effort. Returns true when a restore happened.
 */
function nexovirt_restore_bridge_nf(): bool
{
    $body = is_readable(NAT_SYSCTL_PATH) ? (string) @file_get_contents(NAT_SYSCTL_PATH) : '';
    if (! nexovirt_sysctl_disables_bridge_nf($body)) {
        return false;
    }
    exec('sysctl -w net.bridge.bridge-nf-call-iptables=1 2>&1');
    return true;
}

/**
 * Build the deterministic /bin/sh script that programs the NEXOVIRT chains.
 * PURE, no side effects. Caller MUST have validated $config first
 * (every interpolated value is still escapeshellarg'd defensively).
 *
 * @param array{wan_iface:string, private_cidr:string, masquerade:bool, forwards:array} $config
 */
function nexovirt_build_nat_script(array $config): string
{
    $wan  = escapeshellarg((string) $config['wan_iface']);
    $cidr = escapeshellarg((string) $config['private_cidr']);

    $lines   = [];
    $lines[] = '#!/bin/sh';
    $lines[] = 'set -e';
    $lines[] = '# Managed by nexovirt-agent: DO NOT EDIT. Dedicated NEXOVIRT-* chains only.';

    // 0. IPv4 forwarding (routes guest traffic). bridge-nf-call-iptables is deliberately NOT touched
    //    (it stays at the kernel/Proxmox default 1, so the PVE firewall keeps filtering guests).
    $lines[] = 'sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true';

    // 1. Ensure our chains exist (idempotent: ignore "already exists").
    $lines[] = 'iptables -t nat -N NEXOVIRT-PRE 2>/dev/null || true';
    $lines[] = 'iptables -t nat -N NEXOVIRT-POST 2>/dev/null || true';
    $lines[] = 'iptables -N NEXOVIRT-FWD 2>/dev/null || true';
    $lines[] = 'iptables -t raw -N NEXOVIRT-RAW 2>/dev/null || true';

    // 2. Idempotent jumps from the built-in chains into ours (-C || -I).
    $lines[] = 'iptables -t nat -C PREROUTING -j NEXOVIRT-PRE 2>/dev/null || iptables -t nat -I PREROUTING -j NEXOVIRT-PRE';
    $lines[] = 'iptables -t nat -C POSTROUTING -j NEXOVIRT-POST 2>/dev/null || iptables -t nat -I POSTROUTING -j NEXOVIRT-POST';
    $lines[] = 'iptables -C FORWARD -j NEXOVIRT-FWD 2>/dev/null || iptables -I FORWARD -j NEXOVIRT-FWD';
    $lines[] = 'iptables -t raw -C PREROUTING -j NEXOVIRT-RAW 2>/dev/null || iptables -t raw -I PREROUTING -j NEXOVIRT-RAW';

    // 3. Flush ONLY our chains (never the built-ins).
    $lines[] = 'iptables -t nat -F NEXOVIRT-PRE';
    $lines[] = 'iptables -t nat -F NEXOVIRT-POST';
    $lines[] = 'iptables -F NEXOVIRT-FWD';
    $lines[] = 'iptables -t raw -F NEXOVIRT-RAW';

    // 3b. Conntrack zone for the PVE firewall bridges (the documented Proxmox masquerade fix).
    //     With bridge-nf-call-iptables=1 a guest whose NIC has firewall=1 sits behind a per-guest
    //     fwbrN bridge, so each packet is seen by conntrack TWICE: first while being bridged through
    //     fwbrN (out iface = fwbrN, so the `-o <wan>` MASQUERADE does not match and conntrack commits
    //     the flow WITHOUT NAT), then again when routed out the WAN, where the already-confirmed flow
    //     is never re-evaluated -> MASQUERADE silently skipped. Putting the bridged pass into its own
    //     conntrack zone makes the routed pass a fresh flow in zone 0, so MASQUERADE / DNAT apply.
    //     This is why agents <= 0.17 needed bridge-nf-call-iptables=0 (which disabled the PVE
    //     firewall for guests); with the zone, NAT and the PVE firewall coexist. Best-effort: a
    //     kernel without the CT target still gets every other rule.
    $lines[] = "iptables -t raw -A NEXOVIRT-RAW -i 'fwbr+' -j CT --zone 1 || true";

    // 4. Return traffic for anything we forward / masquerade (hosts with FORWARD policy DROP).
    $lines[] = 'iptables -A NEXOVIRT-FWD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT';

    // 5. MASQUERADE the private network out the WAN bridge (never traffic that stays inside it),
    //    and let it be forwarded out.
    if (! empty($config['masquerade'])) {
        $lines[] = "iptables -t nat -A NEXOVIRT-POST -s {$cidr} ! -d {$cidr} -o {$wan} -j MASQUERADE";
        $lines[] = "iptables -A NEXOVIRT-FWD -s {$cidr} -o {$wan} -j ACCEPT";
    }

    // 6. Per-forward DNAT + matching FORWARD ACCEPT.
    foreach (($config['forwards'] ?? []) as $f) {
        $proto = escapeshellarg((string) $f['proto']);
        $dip   = (string) $f['dest_ip'];
        $dipA  = escapeshellarg($dip);
        $start = (int) $f['public_port'];
        $end   = ($f['public_port_end'] ?? null) !== null ? (int) $f['public_port_end'] : null;

        if ($end !== null) {
            // Range: same-port DNAT (no remap), range FORWARD ACCEPT.
            $rangeA = escapeshellarg($start . ':' . $end);
            $lines[] = "iptables -t nat -A NEXOVIRT-PRE -i {$wan} -p {$proto} --dport {$rangeA} -j DNAT --to-destination {$dipA}";
            $lines[] = "iptables -A NEXOVIRT-FWD -d {$dipA} -p {$proto} --dport {$rangeA} -j ACCEPT";
        } else {
            $pub    = escapeshellarg((string) $start);
            $dport  = (string) (int) $f['dest_port'];
            $dest   = escapeshellarg($dip . ':' . $dport);
            $dportA = escapeshellarg($dport);
            $lines[] = "iptables -t nat -A NEXOVIRT-PRE -i {$wan} -p {$proto} --dport {$pub} -j DNAT --to-destination {$dest}";
            $lines[] = "iptables -A NEXOVIRT-FWD -d {$dipA} -p {$proto} --dport {$dportA} -j ACCEPT";
        }
    }

    return implode("\n", $lines) . "\n";
}

/**
 * Validate + apply a NAT config. Returns ['ok'=>bool,'error'=>string] (+'script' on dry-run).
 *
 * DRY-RUN seam: when NEXOVIRT_AGENT_DRYRUN=1, validates + builds the script and
 * returns it WITHOUT writing any file or executing anything (the unit-test path).
 *
 * On a real run: writes the script (0755), installs+enables a oneshot systemd unit,
 * enables IPv4 forwarding (live + persisted), and runs the script.
 *
 * @param array{wan_iface:string, private_cidr:string, masquerade:bool, forwards:array} $config
 */
function nexovirt_apply_nat(array $config): array
{
    $valid = nexovirt_validate_nat_config($config);
    if (! $valid['ok']) {
        return ['ok' => false, 'error' => $valid['error']];
    }

    $script = nexovirt_build_nat_script($config);

    if (getenv('NEXOVIRT_AGENT_DRYRUN') === '1') {
        return ['ok' => true, 'error' => '', 'script' => $script];
    }

    if (@file_put_contents(NAT_SCRIPT_PATH, $script) === false) {
        return ['ok' => false, 'error' => 'cannot write nat script'];
    }
    @chmod(NAT_SCRIPT_PATH, 0755);

    $unit = "[Unit]\n"
        . "Description=NexoVirt NAT / port-forwarding (iptables)\n"
        . "After=network-online.target\n"
        . "Wants=network-online.target\n\n"
        . "[Service]\n"
        . "Type=oneshot\n"
        . "RemainAfterExit=yes\n"
        . "ExecStart=" . NAT_SCRIPT_PATH . "\n\n"
        . "[Install]\n"
        . "WantedBy=multi-user.target\n";
    @file_put_contents(NAT_UNIT_PATH, $unit);

    // Migrate off the agent <= 0.17 bridge-nf=0 hack: restore 1 live if OUR file pinned 0, then rewrite
    // the file with ip_forward only, and drop the br_netfilter modules-load file (nothing needs it now;
    // pve-firewall loads the module itself when active).
    $restored = nexovirt_restore_bridge_nf();
    @file_put_contents(NAT_SYSCTL_PATH, nexovirt_nat_sysctl_content());
    @unlink(NAT_MODULES_PATH);
    exec('sysctl -w net.ipv4.ip_forward=1 2>&1');
    if ($restored) {
        fwrite(STDOUT, "[nexovirt-agent] NAT: restored net.bridge.bridge-nf-call-iptables=1 (set to 0 by an older agent).\n");
    }

    exec('systemctl daemon-reload 2>&1');
    exec('systemctl enable nexovirt-nat.service 2>&1');

    $out  = [];
    $code = 0;
    exec(escapeshellarg(NAT_SCRIPT_PATH) . ' 2>&1', $out, $code);

    return $code === 0
        ? ['ok' => true, 'error' => '']
        : ['ok' => false, 'error' => trim(implode("\n", $out))];
}

/**
 * NAT teardown commands (best-effort, idempotent): drop the jumps, then flush + delete ONLY our
 * NEXOVIRT-* chains, then disable the unit. PURE. The panel's AgentLifecycle runs the same list over
 * SSH when the agent is removed. @return list<string>
 */
function nexovirt_nat_clear_cmds(): array
{
    return [
        // Remove the jumps (best-effort; ignore if absent).
        'iptables -t nat -D PREROUTING -j NEXOVIRT-PRE 2>/dev/null || true',
        'iptables -t nat -D POSTROUTING -j NEXOVIRT-POST 2>/dev/null || true',
        'iptables -D FORWARD -j NEXOVIRT-FWD 2>/dev/null || true',
        // Flush + delete only our chains.
        'iptables -t nat -F NEXOVIRT-PRE 2>/dev/null || true',
        'iptables -t nat -X NEXOVIRT-PRE 2>/dev/null || true',
        'iptables -t nat -F NEXOVIRT-POST 2>/dev/null || true',
        'iptables -t nat -X NEXOVIRT-POST 2>/dev/null || true',
        'iptables -F NEXOVIRT-FWD 2>/dev/null || true',
        'iptables -X NEXOVIRT-FWD 2>/dev/null || true',
        'systemctl disable --now nexovirt-nat.service 2>/dev/null || true',
        // Legacy raw-table chain from older agents.
        'iptables -t raw -D PREROUTING -j NEXOVIRT-RAW 2>/dev/null || true',
        'iptables -t raw -F NEXOVIRT-RAW 2>/dev/null || true',
        'iptables -t raw -X NEXOVIRT-RAW 2>/dev/null || true',
    ];
}

/**
 * Best-effort, idempotent NAT teardown. Removes the jumps, flushes+deletes the
 * NEXOVIRT chains, disables the unit, and removes the managed files.
 * Honors the DRYRUN seam. Returns ['ok'=>bool,'error'=>string].
 */
function nexovirt_clear_nat(): array
{
    if (getenv('NEXOVIRT_AGENT_DRYRUN') === '1') {
        return ['ok' => true, 'error' => ''];
    }

    foreach (nexovirt_nat_clear_cmds() as $cmd) {
        exec($cmd);
    }

    // Restore bridge-nf-call-iptables=1 if an older agent pinned it to 0. ip_forward is deliberately
    // left as-is (SDN egress / other features may rely on it; set_ip_forward owns turning it off).
    nexovirt_restore_bridge_nf();

    @unlink(NAT_SCRIPT_PATH);
    @unlink(NAT_UNIT_PATH);
    @unlink(NAT_SYSCTL_PATH);
    @unlink(NAT_MODULES_PATH);
    exec('systemctl daemon-reload 2>/dev/null');

    return ['ok' => true, 'error' => ''];
}

// ---------------------------------------------------------------------------
// WireGuard VPN (apply_wireguard / read_wireguard)
//
// SAFETY CONTRACT: the host private key is generated here and never leaves the host (it is only
// written into the 0600 wg-quick config next to it). Only our own NEXOVIRT-VPN* chains are created,
// flushed or deleted. Every payload field is validated fail-closed before any file or command is
// touched, and every interpolated value is escapeshellarg'd.
// ---------------------------------------------------------------------------

const DEFAULT_WG_DIR = '/etc/nexovirt-wg';
const WG_IFACE       = 'wg-nexovirt';
const WG_UNIT_PATH   = '/etc/systemd/system/nexovirt-wg.service';
const WG_SYSCTL_PATH = '/etc/sysctl.d/99-nexovirt-vpn.conf';
const WG_MAX_PEERS   = 1000;
const WG_MAX_PEER_ADDRESSES = 64; // one address per VPN node a device reaches

function nexovirt_wg_dir(): string
{
    $d = getenv('WG_DIR');

    return $d !== false && $d !== '' ? rtrim($d, '/') : DEFAULT_WG_DIR;
}

/** A base64 Curve25519 key (32 bytes): 43 chars + '=', the 43rd char carries only 2 meaningful bits. */
function nexovirt_wg_valid_key(string $k): bool
{
    return preg_match('#^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$#', $k) === 1;
}

/** True for "a.b.c.d/32" whose address is valid IPv4. */
function nexovirt_wg_is_host32(string $c): bool
{
    return preg_match('#^(\d{1,3}(?:\.\d{1,3}){3})/32$#', $c, $m) === 1
        && filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
}

/**
 * A restricted peer's allow entry: a guest /32 or an SDN project subnet (/16../31, network-aligned), always
 * RFC1918 and never overlapping the VPN subnet itself (that would open client-to-client traffic). PURE.
 */
function nexovirt_wg_valid_allow(string $c, string $subnet): bool
{
    if (preg_match('#^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$#', $c, $m) !== 1 || ! nexovirt_validate_nat_cidr($c)) {
        return false;
    }
    $prefix = (int) $m[2];
    if ($prefix < 16) {
        return false;
    }
    $mask = (0xFFFFFFFF << (32 - $prefix)) & 0xFFFFFFFF;
    if ((ip2long($m[1]) & $mask) !== (ip2long($m[1]) & 0xFFFFFFFF)) {
        return false; // host bits set
    }
    $sub = explode('/', $subnet)[0];

    return ! nexovirt_nat_ip_in_cidr($m[1], $subnet) && ! nexovirt_nat_ip_in_cidr($sub, $c);
}

/**
 * Validate an apply_wireguard payload. Fail-closed: the first bad field rejects the whole job. PURE.
 *
 * @return array{ok:bool,error:string}
 */
function nexovirt_validate_wg_payload(array $p): array
{
    if (empty($p['enabled'])) {
        return ['ok' => true, 'error' => '']; // disable needs no other field
    }
    $port = $p['port'] ?? null;
    if ((! is_int($port) && (! is_string($port) || ! ctype_digit($port))) || (int) $port < 1024 || (int) $port > 65535) {
        return ['ok' => false, 'error' => 'invalid port'];
    }
    $subnet = (string) ($p['subnet'] ?? '');
    if (! nexovirt_validate_nat_cidr($subnet)) {
        return ['ok' => false, 'error' => 'invalid or non-private subnet'];
    }
    $address = (string) ($p['address'] ?? '');
    $hostIp  = explode('/', $address, 2)[0];
    if (! nexovirt_validate_nat_cidr($address) || explode('/', $address)[1] !== explode('/', $subnet)[1]
        || ! nexovirt_nat_ip_in_cidr($hostIp, $subnet)) {
        return ['ok' => false, 'error' => 'invalid address'];
    }
    $nets = $p['forward_nets'] ?? [];
    if (! is_array($nets) || count($nets) > 64) {
        return ['ok' => false, 'error' => 'invalid forward net'];
    }
    foreach ($nets as $n) {
        if (! is_string($n) || ! nexovirt_validate_nat_cidr($n)) {
            return ['ok' => false, 'error' => 'invalid forward net'];
        }
    }
    $peers = $p['peers'] ?? [];
    if (! is_array($peers) || ! array_is_list($peers)) {
        return ['ok' => false, 'error' => 'invalid peers'];
    }
    if (count($peers) > WG_MAX_PEERS) {
        return ['ok' => false, 'error' => 'too many peers'];
    }
    $seenKeys = [];
    $seenIps  = [];
    foreach ($peers as $peer) {
        if (! is_array($peer) || ! nexovirt_wg_valid_key((string) ($peer['public_key'] ?? ''))) {
            return ['ok' => false, 'error' => 'invalid peer public key'];
        }
        if (! in_array($peer['role'] ?? '', ['admin', 'customer'], true)) {
            return ['ok' => false, 'error' => 'invalid peer role'];
        }
        if (array_key_exists('preshared_key', $peer)
            && (! is_string($peer['preshared_key']) || ! nexovirt_wg_valid_key($peer['preshared_key']))) {
            return ['ok' => false, 'error' => 'invalid peer preshared key'];
        }
        // First entry: the device's address in THIS node's subnet. Further entries: its addresses on other
        // nodes (a multi-node device may send from any of them), private /32s outside this subnet.
        $ips = $peer['allowed_ips'] ?? null;
        if (! is_array($ips) || ! array_is_list($ips) || $ips === [] || count($ips) > WG_MAX_PEER_ADDRESSES) {
            return ['ok' => false, 'error' => 'invalid peer allowed_ips'];
        }
        $ip = (string) $ips[0];
        if (! nexovirt_wg_is_host32($ip) || ! nexovirt_nat_ip_in_cidr(explode('/', $ip)[0], $subnet)
            || explode('/', $ip)[0] === $hostIp) {
            return ['ok' => false, 'error' => 'invalid peer allowed_ips'];
        }
        foreach (array_slice($ips, 1) as $other) {
            if (! is_string($other) || ! nexovirt_wg_is_host32($other) || ! nexovirt_validate_nat_cidr($other)
                || nexovirt_nat_ip_in_cidr(explode('/', $other)[0], $subnet)) {
                return ['ok' => false, 'error' => 'invalid peer allowed_ips'];
            }
        }
        $allow = $peer['allow'] ?? [];
        if (! is_array($allow) || count($allow) > 256) {
            return ['ok' => false, 'error' => 'invalid peer allow'];
        }
        foreach ($allow as $a) {
            if (! is_string($a) || ! nexovirt_wg_valid_allow($a, $subnet)) {
                return ['ok' => false, 'error' => 'invalid peer allow'];
            }
        }
        if (isset($seenKeys[$peer['public_key']]) || array_intersect_key(array_flip($ips), $seenIps) !== []
            || count(array_unique($ips)) !== count($ips)) {
            return ['ok' => false, 'error' => 'duplicate peer'];
        }
        $seenKeys[$peer['public_key']] = true;
        $seenIps += array_flip($ips);
    }

    return ['ok' => true, 'error' => ''];
}

/** The wg-quick config. PURE; caller validated $p and $privateKey. */
function nexovirt_build_wg_conf(array $p, string $privateKey): string
{
    $out = "# Managed by nexovirt-agent. DO NOT EDIT.\n"
        . "[Interface]\n"
        . 'Address = ' . $p['address'] . "\n"
        . 'ListenPort = ' . (int) $p['port'] . "\n"
        . 'PrivateKey = ' . $privateKey . "\n";
    foreach ($p['peers'] ?? [] as $peer) {
        $out .= "\n[Peer]\n"
            . 'PublicKey = ' . $peer['public_key'] . "\n"
            . (isset($peer['preshared_key']) ? 'PresharedKey = ' . $peer['preshared_key'] . "\n" : '')
            . 'AllowedIPs = ' . implode(', ', $peer['allowed_ips']) . "\n";
    }

    return $out;
}

/** The /bin/sh firewall script for our NEXOVIRT-VPN* chains. PURE; caller validated $p. */
function nexovirt_build_wg_script(array $p): string
{
    $wg     = escapeshellarg(WG_IFACE);
    $port   = escapeshellarg((string) (int) $p['port']);
    $subnet = escapeshellarg((string) $p['subnet']);

    $l   = ['#!/bin/sh', 'set -e', '# Managed by nexovirt-agent. DO NOT EDIT. Dedicated NEXOVIRT-VPN* chains only.'];
    $l[] = 'sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true';
    $l[] = 'iptables -N NEXOVIRT-VPN 2>/dev/null || true';
    $l[] = 'iptables -N NEXOVIRT-VPN-IN 2>/dev/null || true';
    $l[] = 'iptables -t nat -N NEXOVIRT-VPN-NAT 2>/dev/null || true';
    $l[] = 'iptables -C FORWARD -j NEXOVIRT-VPN 2>/dev/null || iptables -I FORWARD -j NEXOVIRT-VPN';
    $l[] = 'iptables -C INPUT -j NEXOVIRT-VPN-IN 2>/dev/null || iptables -I INPUT -j NEXOVIRT-VPN-IN';
    $l[] = 'iptables -t nat -C POSTROUTING -j NEXOVIRT-VPN-NAT 2>/dev/null || iptables -t nat -I POSTROUTING -j NEXOVIRT-VPN-NAT';
    $l[] = 'iptables -F NEXOVIRT-VPN';
    $l[] = 'iptables -F NEXOVIRT-VPN-IN';
    $l[] = 'iptables -t nat -F NEXOVIRT-VPN-NAT';

    // INPUT: the listen port; admin peers may reach the host on ANY of its addresses (the VPN address,
    // its LAN/management IP and its bridge addresses: the master config routes the management IP);
    // customer peers never reach the host itself; everything else from wg dropped.
    $l[] = "iptables -A NEXOVIRT-VPN-IN -p udp --dport {$port} -j ACCEPT";
    $l[] = "iptables -A NEXOVIRT-VPN-IN -i {$wg} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT";
    foreach ($p['peers'] ?? [] as $peer) {
        if ($peer['role'] === 'admin') {
            foreach ($peer['allowed_ips'] as $a) {
                $l[] = "iptables -A NEXOVIRT-VPN-IN -i {$wg} -s " . escapeshellarg($a) . ' -j ACCEPT';
            }
        }
    }
    $l[] = "iptables -A NEXOVIRT-VPN-IN -i {$wg} -j DROP";

    // Addresses a device holds on OTHER nodes (validated: outside this subnet). Its client may use any of them
    // as the source, so they need a route back into the tunnel (wg syncconf adds none) and NAT below.
    $foreign = [];
    foreach ($p['peers'] ?? [] as $peer) {
        foreach (array_slice($peer['allowed_ips'], 1) as $a) {
            $foreign[$a] = true;
        }
    }
    $l[] = "for r in $(ip -4 route show dev {$wg} 2>/dev/null | awk '\$1 !~ /\\// {print \$1}'); do ip -4 route del \"\$r\" dev {$wg} 2>/dev/null || true; done";
    foreach (array_keys($foreign) as $a) {
        $l[] = 'ip -4 route replace ' . escapeshellarg($a) . " dev {$wg}";
    }

    // NAT: guests whose gateway is not this host still answer.
    foreach ($p['forward_nets'] ?? [] as $net) {
        $l[] = "iptables -t nat -A NEXOVIRT-VPN-NAT -s {$subnet} -d " . escapeshellarg($net) . ' -j MASQUERADE';
        foreach (array_keys($foreign) as $a) {
            $l[] = 'iptables -t nat -A NEXOVIRT-VPN-NAT -s ' . escapeshellarg($a) . ' -d ' . escapeshellarg($net) . ' -j MASQUERADE';
        }
    }

    // NAT for restricted peers' network allows (SDN project subnets): their guests answer even when the
    // subnet is not a forward net. Guest /32 allows keep the forward-net NAT above.
    foreach ($p['peers'] ?? [] as $peer) {
        if ($peer['role'] !== 'customer') {
            continue;
        }
        foreach ($peer['allow'] ?? [] as $dst) {
            if (str_ends_with($dst, '/32')) {
                continue;
            }
            foreach ($peer['allowed_ips'] as $a) {
                $l[] = 'iptables -t nat -A NEXOVIRT-VPN-NAT -s ' . escapeshellarg($a) . ' -d ' . escapeshellarg($dst) . ' -j MASQUERADE';
            }
        }
    }

    // FORWARD: return traffic, admin -> every forward net, customer -> its own guests only, default DROP.
    $l[] = "iptables -A NEXOVIRT-VPN -i {$wg} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT";
    $l[] = "iptables -A NEXOVIRT-VPN -o {$wg} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT";
    foreach ($p['peers'] ?? [] as $peer) {
        $targets = $peer['role'] === 'admin' ? ($p['forward_nets'] ?? []) : ($peer['allow'] ?? []);
        foreach ($peer['allowed_ips'] as $a) {
            $src = escapeshellarg($a);
            foreach ($targets as $dst) {
                $l[] = "iptables -A NEXOVIRT-VPN -i {$wg} -s {$src} -d " . escapeshellarg($dst) . ' -j ACCEPT';
            }
        }
    }
    $l[] = "iptables -A NEXOVIRT-VPN -i {$wg} -j DROP";

    return implode("\n", $l) . "\n";
}

/** Teardown commands (best-effort, idempotent). Keeps the host key. PURE. @return list<string> */
function nexovirt_wg_clear_cmds(string $dir): array
{
    $conf = escapeshellarg($dir . '/' . WG_IFACE . '.conf');

    return [
        "wg-quick down {$conf} 2>/dev/null || true",
        'systemctl disable --now nexovirt-wg.service 2>/dev/null || true',
        'iptables -D FORWARD -j NEXOVIRT-VPN 2>/dev/null || true',
        'iptables -D INPUT -j NEXOVIRT-VPN-IN 2>/dev/null || true',
        'iptables -t nat -D POSTROUTING -j NEXOVIRT-VPN-NAT 2>/dev/null || true',
        'iptables -F NEXOVIRT-VPN 2>/dev/null || true',
        'iptables -X NEXOVIRT-VPN 2>/dev/null || true',
        'iptables -F NEXOVIRT-VPN-IN 2>/dev/null || true',
        'iptables -X NEXOVIRT-VPN-IN 2>/dev/null || true',
        'iptables -t nat -F NEXOVIRT-VPN-NAT 2>/dev/null || true',
        'iptables -t nat -X NEXOVIRT-VPN-NAT 2>/dev/null || true',
    ];
}

/**
 * Parse `wg show wg-nexovirt dump`. Line 1 = private-key public-key listen-port fwmark (the private
 * key is dropped here and never returned); peer lines = public-key psk endpoint allowed-ips
 * latest-handshake rx tx keepalive. PURE.
 */
function nexovirt_wg_parse_dump(string $out): array
{
    $res   = ['public_key' => '', 'listening' => false, 'peers' => []];
    $lines = array_values(array_filter(explode("\n", trim($out)), static fn ($l) => trim($l) !== ''));
    if ($lines === []) {
        return $res;
    }
    $first = explode("\t", $lines[0]);
    if (count($first) >= 3 && nexovirt_wg_valid_key($first[1])) {
        $res['public_key'] = $first[1];
        $res['listening']  = true;
    }
    foreach (array_slice($lines, 1) as $line) {
        $f = explode("\t", $line);
        if (count($f) >= 7 && nexovirt_wg_valid_key($f[0])) {
            $res['peers'][] = ['public_key' => $f[0], 'latest_handshake' => (int) $f[4], 'rx' => (int) $f[5], 'tx' => (int) $f[6]];
        }
    }

    return $res;
}

/** Public key derived from the on-host private key ('' when absent/unreadable). */
function nexovirt_wg_host_pubkey(string $dir): string
{
    $key = $dir . '/private.key';
    if (! is_file($key)) {
        return '';
    }
    $pub = trim((string) shell_exec('wg pubkey < ' . escapeshellarg($key) . ' 2>/dev/null'));

    return nexovirt_wg_valid_key($pub) ? $pub : '';
}

/**
 * Things that could drop VPN traffic before our NEXOVIRT-VPN-IN jump. PURE.
 * $iptInput = `iptables -S INPUT`, $nftChains = `nft list chains`, $ufw = `ufw status`.
 *
 * @return list<string> short descriptions (empty = nothing found)
 */
function nexovirt_wg_blockers(string $iptInput, string $nftChains, string $ufw): array
{
    $out    = [];
    $before = [];
    $found  = false;
    foreach (explode("\n", $iptInput) as $line) {
        $line = trim($line);
        if (! str_starts_with($line, '-A INPUT ')) {
            continue;
        }
        if ($line === '-A INPUT -j NEXOVIRT-VPN-IN') {
            $found = true;
            break;
        }
        $before[] = $line;
    }
    if (! $found) {
        $out[] = 'The NEXOVIRT-VPN-IN jump is missing from the INPUT chain';
    } elseif ($before !== []) {
        $out[] = 'INPUT rules run before the VPN rules: ' . implode('; ', array_slice($before, 0, 3));
    }
    // nftables input hooks with a drop policy in tables other than iptables-nft's own "ip filter".
    $table = '';
    foreach (explode("\n", $nftChains) as $line) {
        if (preg_match('/^table (\S+ \S+) \{/', trim($line), $m) === 1) {
            $table = $m[1];
        } elseif ($table !== 'ip filter' && str_contains($line, 'hook input') && preg_match('/policy (drop|reject)/', $line) === 1) {
            $out[] = 'nftables table ' . $table . ' drops incoming traffic by default';
        }
    }
    if (preg_match('/^Status: active/m', $ufw) === 1) {
        $out[] = 'ufw is active';
    }

    return $out;
}

/** The "src" address of `ip -4 route get <ip>` ('' when none). PURE. */
function nexovirt_wg_route_src(string $out): string
{
    return preg_match('/\bsrc (\d{1,3}(?:\.\d{1,3}){3})\b/', $out, $m) === 1 ? $m[1] : '';
}

/** Cheap read-only readiness facts for the panel's VPN checklist. */
function nexovirt_wg_diag(string $dump): array
{
    $first = explode("\t", trim(explode("\n", trim($dump))[0] ?? ''));
    $link  = (string) shell_exec('ip link show ' . escapeshellarg(WG_IFACE) . ' 2>/dev/null');

    return [
        'wg_tools'    => trim((string) shell_exec('command -v wg 2>/dev/null')) !== '',
        'iface_up'    => preg_match('/<[^>]*\bUP\b[^>]*>/', $link) === 1,
        'listen_port' => isset($first[2]) && ctype_digit($first[2]) ? (int) $first[2] : 0,
        'ip_forward'  => trim((string) @file_get_contents('/proc/sys/net/ipv4/ip_forward')) === '1',
        'blockers'    => nexovirt_wg_blockers((string) shell_exec('iptables -S INPUT 2>/dev/null'),
            (string) shell_exec('command -v nft >/dev/null 2>&1 && nft list chains 2>/dev/null'),
            (string) shell_exec('command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null')),
        'local_ipv4'  => nexovirt_wg_route_src((string) shell_exec('ip -4 route get 1.1.1.1 2>/dev/null')),
    ];
}

/** Live status from `wg show wg-nexovirt dump` plus readiness facts. DRYRUN: the empty status. Never returns the private key. */
function nexovirt_read_wireguard(): array
{
    if (getenv('NEXOVIRT_AGENT_DRYRUN') === '1') {
        return ['public_key' => '', 'listening' => false, 'peers' => []];
    }
    $dump   = (string) shell_exec('wg show ' . escapeshellarg(WG_IFACE) . ' dump 2>/dev/null');
    $status = nexovirt_wg_parse_dump($dump);
    if ($status['public_key'] === '') {
        $status['public_key'] = nexovirt_wg_host_pubkey(nexovirt_wg_dir());
    }
    $status['diag'] = nexovirt_wg_diag($dump);

    return $status;
}

/** Remove the interface, unit, chains and generated files. Keeps private.key. */
function nexovirt_wg_disable(string $dir): void
{
    foreach (nexovirt_wg_clear_cmds($dir) as $cmd) {
        exec($cmd);
    }
    foreach ([$dir . '/' . WG_IFACE . '.conf', $dir . '/' . WG_IFACE . '.stripped', $dir . '/nexovirt-vpn.sh', WG_UNIT_PATH, WG_SYSCTL_PATH] as $f) {
        @unlink($f);
    }
    exec('systemctl daemon-reload 2>&1');
}

/** Run a command, returning [exitCode, cappedOutput]. */
function nexovirt_wg_exec(string $cmd): array
{
    $out  = [];
    $code = 0;
    exec($cmd . ' 2>&1', $out, $code);

    return [$code, nexovirt_cap_output(implode("\n", $out), 2000)];
}

/**
 * Validate + apply (or disable) the WireGuard config. Caller-independent: validates again.
 * DRYRUN: builds conf (with a placeholder key) + script and returns them, touching nothing.
 *
 * @return array{ok:bool,error:string,status:array}
 */
function nexovirt_apply_wireguard(array $p): array
{
    $empty = ['public_key' => '', 'listening' => false, 'peers' => []];
    $valid = nexovirt_validate_wg_payload($p);
    if (! $valid['ok']) {
        return ['ok' => false, 'error' => $valid['error'], 'status' => $empty];
    }
    $dryRun = getenv('NEXOVIRT_AGENT_DRYRUN') === '1';
    $dir    = nexovirt_wg_dir();

    if (empty($p['enabled'])) {
        if (! $dryRun) {
            nexovirt_wg_disable($dir);
        }
        return ['ok' => true, 'error' => '', 'status' => $dryRun ? $empty : ['public_key' => nexovirt_wg_host_pubkey($dir), 'listening' => false, 'peers' => []]];
    }

    $script = nexovirt_build_wg_script($p);
    if ($dryRun) {
        return ['ok' => true, 'error' => '', 'status' => $empty,
            'conf' => nexovirt_build_wg_conf($p, str_repeat('A', 43) . '='), 'script' => $script];
    }

    if (trim((string) shell_exec('command -v wg 2>/dev/null')) === '') {
        [$code, $out] = nexovirt_wg_exec('DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools');
        if ($code !== 0) {
            return ['ok' => false, 'error' => 'could not install wireguard-tools: ' . $out, 'status' => $empty];
        }
    }
    @mkdir($dir, 0700, true);
    @chmod($dir, 0700);
    $keyPath = $dir . '/private.key';
    if (! is_file($keyPath)) {
        nexovirt_wg_exec('umask 077 && wg genkey > ' . escapeshellarg($keyPath));
    }
    @chmod($keyPath, 0600);
    $private = trim((string) @file_get_contents($keyPath));
    if (! nexovirt_wg_valid_key($private)) {
        return ['ok' => false, 'error' => 'host key could not be created', 'status' => $empty];
    }

    $confPath   = $dir . '/' . WG_IFACE . '.conf';
    $scriptPath = $dir . '/nexovirt-vpn.sh';
    $old        = umask(0077);
    $wrote      = @file_put_contents($confPath, nexovirt_build_wg_conf($p, $private)) !== false
        && @file_put_contents($scriptPath, $script) !== false;
    umask($old);
    if (! $wrote) {
        return ['ok' => false, 'error' => 'cannot write wireguard config', 'status' => $empty];
    }
    @chmod($confPath, 0600);
    @chmod($scriptPath, 0700);

    $confA = escapeshellarg($confPath);
    @file_put_contents(WG_UNIT_PATH, "[Unit]\nDescription=NexoVirt WireGuard VPN\nAfter=network-online.target\nWants=network-online.target\n\n"
        . "[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/wg-quick up {$confPath}\n"
        . "ExecStartPost={$scriptPath}\nExecStop=/usr/bin/wg-quick down {$confPath}\n\n[Install]\nWantedBy=multi-user.target\n");
    @file_put_contents(WG_SYSCTL_PATH, "# Managed by nexovirt-agent - required for NexoVirt VPN (nexovirt-wg.service).\nnet.ipv4.ip_forward = 1\n");
    exec('systemctl daemon-reload 2>&1');
    exec('systemctl enable nexovirt-wg.service 2>&1');

    // `wg syncconf` never changes the interface Address: a re-addressed host bounces the interface instead.
    [$exists, $addrs] = nexovirt_wg_exec('ip -4 -o addr show dev ' . escapeshellarg(WG_IFACE));
    if ($exists === 0 && ! str_contains($addrs, ' ' . $p['address'] . ' ')) {
        nexovirt_wg_exec("wg-quick down {$confA}");
        $exists = 1;
    }
    if ($exists === 0) {
        $stripped = escapeshellarg($dir . '/' . WG_IFACE . '.stripped');
        [$code, $out] = nexovirt_wg_exec("umask 077 && wg-quick strip {$confA} > {$stripped} && wg syncconf " . escapeshellarg(WG_IFACE) . " {$stripped}");
    } else {
        [$code, $out] = nexovirt_wg_exec("wg-quick up {$confA}");
    }
    if ($code !== 0) {
        return ['ok' => false, 'error' => 'wireguard interface failed: ' . $out, 'status' => $empty];
    }
    [$code, $out] = nexovirt_wg_exec(escapeshellarg($scriptPath));
    if ($code !== 0) {
        return ['ok' => false, 'error' => 'vpn firewall rules failed: ' . $out, 'status' => $empty];
    }

    return ['ok' => true, 'error' => '', 'status' => nexovirt_read_wireguard()];
}

// ---------------------------------------------------------------------------
// Firewall inspection: READ-ONLY: detect + dump common firewall stacks.
//
// SAFETY CONTRACT (do not weaken):
//  - This function ONLY runs read/list/status commands.
//  - It NEVER runs any command that mutates firewall state (-A, -D, -F, -I,
//    add, delete, enable, flush, apply, etc.).
//  - Every tool is checked with `command -v` first; a missing tool is a
//    no-op (installed:false, no error).
// ---------------------------------------------------------------------------

/**
 * Cap a string to $maxBytes without splitting a multi-byte UTF-8 character (a split char would
 * make the result invalid UTF-8). If truncated, appends a truncation marker. Pure.
 */
function nexovirt_cap_output(string $s, int $maxBytes): string
{
    if (strlen($s) <= $maxBytes) {
        return $s;
    }
    $marker = "\n...(truncated)";
    if (function_exists('mb_strcut')) {
        return mb_strcut($s, 0, $maxBytes, 'UTF-8') . $marker;
    }
    $cut = substr($s, 0, $maxBytes);
    // Drop a trailing incomplete UTF-8 sequence (at most 3 bytes: lead byte + missing continuations).
    for ($i = 1; $i <= 3 && $i <= strlen($cut); $i++) {
        $b = ord($cut[strlen($cut) - $i]);
        if (($b & 0xC0) === 0x80) {
            continue; // continuation byte, keep looking for the lead
        }
        if ($b >= 0xC0) {
            $need = $b >= 0xF0 ? 4 : ($b >= 0xE0 ? 3 : 2);
            if ($need > $i) {
                $cut = substr($cut, 0, strlen($cut) - $i);
            }
        }
        break;
    }
    return $cut . $marker;
}

/**
 * json_encode that never fails on host output: invalid UTF-8 (binary log lines, odd locales) is
 * replaced with U+FFFD instead of making json_encode return false (which, under strict_types,
 * would TypeError the string-typed result and crash the agent). Always returns a JSON string.
 *
 * @param mixed $data
 */
function nexovirt_json($data): string
{
    $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
    return is_string($json) ? $json : '{"error":"result could not be encoded"}';
}

/**
 * Check whether a binary is available on PATH via `command -v`.
 * Returns true if the exit code is 0.
 */
function nexovirt_bin_installed(string $bin): bool
{
    $safeBin = escapeshellarg($bin);
    $out  = [];
    $code = 0;
    exec("command -v {$safeBin} >/dev/null 2>&1", $out, $code);
    return $code === 0;
}

/**
 * Run a shell command, capture output (stdout+stderr merged via `2>&1`).
 * Returns the combined output string (already has 2>&1 merged if the
 * caller appended it, or we append it here when running via exec).
 *
 * Bounded: these are read-only status/list commands that finish in <1 s on a healthy host, but one
 * stuck on a hung NFS/CIFS mount sits in uninterruptible sleep (even SIGKILL waits) and a plain exec()
 * would freeze the whole agent loop (heartbeat stops, panel shows the agent as stale). So the output
 * is read until a deadline; then the process is killed and abandoned (no proc_close, which would
 * wait for it) and the output so far is returned with a "timed out" note.
 */
const SCAN_CMD_TIMEOUT_SEC = 30;

function nexovirt_run_cmd(string $cmd, int $timeoutSec = SCAN_CMD_TIMEOUT_SEC): string
{
    if (! function_exists('proc_open')) {
        $out = [];
        exec($cmd . ' 2>&1', $out);
        return implode("\n", $out);
    }
    $proc = proc_open($cmd . ' 2>&1', [1 => ['pipe', 'w']], $pipes);
    if (! is_resource($proc)) {
        return '';
    }
    stream_set_blocking($pipes[1], false);
    $out      = '';
    $deadline = microtime(true) + $timeoutSec;
    while (true) {
        $read = [$pipes[1]];
        $w = $e = null;
        if (@stream_select($read, $w, $e, 0, 200000) > 0) {
            $chunk = fread($pipes[1], 65536);
            if ($chunk === '' || $chunk === false) {
                if (feof($pipes[1])) {
                    break; // finished: output complete
                }
            } else {
                $out .= $chunk;
            }
        }
        if (microtime(true) >= $deadline) {
            proc_terminate($proc, 9);
            fclose($pipes[1]);
            return rtrim($out, "\n") . "\n[nexovirt-agent] command timed out after {$timeoutSec} s";
        }
    }
    fclose($pipes[1]);
    proc_close($proc);

    return rtrim($out, "\n");
}

/**
 * Read-only firewall inspector. Detects installed/active status and dumps
 * the ruleset for each of the five common Linux/Proxmox firewall stacks.
 *
 * Returns ['tools' => [ ['name'=>string, 'installed'=>bool, 'active'=>bool, 'output'=>string], … ]].
 *
 * DRYRUN seam: when NEXOVIRT_AGENT_DRYRUN=1, returns a deterministic stub
 * (all 5 tools, output='(dryrun)') WITHOUT running any real command.
 *
 * Active heuristics (best-effort, documented per tool):
 *  - iptables:    installed + output length > 80 chars OR contains a non-trivial
 *                 rule marker (chain policy line or a user-defined rule `-A`/`-N`).
 *  - nftables:    installed + output contains a 'table' keyword.
 *  - ufw:         output contains "Status: active".
 *  - firewalld:   `firewall-cmd --state` output is exactly "running".
 *  - pve-firewall: output contains "running" (case-insensitive).
 */
/** Maximum bytes captured from each tool's output (64 KB). */
const FIREWALL_OUTPUT_CAP = 65536;

/**
 * Best-effort "is this firewall active?" from its read-command output. Pure.
 *
 * @param string $name        Tool name: 'iptables'|'nftables'|'ufw'|'firewalld'|'pve-firewall'.
 * @param string $output      Combined output from the tool's read command(s).
 * @param string $stateOutput For firewalld only: output of `firewall-cmd --state`.
 */
function nexovirt_fw_active(string $name, string $output, string $stateOutput = ''): bool
{
    switch ($name) {
        case 'iptables':     return preg_match('/^-[AN] /m', $output) === 1;
        case 'nftables':     return str_contains($output, 'table ');
        case 'ufw':          return str_contains($output, 'Status: active');
        case 'firewalld':    return trim($stateOutput) === 'running';
        case 'pve-firewall': return stripos($output, 'running') !== false; // FIX: !== false, not (bool)
        default:             return false;
    }
}

function nexovirt_read_firewall(): array
{
    if (getenv('NEXOVIRT_AGENT_DRYRUN') === '1') {
        $stub = [];
        foreach (['iptables', 'nftables', 'ufw', 'firewalld', 'pve-firewall'] as $name) {
            $stub[] = ['name' => $name, 'installed' => true, 'active' => true, 'output' => '(dryrun)'];
        }
        return ['tools' => $stub];
    }

    $tools = [];

    // --- iptables -----------------------------------------------------------
    $ipInstalled = nexovirt_bin_installed('iptables');
    if ($ipInstalled) {
        // Prefer iptables-save (most complete); fall back to -S + nat -S.
        if (nexovirt_bin_installed('iptables-save')) {
            $raw = nexovirt_run_cmd('iptables-save');
        } else {
            $raw = nexovirt_run_cmd('iptables -S') . "\n" . nexovirt_run_cmd('iptables -t nat -S');
        }
        $out    = nexovirt_cap_output($raw, FIREWALL_OUTPUT_CAP);
        // Active: has any rule or non-default chain entry. Policy lines like
        // `:INPUT ACCEPT` always appear even on an empty ruleset, so we look
        // for at least one `-A` (appended rule) or `-N` (user chain).
        $active = nexovirt_fw_active('iptables', $raw);
    } else {
        $out    = '';
        $active = false;
    }
    $tools[] = ['name' => 'iptables', 'installed' => $ipInstalled, 'active' => $active, 'output' => $out];

    // --- nftables -----------------------------------------------------------
    $nftInstalled = nexovirt_bin_installed('nft');
    if ($nftInstalled) {
        $raw    = nexovirt_run_cmd('nft list ruleset');
        $out    = nexovirt_cap_output($raw, FIREWALL_OUTPUT_CAP);
        // Active: ruleset contains at least one 'table' block.
        $active = nexovirt_fw_active('nftables', $raw);
    } else {
        $out    = '';
        $active = false;
    }
    $tools[] = ['name' => 'nftables', 'installed' => $nftInstalled, 'active' => $active, 'output' => $out];

    // --- ufw ----------------------------------------------------------------
    $ufwInstalled = nexovirt_bin_installed('ufw');
    if ($ufwInstalled) {
        $raw    = nexovirt_run_cmd('ufw status verbose');
        $out    = nexovirt_cap_output($raw, FIREWALL_OUTPUT_CAP);
        $active = nexovirt_fw_active('ufw', $raw);
    } else {
        $out    = '';
        $active = false;
    }
    $tools[] = ['name' => 'ufw', 'installed' => $ufwInstalled, 'active' => $active, 'output' => $out];

    // --- firewalld ----------------------------------------------------------
    $fwdInstalled = nexovirt_bin_installed('firewall-cmd');
    if ($fwdInstalled) {
        $stateOut = nexovirt_run_cmd('firewall-cmd --state');
        $listOut  = nexovirt_run_cmd('firewall-cmd --list-all');
        $raw      = $stateOut . "\n" . $listOut;
        $out      = nexovirt_cap_output($raw, FIREWALL_OUTPUT_CAP);
        // Active: --state returns "running" on the first line.
        $active   = nexovirt_fw_active('firewalld', $raw, $stateOut);
    } else {
        $out    = '';
        $active = false;
    }
    $tools[] = ['name' => 'firewalld', 'installed' => $fwdInstalled, 'active' => $active, 'output' => $out];

    // --- pve-firewall -------------------------------------------------------
    $pveInstalled = nexovirt_bin_installed('pve-firewall');
    if ($pveInstalled) {
        $raw    = nexovirt_run_cmd('pve-firewall status');
        $out    = nexovirt_cap_output($raw, FIREWALL_OUTPUT_CAP);
        // Active: status output mentions "running" anywhere in the output.
        $active = nexovirt_fw_active('pve-firewall', $raw);
    } else {
        $out    = '';
        $active = false;
    }
    $tools[] = ['name' => 'pve-firewall', 'installed' => $pveInstalled, 'active' => $active, 'output' => $out];

    return ['tools' => $tools];
}

// ---------------------------------------------------------------------------
// Host scan: READ-ONLY system + PVE facts.
//
// SAFETY CONTRACT (do not weaken, same discipline as read_firewall):
//  - read_system / read_pve / read_logs take NO PARAMETERS. Every command is a
//    FIXED string (no interpolation of any panel-supplied value) → zero injection
//    surface.
//  - They ONLY run read/status/list commands (cat /proc, os-release, uname,
//    apt -s, smartctl -H, systemctl is-active, pveversion, pvecm/ha/ceph status,
//    pvesm status, journalctl -p err / tail of syslog). They NEVER mutate host state.
//  - Every external binary is `command -v`-guarded; a missing tool degrades to a
//    skipped/empty section, never an error.
//  - All output is capped (SCAN_OUTPUT_CAP) and total JSON kept small.
// ---------------------------------------------------------------------------

/** Maximum bytes captured from each scan sub-command's output (32 KB). */
const SCAN_OUTPUT_CAP = 32768;

/** Read + cap a file (best-effort). Returns '' when absent/unreadable. */
function nexovirt_read_file_capped(string $path): string
{
    if (! is_readable($path)) {
        return '';
    }
    $raw = @file_get_contents($path);
    return $raw === false ? '' : nexovirt_cap_output($raw, SCAN_OUTPUT_CAP);
}

/**
 * Run a read-only command, capping its combined output. The command string is a
 * FIXED literal at every call site (no panel input): escaping is therefore moot
 * but the cap still bounds output.
 */
function nexovirt_scan_cmd(string $cmd): string
{
    return nexovirt_cap_output(nexovirt_run_cmd($cmd), SCAN_OUTPUT_CAP);
}

/**
 * Read host SYSTEM facts. Read-only, no parameters. Returns a JSON-able object with
 * each section as a raw string (the panel-side parser normalizes them). Every section
 * is best-effort: an absent tool/file yields an empty/absent value, never a failure.
 *
 * DRYRUN seam: when NEXOVIRT_AGENT_DRYRUN=1 returns a deterministic stub WITHOUT
 * running any real command (the unit-test path).
 *
 * @return array<string,mixed>
 */
function nexovirt_read_system(): array
{
    if (getenv('NEXOVIRT_AGENT_DRYRUN') === '1') {
        return [
            'os_release' => 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"' . "\nVERSION_ID=\"12\"",
            'kernel'     => '6.8.12-1-pve',
            'cpuinfo'    => "model name\t: DryRun CPU\nprocessor\t: 0\nprocessor\t: 1",
            'nproc'      => '2',
            'meminfo'    => "MemTotal:       16384000 kB\nMemAvailable:    8192000 kB",
            'updates'    => '',
            'smart'      => [],
            'services'   => ['pve-cluster' => 'active', 'pvedaemon' => 'active', 'pveproxy' => 'active', 'pvestatd' => 'active'],
            'uptime'     => '123456.78 100000.00',
            'loadavg'    => '0.10 0.20 0.30 1/200 12345',
            'ip_forward' => ['live' => 1, 'persisted' => true],
        ];
    }

    // --- updates available --------------------------------------------------
    // Prefer `apt-get -s upgrade` (simulation, no changes); fall back to apt list.
    $updates = '';
    if (nexovirt_bin_installed('apt-get')) {
        $updates = nexovirt_scan_cmd('apt-get -s upgrade 2>/dev/null');
    } elseif (nexovirt_bin_installed('apt')) {
        $updates = nexovirt_scan_cmd('apt list --upgradable 2>/dev/null');
    }

    // --- SMART health per physical disk (best-effort; absent → skipped) -----
    $smart = [];
    if (nexovirt_bin_installed('smartctl')) {
        // Enumerate physical block devices (sd*, nvme*, vd*) without partitions.
        $disks = [];
        foreach (glob('/dev/sd[a-z]') ?: [] as $d) {
            $disks[] = $d;
        }
        foreach (glob('/dev/nvme[0-9]n[0-9]') ?: [] as $d) {
            $disks[] = $d;
        }
        foreach (array_slice($disks, 0, 32) as $dev) {
            // -H = health summary only. Read-only. Fixed flag; $dev comes from a
            // local glob (never the panel) but is escapeshellarg'd defensively.
            $out      = nexovirt_scan_cmd('smartctl -H ' . escapeshellarg($dev) . ' 2>&1');
            $smart[]  = ['dev' => $dev, 'output' => $out];
        }
    }

    // --- key PVE service states --------------------------------------------
    $services = [];
    if (nexovirt_bin_installed('systemctl')) {
        foreach (['pve-cluster', 'pvedaemon', 'pveproxy', 'pvestatd'] as $svc) {
            $services[$svc] = trim(nexovirt_run_cmd('systemctl is-active ' . escapeshellarg($svc) . ' 2>/dev/null'));
        }
    }

    return [
        'os_release' => nexovirt_read_file_capped('/etc/os-release'),
        'kernel'     => trim(nexovirt_scan_cmd('uname -r 2>/dev/null')),
        'cpuinfo'    => nexovirt_read_file_capped('/proc/cpuinfo'),
        'nproc'      => trim(nexovirt_scan_cmd('nproc 2>/dev/null')),
        'meminfo'    => nexovirt_read_file_capped('/proc/meminfo'),
        'updates'    => $updates,
        'smart'      => $smart,
        'services'   => $services,
        'uptime'     => trim(nexovirt_read_file_capped('/proc/uptime')),
        'loadavg'    => trim(nexovirt_read_file_capped('/proc/loadavg')),
        'ip_forward' => nexovirt_ip_forward_state(),
    ];
}

/**
 * Read PVE facts. Read-only, no parameters. Returns raw-per-tool output strings; the
 * panel-side parser normalizes them. Every sub-command is best-effort: a standalone
 * (non-cluster) host or an absent ceph simply yields empty output, never a failure.
 *
 * DRYRUN seam: when NEXOVIRT_AGENT_DRYRUN=1 returns a deterministic stub.
 *
 * @return array<string,mixed>
 */
function nexovirt_read_pve(): array
{
    if (getenv('NEXOVIRT_AGENT_DRYRUN') === '1') {
        return [
            'version'      => "pve-manager/8.2.2/abc (running kernel: 6.8.12-1-pve)",
            'cluster'      => '',
            'ha'           => '',
            'ceph'         => '',
            'storages'     => "Name             Type     Status        Total          Used\nlocal            dir      active     100000000     20000000",
        ];
    }

    $version = nexovirt_bin_installed('pveversion') ? nexovirt_scan_cmd('pveversion -v 2>&1') : '';
    // pvecm: standalone hosts have no cluster → the command errors; that's fine, we
    // keep the (empty/error) output and the parser treats it as "not a cluster".
    $cluster  = nexovirt_bin_installed('pvecm') ? nexovirt_scan_cmd('pvecm status 2>&1') : '';
    $ha       = nexovirt_bin_installed('ha-manager') ? nexovirt_scan_cmd('ha-manager status 2>&1') : '';
    $ceph     = nexovirt_bin_installed('ceph') ? nexovirt_scan_cmd('ceph -s 2>&1') : '';
    $storages = nexovirt_bin_installed('pvesm') ? nexovirt_scan_cmd('pvesm status 2>&1') : '';

    return [
        'version'  => $version,
        'cluster'  => $cluster,
        'ha'       => $ha,
        'ceph'     => $ceph,
        'storages' => $storages,
    ];
}

/**
 * Read recent IMPORTANT system log entries. Read-only, no parameters. Prefers journalctl
 * (priority "error" and above: the actionable noise), falling back to the tail of the
 * classic syslog/messages files when journalctl is unavailable. The capped raw text is
 * returned as `entries`; the panel-side LogScanParser normalizes it into rows. Best-effort:
 * an absent tool / unreadable file yields an empty stream, never a failure.
 *
 * DRYRUN seam: when NEXOVIRT_AGENT_DRYRUN=1 returns a deterministic stub.
 *
 * @return array{source:string, entries:string}
 */
function nexovirt_read_logs(): array
{
    if (getenv('NEXOVIRT_AGENT_DRYRUN') === '1') {
        return [
            'source'  => 'journalctl',
            'entries' => "2026-06-20T13:21:01+0000 pve pvedaemon[1234]: authentication failure; rhost=10.0.0.9\n"
                . "2026-06-20T13:22:05+0000 pve kernel: EXT4-fs warning (device sda1): recovery needed\n"
                . "2026-06-20T13:23:00+0000 pve systemd[1]: pvestatd.service: Failed with result 'exit-code'.",
        ];
    }

    if (nexovirt_bin_installed('journalctl')) {
        // -p err = priority "error" and above; --no-pager; ISO timestamps; bounded line count.
        // FIXED command string, no panel input → no injection surface. 2>/dev/null swallows the
        // "no entries" notice on a clean host.
        return [
            'source'  => 'journalctl',
            'entries' => nexovirt_scan_cmd('journalctl -p err -n 300 --no-pager -o short-iso 2>/dev/null'),
        ];
    }

    foreach (['/var/log/syslog' => 'syslog', '/var/log/messages' => 'messages'] as $path => $source) {
        if (is_readable($path)) {
            return ['source' => $source, 'entries' => nexovirt_scan_cmd('tail -n 300 ' . escapeshellarg($path) . ' 2>/dev/null')];
        }
    }

    return ['source' => '', 'entries' => ''];
}

/**
 * Read recent Proxmox VE daemon log entries. Read-only, no parameters. Pulls the journal for the
 * core PVE units (cluster/daemon/proxy/statd/firewall) at notice-and-above; the panel-side
 * LogScanParser normalizes it. Best-effort: no journalctl → empty stream, never a failure.
 *
 * DRYRUN seam: when NEXOVIRT_AGENT_DRYRUN=1 returns a deterministic stub.
 *
 * @return array{source:string, entries:string}
 */
function nexovirt_read_pve_logs(): array
{
    if (getenv('NEXOVIRT_AGENT_DRYRUN') === '1') {
        return [
            'source'  => 'journalctl-pve',
            'entries' => "2026-06-20T13:30:00+0000 pve pvedaemon[1234]: <root@pam> starting task UPID:pve:0001\n"
                . "2026-06-20T13:30:05+0000 pve pvestatd[1100]: status update time (8.1 seconds)\n"
                . "2026-06-20T13:31:00+0000 pve pveproxy[2200]: worker 2201 started",
        ];
    }

    if (! nexovirt_bin_installed('journalctl')) {
        return ['source' => '', 'entries' => ''];
    }

    // FIXED unit list, no panel input → no injection surface. -p notice = notice and above.
    return [
        'source'  => 'journalctl-pve',
        'entries' => nexovirt_scan_cmd(
            'journalctl -u pve-cluster -u pvedaemon -u pveproxy -u pvestatd -u pve-firewall '
            . '-p notice -n 300 --no-pager -o short-iso 2>/dev/null'
        ),
    ];
}

/**
 * Probe whether the SDN DHCP backend (dnsmasq) can be enabled SAFELY on this node. Read-only, takes
 * NO parameters -> no injection surface. Never changes anything. Returns a verdict so the panel can
 * decide whether to enable DHCP or fall back to static IPs, without ever disturbing an existing setup.
 *
 * verdict: 'ready' (installed, no conflict) | 'installable' (absent, apt available, no conflict)
 *          | 'conflict' (a global dnsmasq is already running, or no way to install).
 *
 * @return array{ok:bool,result:string} result is JSON
 */
function nexovirt_probe_sdn_dhcp(): array
{
    $installed    = trim((string) shell_exec('command -v dnsmasq 2>/dev/null')) !== '';
    // A GLOBAL dnsmasq.service (the customer's own), NOT PVE's per-zone dnsmasq@<zone> template units.
    $globalActive = trim((string) shell_exec('systemctl is-active dnsmasq 2>/dev/null')) === 'active';
    $hasApt       = trim((string) shell_exec('command -v apt-get 2>/dev/null')) !== '';
    // Anything already answering DHCP (udp/67): surfaced for the report only.
    $dhcpBind     = trim((string) shell_exec("ss -lunp 2>/dev/null | awk '\$5 ~ /:67\$/' | head -3"));

    $conflict = '';
    $verdict  = 'installable';
    if ($globalActive) {
        $verdict  = 'conflict';
        $conflict = 'a global dnsmasq service is already running on this node';
    } elseif ($installed) {
        $verdict = 'ready';
    } elseif (! $hasApt) {
        $verdict  = 'conflict';
        $conflict = 'dnsmasq is not installed and no apt-get is available';
    }

    return ['ok' => true, 'result' => nexovirt_json([
        'verdict'       => $verdict,
        'installed'     => $installed,
        'global_active' => $globalActive,
        'has_apt'       => $hasApt,
        'dhcp_bind'     => $dhcpBind,
        'conflict'      => $conflict,
    ])];
}

/**
 * Ensure the dnsmasq DHCP backend for PVE SDN, SAFELY. Installs dnsmasq ONLY if absent, and disables
 * the GLOBAL dnsmasq unit ONLY when it was not already active before we touched it (PVE needs the
 * global unit off so its per-zone dnsmasq@<zone> instances can bind). NEVER stops a pre-existing
 * service, NEVER edits config, NEVER removes packages. Fixed commands, no parameters -> no injection.
 * Idempotent + re-runnable.
 *
 * @return array{ok:bool,result:string}
 */
function nexovirt_ensure_sdn_dhcp(): array
{
    // Refuse to disturb an existing/customer dnsmasq. The panel falls back to static IPs.
    if (trim((string) shell_exec('systemctl is-active dnsmasq 2>/dev/null')) === 'active') {
        return ['ok' => false, 'result' => 'conflict: a dnsmasq service is already running; not touching it'];
    }

    $installed = trim((string) shell_exec('command -v dnsmasq 2>/dev/null')) !== '';
    if (! $installed) {
        if (trim((string) shell_exec('command -v apt-get 2>/dev/null')) === '') {
            return ['ok' => false, 'result' => 'dnsmasq not installed and no apt-get available'];
        }
        @exec('DEBIAN_FRONTEND=noninteractive apt-get update -y 2>&1');
        @exec('DEBIAN_FRONTEND=noninteractive apt-get install -y dnsmasq 2>&1', $out, $code);
        $installed = trim((string) shell_exec('command -v dnsmasq 2>/dev/null')) !== '';
        if (! $installed) {
            return ['ok' => false, 'result' => 'dnsmasq install failed: ' . implode(' ', array_slice($out ?? [], -3))];
        }
    }

    // PVE runs dnsmasq per SDN zone (dnsmasq@<zone>); the packaged global unit must not bind. It was
    // inactive above (we just installed it or it was already off), so disabling it is safe here.
    @exec('systemctl disable --now dnsmasq 2>&1');

    return ['ok' => true, 'result' => 'dnsmasq ready for SDN (global unit disabled; PVE manages per-zone)'];
}

/** Path of the persisted SDN-egress sysctl file. */
const SDN_FORWARD_SYSCTL_PATH = '/etc/sysctl.d/99-nexovirt-forward.conf';

/**
 * Enable + persist IPv4 forwarding so a SNAT SDN subnet (created with snat=1) can route its guests
 * out to the WAN. Additive + idempotent: writes a dedicated sysctl.d file and applies it live; it
 * never touches the customer's own sysctl config and only turns forwarding ON (never off).
 *
 * @return array{ok:bool,result:string}
 */
function nexovirt_ensure_sdn_egress(): array
{
    return nexovirt_set_ip_forward(true);
}

/**
 * Current IPv4-forwarding state of the host: the live kernel value and whether our dedicated sysctl.d
 * file persists it across reboot. Read-only. @return array{live:int,persisted:bool}
 */
function nexovirt_ip_forward_state(): array
{
    $live = trim((string) shell_exec('cat /proc/sys/net/ipv4/ip_forward 2>/dev/null'));

    return [
        'live'      => $live === '1' ? 1 : 0,
        // Either of our files persists it: the SDN-egress one or the NAT one (both set ip_forward=1).
        'persisted' => is_file(SDN_FORWARD_SYSCTL_PATH) || is_file(NAT_SYSCTL_PATH),
    ];
}

/** True when NexoVirt NAT is installed on this host (its unit or sysctl file is present). */
function nexovirt_nat_active(): bool
{
    return is_file(NAT_UNIT_PATH) || is_file(NAT_SYSCTL_PATH);
}

/**
 * Enable or disable IPv4 forwarding on the host, live + persisted. Additive + reversible: it only
 * writes/removes its OWN dedicated sysctl.d file (never touches the operator's other sysctl config)
 * and applies the value live. @return array{ok:bool,result:string}
 */
function nexovirt_set_ip_forward(bool $enabled): array
{
    // NexoVirt NAT needs forwarding: turning it off would silently cut every NATed guest off the
    // network (and nexovirt-nat.service would turn it back on at the next boot anyway).
    if (! $enabled && nexovirt_nat_active()) {
        return ['ok' => false, 'result' => 'NexoVirt NAT is active on this host and requires IPv4 forwarding; clear the NAT configuration first'];
    }
    if (getenv('NEXOVIRT_AGENT_DRYRUN') === '1') {
        return ['ok' => true, 'result' => 'ip_forward ' . ($enabled ? 'enabled' : 'disabled') . ' (dryrun)'];
    }
    if ($enabled) {
        $body = "# Managed by nexovirt-agent - IPv4 forwarding (needed for SNAT SDN subnets + NAT).\n"
            . "net.ipv4.ip_forward = 1\n";
        @file_put_contents(SDN_FORWARD_SYSCTL_PATH, $body);
        @exec('sysctl -w net.ipv4.ip_forward=1 2>&1', $out, $code);
    } else {
        // Remove our persisted override + turn forwarding off live. We deliberately do NOT write a
        // "=0" file, so any OTHER sysctl.d entry the operator set can win on the next boot.
        @unlink(SDN_FORWARD_SYSCTL_PATH);
        @exec('sysctl -w net.ipv4.ip_forward=0 2>&1', $out, $code);
    }

    $live = trim((string) shell_exec('cat /proc/sys/net/ipv4/ip_forward 2>/dev/null'));
    $want = $enabled ? '1' : '0';

    return $live === $want
        ? ['ok' => true, 'result' => 'ip_forward ' . ($enabled ? 'enabled' : 'disabled') . ' + persisted']
        : ['ok' => false, 'result' => 'could not set ip_forward: ' . implode(' ', array_slice($out ?? [], -2))];
}

// ---------------------------------------------------------------------------
// Node package updates (apt): apt_refresh, apt_simulate, apt_upgrade_start, apt_upgrade_status.
// Fixed commands only; every package name is validated (Debian name rules) and escapeshellarg'd.
// The upgrade itself runs DETACHED under systemd-run so the agent loop never blocks (a blocked
// loop would make the agent look stale). Never reboots.
// ---------------------------------------------------------------------------

const APT_UNIT      = 'nexovirt-apt-upgrade';
const APT_LOG_DIR   = '/var/log/nexovirt';
const APT_LOG       = APT_LOG_DIR . '/apt-upgrade.log';
const APT_EXIT_FILE = APT_LOG_DIR . '/apt-upgrade.exit';
const APT_RUN_FILE  = APT_LOG_DIR . '/apt-upgrade.run';
const APT_MAX_NAMES = 500;
const APT_LOG_CHUNK = 65536;
const APT_DPKG_OPTS = '-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold';

/** 1..500 Debian package names (lowercase, no options, no paths). PURE. @param mixed $names */
function nexovirt_valid_apt_names($names): bool
{
    if (! is_array($names) || $names === [] || count($names) > APT_MAX_NAMES) {
        return false;
    }
    foreach ($names as $n) {
        if (! is_string($n) || preg_match('/^[a-z0-9][a-z0-9+.-]{0,127}$/', $n) !== 1) {
            return false;
        }
    }

    return true;
}

/** Kernel packages (their upgrade needs a reboot to take effect). PURE. */
function nexovirt_is_kernel_pkg(string $name): bool
{
    return preg_match('/^(proxmox-kernel-|pve-kernel-|linux-image-)/', $name) === 1;
}

/**
 * Parse `apt list --upgradable` ("name/origin to arch [upgradable from: from]"). PURE.
 *
 * @return list<array{name:string, from:string, to:string, origin:string, kernel:bool}>
 */
function nexovirt_parse_apt_upgradable(string $out): array
{
    $pkgs = [];
    foreach (preg_split('/\R/', $out) ?: [] as $line) {
        if (preg_match('#^([a-z0-9][a-z0-9+.-]*)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]#', trim($line), $m) === 1) {
            $pkgs[] = ['name' => $m[1], 'from' => $m[4], 'to' => $m[3], 'origin' => $m[2], 'kernel' => nexovirt_is_kernel_pkg($m[1])];
        }
    }

    return $pkgs;
}

/**
 * Parse an `apt-get -s ...` simulation: Inst with [old] = upgrade, Inst without = new install,
 * Remv = removal, plus the summary counts. Arch qualifiers (name:amd64) are dropped. PURE.
 *
 * @return array{upgrade:list<string>, install:list<string>, remove:list<string>, counts:array{upgrade:int,new:int,remove:int,kept:int}, kernel:bool}
 */
function nexovirt_parse_apt_sim(string $out): array
{
    $r = ['upgrade' => [], 'install' => [], 'remove' => [], 'counts' => ['upgrade' => 0, 'new' => 0, 'remove' => 0, 'kept' => 0], 'kernel' => false];
    $name = static fn (string $n): string => (string) preg_replace('/:[a-z0-9]+$/', '', $n);
    foreach (preg_split('/\R/', $out) ?: [] as $line) {
        if (preg_match('/^Inst (\S+) (\[[^\]]*\] )?\(/', $line, $m) === 1) {
            $r[($m[2] ?? '') !== '' ? 'upgrade' : 'install'][] = $name($m[1]);
        } elseif (preg_match('/^Remv (\S+)/', $line, $m) === 1) {
            $r['remove'][] = $name($m[1]);
        } elseif (preg_match('/^(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded/', $line, $m) === 1) {
            $r['counts'] = ['upgrade' => (int) $m[1], 'new' => (int) $m[2], 'remove' => (int) $m[3], 'kept' => (int) $m[4]];
        }
    }
    foreach (array_merge($r['upgrade'], $r['install']) as $n) {
        if (nexovirt_is_kernel_pkg($n)) {
            $r['kernel'] = true;
            break;
        }
    }

    return $r;
}

/** Short machine reason for a failed apt run (the panel maps it to a hint). PURE. */
function nexovirt_apt_error_reason(string $out, int $code = 0): string
{
    if ($code === 124) {
        return 'timeout';
    }
    if (preg_match('/\b401\b|Unauthorized/i', $out) === 1) {
        return 'repo_unauthorized';
    }
    if (preg_match('/Temporary failure resolving|Could not resolve/i', $out) === 1) {
        return 'dns';
    }
    if (preg_match('/Could not get lock|Unable to acquire the dpkg/i', $out) === 1) {
        return 'locked';
    }
    if (stripos($out, 'dpkg was interrupted') !== false) {
        return 'dpkg_interrupted';
    }

    return 'failed';
}

/** The E:/W:/Err: lines of an apt run verbatim (else its last lines), capped. PURE. */
function nexovirt_apt_error_lines(string $out): string
{
    $lines = preg_split('/\R/', trim($out)) ?: [];
    $errs  = array_values(array_filter($lines, static fn ($l) => preg_match('/^(E|W|Err):/', (string) $l) === 1));

    return nexovirt_cap_output(implode("\n", $errs !== [] ? $errs : array_slice($lines, -15)), 4000);
}

/** A reboot is needed when the flag file exists or a newer kernel than the running one is installed. PURE. */
function nexovirt_reboot_required(string $running, array $installed, bool $flagFile): bool
{
    if ($flagFile) {
        return true;
    }
    if ($installed === []) {
        return false;
    }
    usort($installed, 'strnatcmp');

    return strnatcmp((string) end($installed), $running) > 0;
}

/**
 * The detached upgrade command: systemd-run starts a transient unit that runs apt-get
 * non-interactively (keeping existing config files), appends all output to the 0600 log and
 * records the exit code in APT_EXIT_FILE (--collect unloads the unit, so systemd forgets it). PURE.
 *
 * @param list<string> $names already validated (mode selected)
 */
function nexovirt_apt_upgrade_cmd(string $mode, array $names): string
{
    $apt = 'apt-get -y ' . APT_DPKG_OPTS . ($mode === 'all'
        ? ' dist-upgrade'
        : ' install --only-upgrade ' . implode(' ', array_map('escapeshellarg', $names)));
    $script = $apt . '; rc=$?; echo "$rc" > ' . APT_EXIT_FILE . '; exit "$rc"';

    return 'systemd-run --unit=' . APT_UNIT . ' --collect --quiet'
        . ' --setenv=DEBIAN_FRONTEND=noninteractive --setenv=APT_LISTCHANGES_FRONTEND=none'
        . ' --property=StandardOutput=append:' . APT_LOG . ' --property=StandardError=append:' . APT_LOG
        . ' /bin/sh -c ' . escapeshellarg($script);
}

/** Read up to APT_LOG_CHUNK bytes of $path from $offset (an offset past EOF restarts at 0). */
function nexovirt_log_tail(string $path, int $offset): array
{
    clearstatcache(true, $path);
    $size = is_file($path) ? (int) filesize($path) : 0;
    if ($size === 0) {
        return ['log' => '', 'offset' => 0];
    }
    if ($offset < 0 || $offset > $size) {
        $offset = 0;
    }
    $fh = @fopen($path, 'rb');
    if ($fh === false) {
        return ['log' => '', 'offset' => $offset];
    }
    fseek($fh, $offset);
    $data = (string) fread($fh, APT_LOG_CHUNK);
    fclose($fh);

    return ['log' => $data, 'offset' => $offset + strlen($data)];
}

/** True when another apt/dpkg holds the dpkg lock (best-effort: without fuser apt-get itself refuses). */
function nexovirt_dpkg_locked(): bool
{
    if (! nexovirt_bin_installed('fuser')) {
        return false;
    }
    $o = [];
    $c = 1;
    exec('fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock >/dev/null 2>&1', $o, $c);

    return $c === 0;
}

/**
 * apt-get update (bounded), then the upgradable list + a dist-upgrade simulation. An update error
 * (e.g. 401 from the enterprise repository without a subscription) is returned verbatim with a
 * reason code next to the list from the existing package lists.
 *
 * @return array{ok:bool, result?:array<string,mixed>, error?:string}
 */
function nexovirt_apt_refresh(?callable $tick = null): array
{
    if (getenv('NEXOVIRT_AGENT_DRYRUN') === '1') {
        $sim = nexovirt_parse_apt_sim("Inst pve-manager [8.2.4] (8.2.7 Proxmox:8.2/stable [amd64])\nInst proxmox-kernel-6.8 [6.8.12-2] (6.8.12-4 Proxmox:8.2/stable [all])\nInst proxmox-kernel-6.8.12-4-pve-signed (6.8.12-4 Proxmox:8.2/stable [amd64])\n2 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.");

        return ['ok' => true, 'result' => [
            'packages' => nexovirt_parse_apt_upgradable("pve-manager/stable 8.2.7 amd64 [upgradable from: 8.2.4]\nproxmox-kernel-6.8/stable 6.8.12-4 all [upgradable from: 6.8.12-2]"),
            'summary'  => $sim['counts'], 'kernel' => $sim['kernel'], 'new' => $sim['install'], 'remove' => $sim['remove'],
            'error'    => '', 'reason' => '',
        ]];
    }
    if (! nexovirt_bin_installed('apt-get')) {
        return ['ok' => false, 'error' => 'apt-get is not available on this node.'];
    }

    $error  = '';
    $reason = '';
    $upd    = nexovirt_run_with_ticks('timeout 150 apt-get update 2>&1', $tick, 60);
    if ($upd['code'] !== 0) {
        $error  = nexovirt_apt_error_lines($upd['out']);
        $reason = nexovirt_apt_error_reason($upd['out'], $upd['code']);
    }
    $list = nexovirt_run_with_ticks('timeout 60 apt list --upgradable 2>/dev/null', $tick, 60);
    $sim  = nexovirt_run_with_ticks('timeout 120 apt-get -s dist-upgrade 2>&1', $tick, 60);
    $p    = nexovirt_parse_apt_sim($sim['out']);
    if ($sim['code'] !== 0 && $error === '') {
        $error  = nexovirt_apt_error_lines($sim['out']);
        $reason = nexovirt_apt_error_reason($sim['out'], $sim['code']);
    }

    return ['ok' => true, 'result' => [
        'packages' => nexovirt_parse_apt_upgradable($list['out']),
        'summary'  => $p['counts'], 'kernel' => $p['kernel'], 'new' => $p['install'], 'remove' => $p['remove'],
        'error'    => $error, 'reason' => $reason,
    ]];
}

/**
 * Simulate upgrading only $names: what apt would really upgrade/install/remove for that selection.
 * A selection that would remove anything is refused (error lists the packages).
 *
 * @param list<string> $names validated by the dispatcher
 * @return array{ok:bool, result?:array<string,mixed>, error?:string}
 */
function nexovirt_apt_simulate(array $names, ?callable $tick = null): array
{
    if (getenv('NEXOVIRT_AGENT_DRYRUN') === '1') {
        $lines = [];
        foreach ($names as $n) {
            $lines[] = $n === 'removes-something' ? 'Remv old-tool [1.0]' : "Inst {$n} [1.0] (1.1 Debian:12/stable [amd64])";
            if ($n === 'pve-manager') {
                $lines[] = 'Inst libpve-common-perl [8.2.2] (8.2.3 Proxmox:8.2/stable [all])';
            }
        }
        $out = implode("\n", $lines);
    } else {
        $sim = nexovirt_run_with_ticks('timeout 120 apt-get -s install --only-upgrade ' . implode(' ', array_map('escapeshellarg', $names)) . ' 2>&1', $tick, 60);
        if ($sim['code'] !== 0) {
            return ['ok' => false, 'error' => 'The simulation failed: ' . nexovirt_apt_error_lines($sim['out'])];
        }
        $out = $sim['out'];
    }
    $p = nexovirt_parse_apt_sim($out);
    if ($p['remove'] !== []) {
        return ['ok' => false, 'error' => 'This selection would remove packages: ' . implode(', ', $p['remove']) . '. Install all updates instead, or check the node manually.'];
    }

    return ['ok' => true, 'result' => ['upgrade' => $p['upgrade'], 'install' => $p['install'], 'remove' => [], 'kernel' => $p['kernel']]];
}

/**
 * Start the detached upgrade (mode all = dist-upgrade, selected = install --only-upgrade <names>).
 * Refuses while one is running or dpkg is locked. Returns at once with a run id.
 *
 * @param list<string> $names
 * @return array{ok:bool, result?:array<string,mixed>, error?:string}
 */
function nexovirt_apt_upgrade_start(string $mode, array $names): array
{
    if (! in_array($mode, ['all', 'selected'], true)) {
        return ['ok' => false, 'error' => 'invalid apt_upgrade_start payload: mode'];
    }
    if ($mode === 'selected' && ! nexovirt_valid_apt_names($names)) {
        return ['ok' => false, 'error' => 'invalid apt_upgrade_start payload: names'];
    }
    $names = $mode === 'all' ? [] : array_values($names);
    $run   = date('YmdHis');
    if (getenv('NEXOVIRT_AGENT_DRYRUN') === '1') {
        return ['ok' => true, 'result' => ['run' => $run, 'mode' => $mode]];
    }
    if (! nexovirt_bin_installed('apt-get') || ! nexovirt_bin_installed('systemd-run')) {
        return ['ok' => false, 'error' => 'apt-get or systemd-run is not available on this node.'];
    }
    if (in_array(trim(nexovirt_run_cmd('systemctl is-active ' . APT_UNIT)), ['active', 'activating', 'reloading'], true)) {
        return ['ok' => false, 'error' => 'An update is already running on this node.'];
    }
    if (nexovirt_dpkg_locked()) {
        return ['ok' => false, 'error' => 'Another package manager (apt or dpkg) is running on this node. Try again when it has finished.'];
    }
    if (! is_dir(APT_LOG_DIR)) {
        @mkdir(APT_LOG_DIR, 0700, true);
    }
    @unlink(APT_EXIT_FILE);
    if (! nexovirt_write_private(APT_LOG, '') || ! nexovirt_write_private(APT_RUN_FILE, nexovirt_json(['run' => $run, 'mode' => $mode, 'count' => count($names)]))) {
        return ['ok' => false, 'error' => 'Could not write the update log in ' . APT_LOG_DIR . '.'];
    }
    $out  = [];
    $code = 0;
    exec(nexovirt_apt_upgrade_cmd($mode, $names) . ' 2>&1', $out, $code);
    if ($code !== 0) {
        return ['ok' => false, 'error' => 'Could not start the update: ' . nexovirt_cap_output(implode("\n", $out), 2000)];
    }

    return ['ok' => true, 'result' => ['run' => $run, 'mode' => $mode]];
}

/**
 * State of the detached upgrade: running / succeeded / failed (+ exit code) / idle, the log after
 * $offset (bounded) and whether a reboot is required.
 *
 * @return array<string,mixed>
 */
function nexovirt_apt_upgrade_status(int $offset): array
{
    if (getenv('NEXOVIRT_AGENT_DRYRUN') === '1') {
        $log = "Reading package lists...\nSetting up pve-manager (8.2.7) ...\n";

        return ['state' => 'succeeded', 'exit_code' => 0, 'run' => '20261014120000', 'log' => substr($log, $offset), 'offset' => strlen($log), 'reboot_required' => false];
    }

    $active = trim(nexovirt_run_cmd('systemctl is-active ' . APT_UNIT));
    $exit   = is_readable(APT_EXIT_FILE) ? trim((string) @file_get_contents(APT_EXIT_FILE)) : '';
    $runRaw = is_readable(APT_RUN_FILE) ? (string) @file_get_contents(APT_RUN_FILE) : '';
    $run    = json_decode($runRaw, true);
    $code   = null;
    if (in_array($active, ['active', 'activating', 'reloading'], true)) {
        $state = 'running';
    } elseif ($exit !== '' && ctype_digit($exit)) {
        $code  = (int) $exit;
        $state = $code === 0 ? 'succeeded' : 'failed';
    } else {
        $state = is_array($run) ? 'failed' : 'idle'; // a run that ended without an exit code was killed
    }
    $tail = nexovirt_log_tail(APT_LOG, $offset);
    $kernels = array_map(static fn ($p) => substr((string) $p, strlen('/boot/vmlinuz-')), glob('/boot/vmlinuz-*') ?: []);

    return [
        'state'           => $state,
        'exit_code'       => $code,
        'run'             => is_array($run) ? (string) ($run['run'] ?? '') : '',
        'log'             => $tail['log'],
        'offset'          => $tail['offset'],
        'reboot_required' => nexovirt_reboot_required(php_uname('r'), $kernels, is_file('/var/run/reboot-required')),
    ];
}

/**
 * Execute one job. Returns ['id'=>int, 'ok'=>bool, 'result'=>string].
 * Allowlisted job types only (`write_snippet`, `ensure_storage`, `download_image`,
 * `delete_image`, `apply_nat`, `clear_nat`, `read_firewall`, `read_system`,
 * `read_pve`, `read_logs`, `read_pve_logs`, `lxc_root_ssh`);
 * everything else is rejected here.
 *
 * @param array{id:int, type:string, payload:array<string,mixed>} $job
 */
function nexovirt_dispatch_job(array $job, array $config = []): array
{
    $id   = (int) ($job['id'] ?? 0);
    $type = (string) ($job['type'] ?? '');
    $p    = is_array($job['payload'] ?? null) ? $job['payload'] : [];

    if ($type === 'write_snippet') {
        $storage = (string) ($p['storage'] ?? 'local');
        // The snippet is always written to SNIPPETS_DIR (local's snippets dir), so only `local` is
        // truthful; any other storage would hand the panel a reference to a file that isn't there.
        if ($storage !== 'local') {
            return ['id' => $id, 'ok' => false, 'result' => 'unsupported snippet storage (only local)'];
        }
        $name    = (string) ($p['filename'] ?? '');
        $content = (string) ($p['content'] ?? '');
        $w       = nexovirt_write_snippet(nexovirt_snippets_dir(), $name, $content);
        return $w['ok']
            ? ['id' => $id, 'ok' => true, 'result' => nexovirt_snippet_ref($storage, $name)]
            : ['id' => $id, 'ok' => false, 'result' => $w['error']];
    }

    if ($type === 'ensure_storage') {
        $storage = (string) ($p['storage'] ?? '');
        $path    = (string) ($p['path'] ?? '');
        $content = (string) ($p['content'] ?? '');
        if (! nexovirt_validate_storage_name($storage) || ! nexovirt_validate_storage_path($path) || preg_match('/^[a-z,]+$/', $content) !== 1) {
            return ['id' => $id, 'ok' => false, 'result' => 'invalid ensure_storage payload'];
        }
        $r = nexovirt_ensure_storage($storage, $path, $content);
        return $r['ok'] ? ['id' => $id, 'ok' => true, 'result' => $storage] : ['id' => $id, 'ok' => false, 'result' => $r['error']];
    }

    if ($type === 'download_image') {
        $tick = isset($config['busyTick']) && is_callable($config['busyTick']) ? $config['busyTick'] : null;
        $r    = nexovirt_download_image((string) ($p['url'] ?? ''), (string) ($p['filename'] ?? ''), (string) ($p['content'] ?? 'iso'), $tick);
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['result']];
    }

    if ($type === 'image_cache_start') {
        $r = nexovirt_image_cache_start($p);
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['result']];
    }

    if ($type === 'delete_image') {
        $r = nexovirt_delete_image((string) ($p['filename'] ?? ''), (string) ($p['content'] ?? 'iso'));
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['result']];
    }

    if ($type === 'apply_nat') {
        $valid = nexovirt_validate_nat_config($p);
        if (! $valid['ok']) {
            return ['id' => $id, 'ok' => false, 'result' => 'invalid apply_nat payload'];
        }
        $r = nexovirt_apply_nat($p);
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['ok'] ? 'applied' : $r['error']];
    }

    if ($type === 'clear_nat') {
        $r = nexovirt_clear_nat();
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['ok'] ? 'cleared' : $r['error']];
    }

    if ($type === 'apply_wireguard') {
        $valid = nexovirt_validate_wg_payload($p);
        if (! $valid['ok']) {
            return ['id' => $id, 'ok' => false, 'result' => 'invalid apply_wireguard payload: ' . $valid['error']];
        }
        $r = nexovirt_apply_wireguard($p);
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['ok'] ? nexovirt_json($r['status']) : $r['error']];
    }

    if ($type === 'read_wireguard') {
        // Read-only, no parameters consumed.
        return ['id' => $id, 'ok' => true, 'result' => nexovirt_json(nexovirt_read_wireguard())];
    }

    if ($type === 'read_firewall') {
        // Read-only: no payload validation needed (no parameters consumed).
        $fw = nexovirt_read_firewall();
        return ['id' => $id, 'ok' => true, 'result' => nexovirt_json($fw)];
    }

    if ($type === 'read_system') {
        // Read-only, no parameters → no injection surface.
        $sys = nexovirt_read_system();
        return ['id' => $id, 'ok' => true, 'result' => nexovirt_json($sys)];
    }

    if ($type === 'read_pve') {
        // Read-only, no parameters → no injection surface.
        $pve = nexovirt_read_pve();
        return ['id' => $id, 'ok' => true, 'result' => nexovirt_json($pve)];
    }

    if ($type === 'read_logs') {
        // Read-only, no parameters → no injection surface.
        $logs = nexovirt_read_logs();
        return ['id' => $id, 'ok' => true, 'result' => nexovirt_json($logs)];
    }

    if ($type === 'read_pve_logs') {
        // Read-only, no parameters → no injection surface.
        $logs = nexovirt_read_pve_logs();
        return ['id' => $id, 'ok' => true, 'result' => nexovirt_json($logs)];
    }

    if ($type === 'probe_sdn_dhcp') {
        // Read-only, no parameters → no injection surface. Reports whether SDN DHCP can be enabled safely.
        $r = nexovirt_probe_sdn_dhcp();
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['result']];
    }

    if ($type === 'ensure_sdn_dhcp') {
        // No parameters → no injection surface. Installs dnsmasq only if absent + safe; never disturbs a running one.
        $r = nexovirt_ensure_sdn_dhcp();
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['result']];
    }

    if ($type === 'ensure_sdn_egress') {
        // No parameters. Enables + persists IPv4 forwarding so a SNAT SDN subnet can route to the WAN.
        $r = nexovirt_ensure_sdn_egress();
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['result']];
    }

    if ($type === 'set_ip_forward') {
        // payload {enabled: 0|1}: the only accepted field; anything else is ignored.
        $r = nexovirt_set_ip_forward(! empty($p['enabled']));
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['result']];
    }

    if ($type === 'lxc_root_ssh') {
        $vmid = (int) ($p['vmid'] ?? 0);
        if ($vmid < 1) {
            return ['id' => $id, 'ok' => false, 'result' => 'invalid lxc_root_ssh payload'];
        }
        $r = nexovirt_lxc_root_ssh($vmid);
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['result']];
    }

    if ($type === 'lxc_set_password') {
        $r = nexovirt_lxc_set_password((int) ($p['vmid'] ?? 0), (string) ($p['password'] ?? ''));
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['result']];
    }

    if ($type === 'scan_ips') {
        $r = nexovirt_scan_ips((string) ($p['cidr'] ?? ''));
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['ok']
            ? nexovirt_json(['alive' => $r['alive'], 'scanned' => $r['scanned']])
            : (string) ($r['error'] ?? 'scan failed')];
    }

    if ($type === 'probe_tcp') {
        $r = nexovirt_probe_tcp((string) ($p['host'] ?? ''), $p['port'] ?? 0);
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['result']];
    }

    if ($type === 'guest_unlock') {
        $r = nexovirt_guest_unlock((string) ($p['type'] ?? ''), $p['vmid'] ?? 0);
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['result']];
    }

    if ($type === 'dyndns_configure') {
        $valid = nexovirt_validate_dyndns_payload($p);
        if (! $valid['ok']) {
            return ['id' => $id, 'ok' => false, 'result' => 'invalid dyndns_configure payload: ' . $valid['error']];
        }
        // No inline publish here: the result must reach the panel fast (it waits 30 s). The main loop
        // runs the first update right after this job's result is delivered.
        $r = nexovirt_dyndns_configure($p);

        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['ok'] ? ($p['enabled'] ? 'configured' : 'removed') : $r['error']];
    }

    if ($type === 'apt_refresh') {
        // No parameters consumed. Bounded (timeouts) and keeps busy heartbeats going while apt runs.
        $tick = isset($config['busyTick']) && is_callable($config['busyTick']) ? $config['busyTick'] : null;
        $r    = nexovirt_apt_refresh($tick);
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['ok'] ? nexovirt_json($r['result']) : $r['error']];
    }

    if ($type === 'apt_simulate') {
        $names = $p['names'] ?? null;
        if (! nexovirt_valid_apt_names($names)) {
            return ['id' => $id, 'ok' => false, 'result' => 'invalid apt_simulate payload'];
        }
        $tick = isset($config['busyTick']) && is_callable($config['busyTick']) ? $config['busyTick'] : null;
        $r    = nexovirt_apt_simulate(array_values($names), $tick);
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['ok'] ? nexovirt_json($r['result']) : $r['error']];
    }

    if ($type === 'apt_upgrade_start') {
        $r = nexovirt_apt_upgrade_start((string) ($p['mode'] ?? ''), is_array($p['names'] ?? null) ? $p['names'] : []);
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['ok'] ? nexovirt_json($r['result']) : $r['error']];
    }

    if ($type === 'apt_upgrade_status') {
        // Read-only; the only field is the numeric log offset.
        return ['id' => $id, 'ok' => true, 'result' => nexovirt_json(nexovirt_apt_upgrade_status(max(0, (int) ($p['offset'] ?? 0))))];
    }

    return ['id' => $id, 'ok' => false, 'result' => 'unsupported job type'];
}

/**
 * Active IP-usage scan for IPAM (read-only). Ping-sweep the CIDR to populate the ARP cache, then
 * read the neighbor table: an IP with a resolved MAC (state not FAILED/INCOMPLETE) is in use on
 * the LAN, which ALSO catches devices that ignore ICMP (ARP still answers). Bounded to <= 1024
 * addresses (prefix >= 22) so it can never sweep a huge range. Every pinged IP is derived from the
 * validated CIDR and escapeshellarg'd, no payload string reaches the shell.
 *
 * @return array{ok:bool, alive?:array<int,string>, scanned?:int, error?:string}
 */
function nexovirt_scan_ips(string $cidr): array
{
    if (! nexovirt_validate_nat_cidr($cidr)) {
        return ['ok' => false, 'error' => 'Invalid CIDR.'];
    }
    [$net, $bits] = explode('/', $cidr, 2);
    $prefix = (int) $bits;
    if ($prefix < 22 || $prefix > 32) {
        return ['ok' => false, 'error' => 'Range too large: use a /22 or smaller.'];
    }
    $netLong = ip2long($net) & (0xFFFFFFFF << (32 - $prefix)) & 0xFFFFFFFF;
    $size    = 1 << (32 - $prefix);
    $first   = $prefix <= 30 ? 1 : 0;                 // skip the network address on real subnets
    $last    = $prefix <= 30 ? $size - 2 : $size - 1; // skip the broadcast address
    $ips = [];
    for ($i = $first; $i <= $last; $i++) {
        $ips[] = long2ip(($netLong + $i) & 0xFFFFFFFF);
    }

    // Ping-sweep in bounded parallel batches to populate the ARP cache (best-effort).
    foreach (array_chunk($ips, 64) as $chunk) {
        $cmds = [];
        foreach ($chunk as $ip) {
            $cmds[] = 'ping -c1 -W1 ' . escapeshellarg($ip) . ' >/dev/null 2>&1 &';
        }
        @exec(implode(' ', $cmds) . ' wait');
    }

    // A neighbor with a resolved MAC (not FAILED/INCOMPLETE) is in use: includes ICMP-silent hosts.
    $neigh = [];
    @exec('ip -4 neigh show 2>/dev/null', $neigh);
    $inPool = array_flip($ips);
    $alive  = [];
    foreach ($neigh as $line) {
        if (preg_match('/^(\d+\.\d+\.\d+\.\d+)\b.*\blladdr\s+([0-9a-f:]{17})\b\s+(\S+)/i', $line, $m)) {
            $ip    = $m[1];
            $state = strtoupper($m[3]);
            if (isset($inPool[$ip]) && $state !== 'FAILED' && $state !== 'INCOMPLETE') {
                $alive[$ip] = true;
            }
        }
    }

    return ['ok' => true, 'alive' => array_keys($alive), 'scanned' => count($ips)];
}

/**
 * Pull the jobs array out of a heartbeat response body.
 *
 * @return array<int, array{id:int, type:string, payload:array<string,mixed>}>
 */
function nexovirt_parse_jobs(string $body): array
{
    $decoded = json_decode($body, true);
    $jobs    = is_array($decoded) ? ($decoded['data']['jobs'] ?? null) : null;
    // Skip malformed (non-array) entries instead of letting the typed dispatcher crash the agent.
    return is_array($jobs) ? array_values(array_filter($jobs, 'is_array')) : [];
}

/**
 * Dispatch one job, never letting a handler exception kill the agent mid-batch (the remaining jobs
 * would be left stuck 'running' on the panel). The panel gets a generic error; the detail goes to
 * the local journal only.
 *
 * @return array{id:int, ok:bool, result:string}
 */
function nexovirt_run_job(array $job, array $config = []): array
{
    $id = is_numeric($job['id'] ?? null) ? (int) $job['id'] : 0;
    try {
        return nexovirt_dispatch_job($job, $config);
    } catch (\Throwable $e) {
        fwrite(STDERR, '[' . date('Y-m-d H:i:s') . "] Job {$id} crashed: " . get_class($e) . ': ' . $e->getMessage() . "\n");
        return ['id' => $id, 'ok' => false, 'result' => 'agent error while running the job (see the agent journal)'];
    }
}

/** Max age (seconds) of an undelivered job result before it is dropped. */
const RESULT_QUEUE_MAX_AGE = 3600;
/** Max number of undelivered job results kept for redelivery. */
const RESULT_QUEUE_MAX = 50;

/**
 * Add new job results to the redelivery queue and bound it (drop entries older than
 * RESULT_QUEUE_MAX_AGE, keep the newest RESULT_QUEUE_MAX). PURE.
 *
 * @param list<array{at:int, result:array}> $queue
 * @param list<array>                       $new
 * @return list<array{at:int, result:array}>
 */
function nexovirt_queue_results(array $queue, array $new, int $now): array
{
    foreach ($new as $r) {
        $queue[] = ['at' => $now, 'result' => $r];
    }
    $queue = array_values(array_filter($queue, static fn ($e) => $now - (int) $e['at'] <= RESULT_QUEUE_MAX_AGE));
    return array_slice($queue, -RESULT_QUEUE_MAX);
}

/**
 * Send a heartbeat carrying the queued results. Returns [response, remaining queue]: the queue is
 * emptied only when the POST succeeded, so results survive a failed delivery and ride the next one.
 *
 * @return array{0:array{ok:bool, status:int|null, body:string}, 1:list<array{at:int, result:array}>}
 */
function nexovirt_deliver(array $config, array $queue): array
{
    $results = array_map(static fn ($e) => $e['result'], $queue);
    $resp    = sendHeartbeat($config, collectStats(), $results);
    return [$resp, $resp['ok'] ? [] : nexovirt_queue_results($queue, [], time())];
}

// ---------------------------------------------------------------------------
// HTTP: send heartbeat via cURL extension (preferred) or file_get_contents
// ---------------------------------------------------------------------------

/**
 * @param array{url:string, token:string, caBundle:?string, interval:int} $config
 * @param array<string, mixed> $stats
 * @param bool $busy true = keep-alive sent while a long job runs (no results, jobs in the reply ignored)
 * @param array<int, array{id:int, ok:bool, result:string}> $results
 * @return array{ok:bool, status:int|null, body:string}
 */
function sendHeartbeat(array $config, array $stats, array $results = [], bool $busy = false): array
{
    $body = [
        'version' => AGENT_VERSION,
        'stats'   => $stats,
        'results' => $results,
    ];
    if ($busy) {
        // "I'm alive but mid-job": the panel refreshes last_seen and hands out NO jobs.
        $body['busy'] = true;
    }
    $payload = nexovirt_json($body);

    $endpoint = $config['url'] . '/api/v1/agent/heartbeat';

    if (extension_loaded('curl')) {
        return sendWithCurl($endpoint, $config['token'], $payload, $config['caBundle']);
    }

    return sendWithStream($endpoint, $config['token'], $payload, $config['caBundle']);
}

/**
 * @return array{ok:bool, status:int|null, body:string}
 */
function sendWithCurl(string $url, string $token, string $payload, ?string $caBundle): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => CONNECT_TIMEOUT,
        CURLOPT_TIMEOUT        => REQUEST_TIMEOUT,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HTTPHEADER     => [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $token,
        ],
    ]);

    if ($caBundle !== null && is_file($caBundle)) {
        curl_setopt($ch, CURLOPT_CAINFO, $caBundle);
    }

    $body   = (string) curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error  = curl_error($ch);
    curl_close($ch);

    if ($error !== '') {
        return ['ok' => false, 'status' => null, 'body' => $error];
    }

    return ['ok' => $status >= 200 && $status < 300, 'status' => $status, 'body' => $body];
}

/**
 * Fallback when the cURL extension is not available.
 *
 * @return array{ok:bool, status:int|null, body:string}
 */
function sendWithStream(string $url, string $token, string $payload, ?string $caBundle): array
{
    $opts = [
        'http' => [
            'method'        => 'POST',
            'header'        => implode("\r\n", [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $token,
                'Content-Length: ' . strlen($payload),
            ]),
            'content'       => $payload,
            'timeout'       => REQUEST_TIMEOUT,
            'ignore_errors' => true,
        ],
        'ssl' => [
            'verify_peer'      => true,
            'verify_peer_name' => true,
        ],
    ];

    if ($caBundle !== null && is_file($caBundle)) {
        $opts['ssl']['cafile'] = $caBundle;
    }

    $ctx  = stream_context_create($opts);
    $body = @file_get_contents($url, false, $ctx);

    if ($body === false) {
        return ['ok' => false, 'status' => null, 'body' => 'Connection failed'];
    }

    // Extract status code from $http_response_header (set by file_get_contents)
    $status = null;
    if (! empty($http_response_header[0])) {
        preg_match('/HTTP\/\S+\s+(\d+)/', $http_response_header[0], $m);
        $status = isset($m[1]) ? (int) $m[1] : null;
    }

    return ['ok' => $status !== null && $status >= 200 && $status < 300, 'status' => $status, 'body' => $body];
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

$once = in_array('--once', $argv ?? [], true);

// Detached image download child (started by image_cache_start via systemd-run).
if (getenv('NEXOVIRT_AGENT_NO_MAIN') !== '1' && ($argv[1] ?? '') === '--image-download') {
    $r = nexovirt_image_cache_run((string) ($argv[2] ?? ''));
    fwrite($r['ok'] ? STDOUT : STDERR, '[nexovirt-agent] image ' . ($argv[2] ?? '') . ': ' . $r['result'] . "\n");
    exit($r['ok'] ? 0 : 1);
}

if (getenv('NEXOVIRT_AGENT_NO_MAIN') !== '1') {
    $config = loadConfig();

    $endpoint = $config['url'] . '/api/v1/agent/heartbeat';
    fwrite(STDOUT, "[nexovirt-agent] Starting v" . AGENT_VERSION . " → {$endpoint}\n");

    // Keep-alive while a long job (e.g. a 30 min image download) blocks the loop, so the panel
    // doesn't mark the agent stale after 300s. Any jobs in its reply are ignored (the server hands
    // none out to a busy agent anyway).
    $config['busyTick'] = static function () use ($config): void {
        $r = sendHeartbeat($config, collectStats(), [], true);
        if (! $r['ok']) {
            fwrite(STDERR, '[' . date('Y-m-d H:i:s') . "] Busy heartbeat FAILED\n");
        }
    };

    $queue = []; // undelivered job results (redelivered on the next heartbeat, bounded)
    $sweepLast  = 0; // last stale .part sweep of the image cache dir
    $dyndnsLast = 0; // last DynDNS update run (0 = due now, also reset after a dyndns_configure job)

    do {
        [$result, $queue] = nexovirt_deliver($config, $queue);

        $ts = date('Y-m-d H:i:s');
        if ($result['ok']) {
            fwrite(STDOUT, "[{$ts}] Heartbeat OK (HTTP {$result['status']})\n");
        } else {
            $detail = $result['status'] !== null ? "HTTP {$result['status']}" : 'no response';
            fwrite(STDERR, "[{$ts}] Heartbeat FAILED ({$detail}): " . substr($result['body'], 0, 200) . "\n");
        }

        // Execute any jobs the panel handed us, then report immediately.
        $jobs    = $result['ok'] ? nexovirt_parse_jobs($result['body']) : [];
        $hadJobs = $jobs !== [];

        // Execute handed-out jobs, then deliver their results in an immediate follow-up
        // heartbeat. That follow-up's response can itself carry jobs enqueued while we were
        // working (the server marks them running on hand-out), so keep draining until a
        // heartbeat returns no jobs; otherwise those jobs are left stuck 'running'.
        // A failed delivery keeps the results queued for the next heartbeat (bounded).
        while ($jobs !== []) {
            $results = [];
            foreach ($jobs as $job) {
                $out   = nexovirt_run_job($job, $config);
                $jobTs = date('Y-m-d H:i:s');
                // Log only a prefix: results can be large JSON blobs.
                fwrite(STDOUT, "[{$jobTs}] Job {$out['id']} " . ($out['ok'] ? 'OK' : 'ERROR') . ': ' . substr((string) $out['result'], 0, 200) . "\n");
                $results[] = $out;
                if (($job['type'] ?? '') === 'dyndns_configure') {
                    $dyndnsLast = 0; // publish right after the result is delivered
                }
            }
            $queue = nexovirt_queue_results($queue, $results, time());
            [$follow, $queue] = nexovirt_deliver($config, $queue);
            $jobs = $follow['ok'] ? nexovirt_parse_jobs($follow['body']) : [];
        }

        // DynDNS: at most two 10s curl calls every 300s; heartbeats resume right after.
        // ponytail: runs inline in the loop (worst case 20 s delay of one heartbeat, far under the 300 s
        // stale threshold); move to a forked child if more periodic work appears.
        $dyndnsLast = nexovirt_dyndns_tick($dyndnsLast, time());
        if (time() - $sweepLast >= 3600) {
            nexovirt_images_sweep(time());
            $sweepLast = time();
        }

        if (! $once) {
            sleep($hadJobs ? 3 : $config['interval']);
        }
    } while (! $once);
}
