#!/usr/bin/env php
<?php

/**
 * NexoVirt Host Agent: heartbeat + host stats + job queue
 * (write_snippet, ensure_storage, download_image, delete_image, apply_nat,
 *  clear_nat, read_firewall, read_system, read_pve, read_logs, read_pve_logs,
 *  probe_sdn_dhcp, ensure_sdn_dhcp, ensure_sdn_egress, set_ip_forward,
 *  lxc_root_ssh, lxc_set_password, scan_ips, dyndns_configure, apply_wireguard, read_wireguard,
 *  apt_refresh, apt_simulate, apt_upgrade_start, apt_upgrade_status, nat_inventory,
 *  nat_adopt_finalize, nat_adopt_restore, apply_dhcp, apply_fail2ban, read_fail2ban, fail2ban_unban,
 *  lxc_app_install, lxc_app_status)
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

const AGENT_VERSION        = '0.28.1';
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

    // Port isolation report (0.28.1): the panel's per-guest "Active on the node" status comes from here.
    try {
        $iso = nexovirt_isolation_report();
        if ($iso !== null) {
            $stats['isolation'] = $iso;
        }
    } catch (\Throwable $e) {
        fwrite(STDERR, '[nexovirt-agent] isolation report failed: ' . $e->getMessage() . PHP_EOL);
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
const NAT_MAX_NETWORKS = 32;

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
function nexovirt_probe_tcp(string $host, $port, float $timeout = 5.0): array
{
    if (! nexovirt_validate_probe_host($host) || ! nexovirt_validate_port($port)) {
        return ['ok' => false, 'result' => 'invalid probe_tcp payload'];
    }
    $target = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? '[' . $host . ']' : $host;
    $errno  = 0;
    $errstr = '';
    $fh     = @fsockopen($target, (int) $port, $errno, $errstr, $timeout);
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
    // Several NAT networks (0.24.3, adopted NAT): each one RFC1918, its own WAN iface, optional SNAT address.
    $networks = $config['networks'] ?? [];
    if (! is_array($networks) || count($networks) > NAT_MAX_NETWORKS) {
        return ['ok' => false, 'error' => 'invalid networks'];
    }
    foreach ($networks as $n) {
        if (! is_array($n) || ! nexovirt_validate_nat_cidr((string) ($n['cidr'] ?? '')) || ! nexovirt_validate_iface((string) ($n['wan_iface'] ?? ''))) {
            return ['ok' => false, 'error' => 'invalid network'];
        }
        $snat = (string) ($n['snat_ip'] ?? '');
        if ($snat !== '' && filter_var($snat, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return ['ok' => false, 'error' => 'invalid network snat_ip'];
        }
        $destCidrs[] = (string) $n['cidr'];
    }
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
        $pip = (string) ($f['public_ip'] ?? '');
        if ($pip !== '' && filter_var($pip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return ['ok' => false, 'error' => 'invalid public_ip'];
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

    // 5. MASQUERADE (or SNAT to one address) each private network out its WAN bridge (never traffic
    //    that stays inside it), and let it be forwarded out. `networks` (0.24.3) lists every NAT
    //    network; without it the single private_cidr is the only one.
    $networks = isset($config['networks']) && is_array($config['networks']) && $config['networks'] !== []
        ? $config['networks']
        : [['cidr' => (string) $config['private_cidr'], 'wan_iface' => (string) $config['wan_iface'], 'masquerade' => ! empty($config['masquerade']), 'snat_ip' => '']];
    foreach ($networks as $n) {
        if (empty($n['masquerade'])) {
            continue;
        }
        $nc   = escapeshellarg((string) $n['cidr']);
        $nw   = escapeshellarg((string) $n['wan_iface']);
        $snat = (string) ($n['snat_ip'] ?? '');
        $to   = $snat !== '' ? 'SNAT --to-source ' . escapeshellarg($snat) : 'MASQUERADE';
        $lines[] = "iptables -t nat -A NEXOVIRT-POST -s {$nc} ! -d {$nc} -o {$nw} -j {$to}";
        $lines[] = "iptables -A NEXOVIRT-FWD -s {$nc} -o {$nw} -j ACCEPT";
    }

    // 6. Per-forward DNAT + matching FORWARD ACCEPT.
    foreach (($config['forwards'] ?? []) as $f) {
        $proto = escapeshellarg((string) $f['proto']);
        $dip   = (string) $f['dest_ip'];
        $dipA  = escapeshellarg($dip);
        $start = (int) $f['public_port'];
        $end   = ($f['public_port_end'] ?? null) !== null ? (int) $f['public_port_end'] : null;
        // Only one public address of the WAN (the adopted rule had `-d <public ip>`).
        $pipA  = (string) ($f['public_ip'] ?? '') !== '' ? ' -d ' . escapeshellarg((string) $f['public_ip']) : '';

        if ($end !== null) {
            // Range: same-port DNAT (no remap), range FORWARD ACCEPT.
            $rangeA = escapeshellarg($start . ':' . $end);
            $lines[] = "iptables -t nat -A NEXOVIRT-PRE -i {$wan}{$pipA} -p {$proto} --dport {$rangeA} -j DNAT --to-destination {$dipA}";
            $lines[] = "iptables -A NEXOVIRT-FWD -d {$dipA} -p {$proto} --dport {$rangeA} -j ACCEPT";
        } else {
            $pub    = escapeshellarg((string) $start);
            $dport  = (string) (int) $f['dest_port'];
            $dest   = escapeshellarg($dip . ':' . $dport);
            $dportA = escapeshellarg($dport);
            $lines[] = "iptables -t nat -A NEXOVIRT-PRE -i {$wan}{$pipA} -p {$proto} --dport {$pub} -j DNAT --to-destination {$dest}";
            $lines[] = "iptables -A NEXOVIRT-FWD -d {$dipA} -p {$proto} --dport {$dportA} -j ACCEPT";
        }
    }

    return implode("\n", $lines) . "\n";
}

/**
 * NAT rules on the node that NexoVirt did not create: MASQUERADE / SNAT / DNAT outside the NEXOVIRT-*
 * chains (iptables-save -t nat) and outside the NEXOVIRT-* chains / proxmox* tables (nft list ruleset).
 * SNAT/MASQUERADE whose exact source is one of $ownSources (NexoVirt SDN subnets, written by Proxmox
 * SDN) is not foreign. PURE. @param list<string> $ownSources @return list<string> the offending lines
 */
function nexovirt_nat_foreign_rules(string $iptablesSave, string $nftRuleset, array $ownSources): array
{
    $found = [];
    $own   = static function (string $line, string $srcPattern) use ($ownSources): bool {
        return preg_match($srcPattern, $line, $m) === 1 && in_array($m[1], $ownSources, true);
    };

    $table = '';
    foreach (preg_split('/\r?\n/', $iptablesSave) ?: [] as $line) {
        // `iptables-save -c` prefixes [packets:bytes]: the rule is the same (the panel planner strips it too).
        $line = trim((string) preg_replace('/^\s*\[\d+:\d+\]\s+/', '', $line));
        // iptables-nft cannot list a native nft nat table; without nft output those rules are unknown.
        if ($nftRuleset === '' && preg_match('/^# Table `nat\' is incompatible/', $line) === 1) {
            $found[] = $line;
            continue;
        }
        if ($line !== '' && $line[0] === '*') {
            $table = substr($line, 1);
            continue;
        }
        if ($table !== 'nat' || preg_match('/^-A\s+(\S+)\s.*-j\s+(MASQUERADE|SNAT|DNAT)\b/', $line, $m) !== 1) {
            continue;
        }
        if (strpos($m[1], 'NEXOVIRT-') === 0 || ($m[2] !== 'DNAT' && $own($line, '#\s-s\s+(\S+)#'))) {
            continue;
        }
        $found[] = $line;
    }

    $nftTable = '';
    $nftChain = '';
    foreach (preg_split('/\r?\n/', $nftRuleset) ?: [] as $line) {
        $line = trim($line);
        if (preg_match('/^table\s+\S+\s+(\S+)\s*\{/', $line, $m) === 1) {
            $nftTable = $m[1];
            $nftChain = '';
            continue;
        }
        if (preg_match('/^chain\s+(\S+)\s*\{/', $line, $m) === 1) {
            $nftChain = trim($m[1], '"');
            continue;
        }
        // Only NAT statements count: not a `ct status dnat` match and not text in a comment.
        $stmt = preg_replace(['/\bct\s+status\s+\S+/i', '/\bcomment\s+"[^"]*"/i'], '', $line) ?? $line;
        if (preg_match('/\b(masquerade|snat|dnat)\b/i', $stmt, $m) !== 1 || strpos($line, 'type ') === 0) {
            continue;
        }
        if (strpos($nftChain, 'NEXOVIRT-') === 0 || strpos($nftTable, 'proxmox') !== false
            || (strtolower($m[1]) !== 'dnat' && $own($line, '#\bip\s+saddr\s+(\S+)#'))) {
            continue;
        }
        $found[] = $line;
    }

    return $found;
}

/**
 * Read the node's NAT rule sets for the foreign-NAT check. ['ok'=>bool,'error'=>string,'ipt'=>string,'nft'=>string].
 * Fails closed: an unreadable rule set is an error. DRYRUN seam: NEXOVIRT_AGENT_FAKE_IPT_NAT /
 * NEXOVIRT_AGENT_FAKE_NFT hold the outputs (unit tests); nothing is executed.
 */
function nexovirt_nat_read_rulesets(): array
{
    if (getenv('NEXOVIRT_AGENT_DRYRUN') === '1') {
        return ['ok' => true, 'error' => '', 'ipt' => (string) getenv('NEXOVIRT_AGENT_FAKE_IPT_NAT'), 'nft' => (string) getenv('NEXOVIRT_AGENT_FAKE_NFT')];
    }
    $out  = [];
    $code = 0;
    exec('iptables-save -t nat 2>/dev/null', $out, $code);
    if ($code !== 0) {
        return ['ok' => false, 'error' => 'cannot read the node NAT rules (iptables-save failed); NAT not changed', 'ipt' => '', 'nft' => ''];
    }
    $ipt = implode("\n", $out);
    // iptables-nft hides rules in legacy (x_tables) tables and only says so: read those too.
    if (strpos($ipt, 'iptables-legacy tables present') !== false) {
        $out  = [];
        $code = 0;
        exec('iptables-legacy-save -t nat 2>/dev/null', $out, $code);
        if ($code !== 0) {
            return ['ok' => false, 'error' => 'cannot read the node NAT rules (iptables-legacy-save failed); NAT not changed', 'ipt' => '', 'nft' => ''];
        }
        $ipt .= "\n" . implode("\n", $out);
    }
    $nft = '';
    $has = [];
    exec('command -v nft 2>/dev/null', $has);
    if ($has !== []) {
        $out  = [];
        $code = 0;
        exec('nft list ruleset 2>/dev/null', $out, $code);
        if ($code !== 0) {
            return ['ok' => false, 'error' => 'cannot read the node NAT rules (nft list ruleset failed); NAT not changed', 'ipt' => '', 'nft' => ''];
        }
        $nft = implode("\n", $out);
    }

    return ['ok' => true, 'error' => '', 'ipt' => $ipt, 'nft' => $nft];
}

// ---------------------------------------------------------------------------
// NAT adoption inventory (nat_inventory, 0.24.3): READ-ONLY. Lists the live NAT/raw/filter rules (with
// counters), the nft ruleset (with handles) and the lines of the persistent sources that can carry
// NAT rules, plus optional TCP probes. Nothing is written or executed beyond list/save commands.
// ---------------------------------------------------------------------------

const NAT_INVENTORY_CAP        = 262144;
const NAT_INVENTORY_MAX_PROBES = 32;
const NAT_SOURCE_MAX_FILES     = 40;
const NAT_SOURCE_MAX_LINES     = 2000;

/**
 * Rule-carrying lines of the persistent NAT sources under $root ('' = the real /): /etc/network/interfaces
 * (+ interfaces.d), /etc/iptables/rules.v4 and /etc/nftables.conf (+ its includes). Each entry
 * {path, kind: interfaces|rules_v4|nftables, lines: [{n, text}]}. Read-only, size-capped.
 *
 * @return list<array{path:string,kind:string,lines:list<array{n:int,text:string}>}>
 */
function nexovirt_nat_sources(string $root = ''): array
{
    $files = [['interfaces', '/etc/network/interfaces']];
    foreach (glob($root . '/etc/network/interfaces.d/*') ?: [] as $f) {
        $files[] = ['interfaces', substr($f, strlen($root))];
    }
    $files[] = ['rules_v4', '/etc/iptables/rules.v4'];
    $files[] = ['nftables', '/etc/nftables.conf'];
    $conf = is_readable($root . '/etc/nftables.conf') ? (string) @file_get_contents($root . '/etc/nftables.conf') : '';
    if (preg_match_all('/^\s*include\s+"([^"]+)"/m', $conf, $m) > 0) {
        foreach ($m[1] as $inc) {
            $pattern = $inc[0] === '/' ? $inc : '/etc/' . $inc;
            foreach (glob($root . $pattern) ?: [] as $f) {
                $rel = substr($f, strlen($root));
                if (strpos($rel, '/etc/') === 0 && strpos($rel, '/..') === false) { // never edit files outside /etc
                    $files[] = ['nftables', $rel];
                }
            }
        }
    }
    $match = [
        'interfaces' => '/^\s*(post-up|pre-up|up|post-down|pre-down|down)\s.*\b(iptables|nft)\b/',
        'rules_v4'   => '/^(\*|-A\s)/',
        'nftables'   => '/\b(table|chain|masquerade|snat|dnat)\b/',
    ];
    $out  = [];
    $seen = [];
    foreach (array_slice($files, 0, NAT_SOURCE_MAX_FILES) as [$kind, $path]) {
        if (isset($seen[$path]) || ! is_file($root . $path) || ! is_readable($root . $path)) {
            continue;
        }
        $seen[$path] = true;
        $body  = nexovirt_cap_output((string) @file_get_contents($root . $path), NAT_INVENTORY_CAP);
        $lines = [];
        foreach (preg_split('/\r?\n/', $body) ?: [] as $i => $text) {
            if (preg_match($match[$kind], $text) === 1 && count($lines) < NAT_SOURCE_MAX_LINES) {
                $lines[] = ['n' => $i + 1, 'text' => $text];
            }
        }
        $out[] = ['path' => $path, 'kind' => $kind, 'lines' => $lines];
    }

    return $out;
}

/** The live rule sets for the inventory: iptables-save -c of nat/raw/filter (+ legacy tables) and nft -a. */
function nexovirt_nat_inventory_rulesets(): array
{
    $ipt = '';
    foreach (['nat', 'raw', 'filter'] as $t) {
        $ipt .= nexovirt_run_cmd('iptables-save -c -t ' . $t) . "\n";
    }
    if (strpos($ipt, 'iptables-legacy tables present') !== false) {
        foreach (['nat', 'raw', 'filter'] as $t) {
            $ipt .= nexovirt_run_cmd('iptables-legacy-save -c -t ' . $t) . "\n";
        }
    }
    $nft = nexovirt_bin_installed('nft') ? nexovirt_run_cmd('nft -a list ruleset') : '';

    return [$ipt, $nft];
}

/**
 * nat_inventory job. Payload {probes?: [{host: IPv4, port}]} (max 32, fail-closed). Returns
 * ['ok'=>bool,'result'=>array|string]. DRYRUN seam: NEXOVIRT_AGENT_FAKE_IPT_NAT / NEXOVIRT_AGENT_FAKE_NFT hold
 * the rule sets, NEXOVIRT_AGENT_ETC_ROOT the source tree, and no probe is run.
 */
function nexovirt_nat_inventory(array $p): array
{
    $probes = $p['probes'] ?? [];
    if (! is_array($probes) || count($probes) > NAT_INVENTORY_MAX_PROBES) {
        return ['ok' => false, 'result' => 'invalid nat_inventory payload'];
    }
    foreach ($probes as $pr) {
        if (! is_array($pr) || filter_var((string) ($pr['host'] ?? ''), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false || ! nexovirt_validate_port($pr['port'] ?? 0)) {
            return ['ok' => false, 'result' => 'invalid nat_inventory payload'];
        }
    }
    $dry = getenv('NEXOVIRT_AGENT_DRYRUN') === '1';
    if ($dry) {
        $ipt  = (string) getenv('NEXOVIRT_AGENT_FAKE_IPT_NAT');
        $nft  = (string) getenv('NEXOVIRT_AGENT_FAKE_NFT');
        $root = (string) getenv('NEXOVIRT_AGENT_ETC_ROOT');
    } else {
        [$ipt, $nft] = nexovirt_nat_inventory_rulesets();
        $root = '';
    }
    $results = [];
    foreach ($probes as $pr) {
        $host = (string) $pr['host'];
        $port = (int) $pr['port'];
        $res  = $dry ? ['reachable' => false, 'error' => 'dry run'] : json_decode(nexovirt_probe_tcp($host, $port, 2.0)['result'], true);
        $results[] = ['host' => $host, 'port' => $port, 'reachable' => (bool) ($res['reachable'] ?? false), 'error' => (string) ($res['error'] ?? '')];
    }

    return ['ok' => true, 'result' => [
        'iptables' => nexovirt_cap_output($ipt, NAT_INVENTORY_CAP),
        'nft'      => nexovirt_cap_output($nft, NAT_INVENTORY_CAP),
        'sources'  => nexovirt_nat_sources($root),
        'scripts'  => nexovirt_nat_script_sources($root),
        'probes'   => $results,
    ]];
}

// ---------------------------------------------------------------------------
// NAT adoption switch-off + restore (nat_adopt_finalize / nat_adopt_restore, 0.24.4).
//
// SAFETY CONTRACT: only the adopted rules the panel names are touched, each by EXACT match: an iptables
// rule is checked with `-C <its stored spec>` and removed with `-D <the same spec>`, an nft rule by its
// handle after its text was compared; a rule that no longer matches is reported and left alone. No
// built-in chain or table is ever flushed or deleted; the ONLY chain deletion is a user chain whose
// stored rules are exactly its live rules (jump removed first). Persistent sources come from the fixed
// allowlist (nexovirt_nat_sources), are edited only after the live removal succeeded, only when every
// named line still reads exactly as stored, with a timestamped backup next to the file that is never
// overwritten, and by an atomic tmp + rename. systemd units are only disabled (never stopped/masked)
// and only units nexovirt_nat_script_sources found. No ifreload, no service restart. Every value that
// reaches a shell is escapeshellarg'd token by token.
// ---------------------------------------------------------------------------

const NAT_ADOPT_MAX_RULES  = 500;
const NAT_ADOPT_MAX_CHAINS = 20;
const NAT_ADOPT_MAX_FILES  = 40;
const NAT_ADOPT_MAX_UNITS  = 10;
const NAT_ADOPT_MAX_COUNT  = 64;
const NAT_ADOPT_SCRIPT_CAP = 262144;

/** Lines that hook a script into an interface, and the script/unit test for "sets NAT rules". PURE. */
function nexovirt_nat_text_sets_nat(string $s): bool
{
    return preg_match('/\b(iptables|nft)\b/', $s) === 1 && preg_match('/(-t\s+nat\b|\bnat\b|MASQUERADE|DNAT|SNAT|masquerade|dnat|snat)/', $s) === 1;
}

/** The script a unit's Exec value runs ('' when it is not an absolute path). PURE. */
function nexovirt_nat_exec_path(string $exec): string
{
    $first = (string) (preg_split('/\s+/', ltrim($exec, " \t-@+!:")) ?: [''])[0];

    return preg_match('#^/[A-Za-z0-9_./+-]{1,255}$#', $first) === 1 && strpos($first, '..') === false ? $first : '';
}

function nexovirt_nat_script_sets_nat(string $root, string $script): bool
{
    $f = $root . $script;
    if ($script === '' || ! is_file($f) || ! is_readable($f) || (int) @filesize($f) > NAT_ADOPT_SCRIPT_CAP) {
        return false;
    }

    return nexovirt_nat_text_sets_nat((string) @file_get_contents($f));
}

/**
 * Script sources: interfaces hook lines (post-up/up/pre-up/pre-down/down/post-down) that run a script
 * which sets NAT rules, and /etc/systemd/system units whose Exec lines set NAT rules directly or through
 * such a script (nexovirt-* units excluded). Read-only.
 *
 * @return list<array<string,mixed>> {kind: interfaces, path, n, text, script} | {kind: systemd, path, unit, script}
 */
function nexovirt_nat_script_sources(string $root = ''): array
{
    $out = [];
    foreach (nexovirt_nat_sources($root) as $src) {
        if ($src['kind'] !== 'interfaces') {
            continue;
        }
        $body = (string) @file_get_contents($root . $src['path']);
        foreach (preg_split('/\r?\n/', nexovirt_cap_output($body, NAT_INVENTORY_CAP)) ?: [] as $i => $text) {
            if (preg_match('/^\s*(post-up|pre-up|up|pre-down|down|post-down)\s+(\/\S+)/', $text, $m) !== 1 || preg_match('/\b(iptables|nft)\b/', $text) === 1) {
                continue;
            }
            $script = nexovirt_nat_exec_path($m[2]);
            if ($script !== '' && nexovirt_nat_script_sets_nat($root, $script)) {
                $out[] = ['kind' => 'interfaces', 'path' => $src['path'], 'n' => $i + 1, 'text' => $text, 'script' => $script];
            }
        }
    }
    foreach (array_slice(glob($root . '/etc/systemd/system/*.service') ?: [], 0, 200) as $f) {
        $unit = basename($f);
        if (strpos($unit, 'nexovirt-') === 0 || ! is_file($f) || (int) @filesize($f) > NAT_ADOPT_SCRIPT_CAP) {
            continue;
        }
        if (preg_match_all('/^\s*(ExecStart|ExecStartPre|ExecStartPost)\s*=\s*(.+)$/m', (string) @file_get_contents($f), $m) < 1) {
            continue;
        }
        foreach ($m[2] as $exec) {
            if (nexovirt_nat_text_sets_nat($exec) || nexovirt_nat_script_sets_nat($root, nexovirt_nat_exec_path($exec))) {
                $out[] = ['kind' => 'systemd', 'path' => substr($f, strlen($root)), 'unit' => $unit, 'script' => trim($exec)];
                break;
            }
        }
    }

    return $out;
}

/**
 * Shell-like tokens of an iptables-save line: "double" quotes with \" escapes, 'single' quotes. null when
 * the line does not split cleanly (same rules as the panel's NatRule::tokens). PURE.
 *
 * @return list<string>|null
 */
function nexovirt_nat_tokens(string $s): ?array
{
    $n = preg_match_all('/\G\s*(?:"((?:[^"\\\\]|\\\\.)*)"|\'([^\']*)\'|([^\s"\'\\\\]+))(?=\s|$)/', $s, $m, PREG_SET_ORDER | PREG_UNMATCHED_AS_NULL);
    $used = 0;
    $out  = [];
    foreach ($m as $t) {
        $used += strlen($t[0]);
        $out[] = $t[1] !== null ? (string) preg_replace('/\\\\(.)/', '$1', $t[1]) : (string) ($t[3] ?? $t[2]);
    }

    return $n === false || trim(substr($s, $used)) !== '' ? null : $out;
}

function nexovirt_nat_printable(string $s, int $max = 1000): bool
{
    return $s !== '' && strlen($s) <= $max && preg_match('/^[\x20-\x7e]+$/', $s) === 1;
}

/** An iptables user chain the switch-off may flush + delete. PURE. */
function nexovirt_nat_user_chain(string $c): bool
{
    return preg_match('/^[A-Za-z0-9_.-]{1,28}$/', $c) === 1
        && ! in_array($c, ['PREROUTING', 'POSTROUTING', 'INPUT', 'OUTPUT', 'FORWARD', 'ACCEPT', 'DROP', 'RETURN', 'REJECT', 'MASQUERADE', 'SNAT', 'DNAT', 'CT', 'LOG', 'MARK'], true)
        && strpos($c, 'PVEFW-') !== 0 && strpos($c, 'NEXOVIRT-') !== 0;
}

/**
 * One stored iptables-save rule line ('[p:b] -A CHAIN ...', exactly as nat_inventory returned it) as argv tokens after the op, or null when it is
 * not exactly one append of a plain rule (no other table/chain operation, no NEXOVIRT-* chain). PURE.
 *
 * @return array{chain:string,args:list<string>}|null
 */
function nexovirt_nat_rule_args(string $line): ?array
{
    // The exact line nat_inventory returned; `iptables-save -c` prefixes [packets:bytes].
    $line = (string) preg_replace('/^\[\d+:\d+\]\s+/', '', trim($line));
    if (! nexovirt_nat_printable($line) || strpos($line, '-A ') !== 0) {
        return null;
    }
    $t = nexovirt_nat_tokens($line);
    if ($t === null || count($t) < 3 || preg_match('/^[A-Za-z0-9_.+-]{1,28}$/', $t[1]) !== 1 || strpos($t[1], 'NEXOVIRT-') === 0) {
        return null;
    }
    $ops = ['-A', '--append', '-D', '--delete', '-I', '--insert', '-R', '--replace', '-F', '--flush', '-X', '--delete-chain',
        '-Z', '--zero', '-N', '--new-chain', '-P', '--policy', '-E', '--rename-chain', '-t', '--table', '-C', '--check', '-L', '-S', '-M'];
    $args = array_slice($t, 2);
    foreach ($args as $a) {
        // --modprobe=<program> (or any getopt abbreviation of it) makes iptables EXECUTE a program as root;
        // combined short options (-vM/x) could smuggle -M or a second command past the list above.
        $opt = explode('=', $a, 2)[0];
        if (in_array($a, $ops, true) || $a === '' || (strlen($opt) >= 4 && strncmp('--modprobe', $opt, strlen($opt)) === 0)
            || preg_match('/^-[^-]./', $a) === 1) {
            return null;
        }
    }

    return ['chain' => $t[1], 'args' => $args];
}

/** iptables command for $op (-C|-D|-A) on a stored rule line in $table. PURE. */
function nexovirt_nat_rule_cmd(string $op, string $table, array $rule): string
{
    $parts = ['iptables', '-w', '-t', escapeshellarg($table), $op, escapeshellarg($rule['chain'])];
    foreach ($rule['args'] as $a) {
        $parts[] = escapeshellarg($a);
    }

    return implode(' ', $parts);
}

/** The jump/goto target of a parsed iptables rule, or ''. PURE. */
function nexovirt_nat_rule_target(array $rule): string
{
    foreach ($rule['args'] as $i => $arg) {
        if (in_array($arg, ['-j', '--jump', '-g', '--goto'], true)) {
            return (string) ($rule['args'][$i + 1] ?? '');
        }
    }

    return '';
}

/**
 * What the switch-off may remove or the restore re-add: only the rule kinds NAT adoption takes over.
 * nat: DNAT/SNAT/MASQUERADE in PREROUTING/POSTROUTING or a user chain (chain jumps go through the
 * checked chain step only); raw: the PREROUTING CT zone rule; filter: FORWARD accepts. Never a
 * PVEFW-* chain, never INPUT/OUTPUT, never a DROP/REJECT. PURE.
 */
function nexovirt_nat_adopt_scope_ok(string $table, array $rule): bool
{
    $chain  = $rule['chain'];
    $target = nexovirt_nat_rule_target($rule);
    if (strpos($chain, 'PVEFW-') === 0) {
        return false;
    }
    if ($table === 'nat') {
        return in_array($target, ['DNAT', 'SNAT', 'MASQUERADE'], true)
            && (in_array($chain, ['PREROUTING', 'POSTROUTING'], true) || nexovirt_nat_user_chain($chain));
    }
    if ($table === 'raw') {
        return $chain === 'PREROUTING' && $target === 'CT';
    }

    return $table === 'filter' && $chain === 'FORWARD' && $target === 'ACCEPT';
}

/** nft rule text without the handle comment and counter values, single-spaced. PURE. */
function nexovirt_nat_nft_norm(string $s): string
{
    $s = (string) preg_replace('/\s*#\s*handle\s+\d+\s*$/', '', trim($s));
    $s = (string) preg_replace('/\bcounter\s+packets\s+\d+\s+bytes\s+\d+/', 'counter', $s);

    return trim((string) preg_replace('/\s+/', ' ', $s));
}

function nexovirt_nat_nft_name(string $s): bool
{
    return preg_match('/^[A-Za-z0-9_.-]{1,64}$/', $s) === 1;
}

/**
 * Validate a finalize/restore payload. Returns ['ok'=>bool,'error'=>string,'rules'=>..., 'chains'=>...,
 * 'files'=>..., 'units'=>...] with the parsed rules. $allowedFiles: path => kind; $allowedUnits: names.
 */
function nexovirt_nat_adopt_validate(array $p, array $allowedFiles, array $allowedUnits, bool $restore): array
{
    $bad = static function (string $why): array {
        return ['ok' => false, 'error' => 'invalid NAT adoption payload: ' . $why];
    };
    foreach (['rules', 'chains', 'files', 'units', 'require'] as $k) {
        if (isset($p[$k]) && ! is_array($p[$k])) {
            return $bad($k);
        }
    }
    // NexoVirt's own replacement rules that must be live before anything is switched off (compared as text only).
    $require = [];
    foreach (array_values((array) ($p['require'] ?? [])) as $i => $line) {
        $line = is_string($line) ? trim((string) preg_replace('/^\[\d+:\d+\]\s+/', '', trim($line))) : '';
        if ($i >= NAT_ADOPT_MAX_RULES || ! nexovirt_nat_printable($line) || preg_match('/^-A NEXOVIRT-(PRE|POST|FWD) /', $line) !== 1) {
            return $bad('require');
        }
        $require[] = $line;
    }
    $rules = [];
    foreach (array_values((array) ($p['rules'] ?? [])) as $i => $r) {
        if ($i >= NAT_ADOPT_MAX_RULES || ! is_array($r)) {
            return $bad('rules');
        }
        $count = (int) ($r['count'] ?? 1);
        if ($count < 1 || $count > NAT_ADOPT_MAX_COUNT) {
            return $bad('rule count');
        }
        if (($r['kind'] ?? '') === 'ipt') {
            $table = (string) ($r['table'] ?? '');
            $rule  = nexovirt_nat_rule_args((string) ($r['line'] ?? ''));
            if (! in_array($table, ['nat', 'raw', 'filter'], true) || $rule === null || ! nexovirt_nat_adopt_scope_ok($table, $rule)) {
                return $bad('iptables rule ' . $i);
            }
            $rules[] = ['kind' => 'ipt', 'table' => $table, 'rule' => $rule, 'line' => (string) $r['line'], 'count' => $count];
        } elseif (($r['kind'] ?? '') === 'nft') {
            $body = nexovirt_nat_nft_norm((string) ($r['body'] ?? ''));
            if (! in_array($r['family'] ?? '', ['ip', 'inet'], true) || ! nexovirt_nat_nft_name((string) ($r['table'] ?? '')) || ! nexovirt_nat_nft_name((string) ($r['chain'] ?? ''))
                || ! is_int($r['handle'] ?? null) || $r['handle'] < 1 || ! nexovirt_nat_printable($body) || preg_match('/[;{}#\\\\]/', $body) === 1
                || preg_match('/\b(masquerade|snat|dnat)\b/', $body) !== 1
                || strpos((string) $r['table'], 'proxmox') !== false || strpos((string) $r['chain'], 'NEXOVIRT-') === 0) {
                return $bad('nft rule ' . $i);
            }
            $rules[] = ['kind' => 'nft', 'family' => $r['family'], 'table' => (string) $r['table'], 'chain' => (string) $r['chain'], 'handle' => $r['handle'], 'body' => $body, 'count' => 1];
        } else {
            return $bad('rule kind');
        }
    }
    $chains = [];
    foreach (array_values((array) ($p['chains'] ?? [])) as $i => $c) {
        $name = (string) ($c['chain'] ?? '');
        $jump = nexovirt_nat_rule_args((string) ($c['jump'] ?? ''));
        if ($i >= NAT_ADOPT_MAX_CHAINS || ($c['table'] ?? '') !== 'nat' || ! nexovirt_nat_user_chain($name) || $jump === null
            || $jump['chain'] !== 'PREROUTING' || nexovirt_nat_rule_target($jump) !== $name || ! is_array($c['rules'] ?? null) || $c['rules'] === [] || count($c['rules']) > NAT_ADOPT_MAX_RULES) {
            return $bad('chain ' . $i);
        }
        $lines = [];
        foreach ($c['rules'] as $line) {
            $rule = nexovirt_nat_rule_args((string) $line);
            if ($rule === null || $rule['chain'] !== $name || nexovirt_nat_rule_target($rule) !== 'DNAT') {
                return $bad('chain rule of ' . $name);
            }
            $lines[] = ['line' => (string) $line, 'rule' => $rule];
        }
        $chains[] = ['chain' => $name, 'jump' => $jump, 'jump_line' => (string) $c['jump'], 'rules' => $lines];
    }
    $files = [];
    foreach (array_values((array) ($p['files'] ?? [])) as $i => $f) {
        $path = (string) ($f['path'] ?? '');
        if ($i >= NAT_ADOPT_MAX_FILES || ! isset($allowedFiles[$path])) {
            return $bad('file ' . $path);
        }
        if ($restore) {
            $backup = (string) ($f['backup'] ?? '');
            $stamp  = substr($backup, -15);
            if (! in_array($backup, [nexovirt_nat_backup_path($path, $stamp), $path . '.nexovirt-adopted-' . $stamp], true) || preg_match('/^\d{8}-\d{6}$/', $stamp) !== 1
                || preg_match('/^[0-9a-f]{64}$/', (string) ($f['sha256'] ?? '')) !== 1) {
                return $bad('backup of ' . $path);
            }
            $files[] = ['path' => $path, 'backup' => $backup, 'sha256' => (string) $f['sha256']];
            continue;
        }
        $mode = $allowedFiles[$path] === 'rules_v4' ? 'remove' : 'comment';
        if (($f['mode'] ?? '') !== $mode || ! is_array($f['lines'] ?? null) || $f['lines'] === [] || count($f['lines']) > NAT_SOURCE_MAX_LINES) {
            return $bad('lines of ' . $path);
        }
        $lines = [];
        foreach ($f['lines'] as $l) {
            $n    = $l['n'] ?? null;
            $text = (string) ($l['text'] ?? '');
            if (! is_int($n) || $n < 1 || $text === '' || strpbrk($text, "\r\n\0") !== false || strlen($text) > 4096) {
                return $bad('line of ' . $path);
            }
            $lines[$n] = $text;
        }
        $files[] = ['path' => $path, 'mode' => $mode, 'lines' => $lines];
    }
    $units = [];
    foreach (array_values((array) ($p['units'] ?? [])) as $i => $u) {
        if ($i >= NAT_ADOPT_MAX_UNITS || ! is_string($u) || preg_match('/^[A-Za-z0-9@._-]{1,100}\.service$/', $u) !== 1 || ! in_array($u, $allowedUnits, true)) {
            return $bad('unit');
        }
        $units[] = $u;
    }

    return ['ok' => true, 'error' => '', 'rules' => $rules, 'chains' => $chains, 'files' => $files, 'units' => $units, 'require' => $require];
}

/**
 * The source lines a switch-off may edit, from this agent's own scan: path => [n => text]. interfaces:
 * hook lines running iptables/nft or a NAT script; rules.v4: `-A` lines inside the switch-off scope of
 * their table; nftables: single rule lines with a NAT statement (never a table/chain/brace line).
 *
 * @return array<string,array<int,string>>
 */
function nexovirt_nat_adopt_scanned_lines(string $root): array
{
    $out = [];
    foreach (nexovirt_nat_sources($root) as $src) {
        $table = '';
        if ($src['kind'] === 'rules_v4') {
            $body = (string) @file_get_contents($root . $src['path']);
            foreach (preg_split('/\r?\n/', nexovirt_cap_output($body, NAT_INVENTORY_CAP)) ?: [] as $i => $text) {
                if (preg_match('/^\*(\w+)/', $text, $m) === 1) {
                    $table = $m[1];
                    continue;
                }
                $rule = nexovirt_nat_rule_args($text);
                if ($rule !== null && nexovirt_nat_adopt_scope_ok($table, $rule)) {
                    $out[$src['path']][$i + 1] = $text;
                }
            }
            continue;
        }
        foreach ($src['lines'] as $l) {
            if ($src['kind'] === 'interfaces'
                || (strpbrk($l['text'], '{}') === false && preg_match('/^\s*(table|chain)\b/', $l['text']) !== 1 && preg_match('/\b(masquerade|snat|dnat)\b/', $l['text']) === 1)) {
                $out[$src['path']][$l['n']] = $l['text'];
            }
        }
    }
    foreach (nexovirt_nat_script_sources($root) as $sc) {
        if ($sc['kind'] === 'interfaces') {
            $out[$sc['path']][$sc['n']] = $sc['text'];
        }
    }

    return $out;
}

/** The default command runner: [exit code, output]. */
function nexovirt_nat_adopt_exec(string $cmd): array
{
    $out  = [];
    $code = 0;
    exec($cmd . ' 2>&1', $out, $code);

    return [$code, implode("\n", $out)];
}

/**
 * Backup next to the file, as a dot file: `source /etc/network/interfaces.d/*` and nft `include "dir/*"`
 * wildcards skip it, so a backup never brings the old rules (or a second iface stanza) back at boot. PURE.
 */
function nexovirt_nat_backup_path(string $path, string $stamp): string
{
    return dirname($path) . '/.' . basename($path) . '.nexovirt-adopted-' . $stamp;
}

/** Create $file with $content; fails when anything (a file or a symlink, even a dangling one) is already there. */
function nexovirt_nat_write_new(string $file, string $content, int $mode = 0600): bool
{
    // PHP's 'x' resolves a dangling symlink and creates its target, so refuse any existing entry first.
    $h = is_link($file) || file_exists($file) ? false : @fopen($file, 'x');
    if ($h === false) {
        return false;
    }
    $ok = @fwrite($h, $content) === strlen($content) && @fflush($h);
    @fclose($h);
    @chmod($file, $mode);
    if (! $ok) {
        @unlink($file);
    }

    return $ok;
}

/** Atomic write (tmp + rename on the same filesystem) keeping mode and owner; a symlinked file is written at its target. */
function nexovirt_nat_atomic_write(string $file, string $content): bool
{
    if (is_link($file)) {
        $file = realpath($file);
        if ($file === false) {
            return false;
        }
    }
    $tmp = dirname($file) . '/.' . basename($file) . '.nexovirt-tmp-' . getmypid() . '-' . bin2hex(random_bytes(4)); // hidden from wildcard includes
    $st  = @stat($file);
    if (! nexovirt_nat_write_new($tmp, $content, $st !== false ? $st['mode'] & 0777 : 0644)) {
        @unlink($tmp);

        return false;
    }
    if ($st !== false) {
        @chown($tmp, $st['uid']);
        @chgrp($tmp, $st['gid']);
    }
    if (! @rename($tmp, $file)) {
        @unlink($tmp);

        return false;
    }

    return true;
}

/** Remove the live rules of a finalize payload. @return list<array<string,mixed>> per rule */
function nexovirt_nat_adopt_remove_rules(array $rules, callable $run): array
{
    $report = [];
    foreach ($rules as $r) {
        if ($r['kind'] === 'ipt') {
            $removed = 0;
            $status  = 'removed';
            $detail  = '';
            for ($i = 0; $i < $r['count']; $i++) {
                if ($run(nexovirt_nat_rule_cmd('-C', $r['table'], $r['rule']))[0] !== 0) {
                    $status = $removed > 0 ? 'removed' : 'missing';
                    $detail = $removed > 0 ? '' : 'The rule no longer matches exactly on the node; it was not touched.';
                    break;
                }
                [$code, $out] = $run(nexovirt_nat_rule_cmd('-D', $r['table'], $r['rule']));
                if ($code !== 0) {
                    $status = 'failed';
                    $detail = trim($out);
                    break;
                }
                $removed++;
            }
            $report[] = ['kind' => 'ipt', 'table' => $r['table'], 'line' => $r['line'], 'status' => $status, 'removed' => $removed, 'detail' => $detail];
            continue;
        }
        $where = escapeshellarg($r['family']) . ' ' . escapeshellarg($r['table']) . ' ' . escapeshellarg($r['chain']);
        [$code, $list] = $run('nft -a list chain ' . $where);
        $match = false;
        foreach (preg_split('/\r?\n/', $list) ?: [] as $line) {
            if (preg_match('/#\s*handle\s+' . $r['handle'] . '\s*$/', $line) === 1 && nexovirt_nat_nft_norm($line) === $r['body']) {
                $match = true;
            }
        }
        $row = ['kind' => 'nft', 'family' => $r['family'], 'table' => $r['table'], 'chain' => $r['chain'], 'handle' => $r['handle'], 'body' => $r['body'], 'removed' => 0];
        if ($code !== 0 || ! $match) {
            $report[] = $row + ['status' => 'missing', 'detail' => 'The rule no longer matches exactly on the node; it was not touched.'];
            continue;
        }
        [$code, $out] = $run('nft delete rule ' . $where . ' handle ' . escapeshellarg((string) $r['handle']));
        $report[] = $row + ($code === 0 ? ['status' => 'removed', 'removed' => 1, 'detail' => ''] : ['status' => 'failed', 'detail' => trim($out)]);
    }

    return $report;
}

/** Live rules of one iptables chain in iptables-save form, counters dropped. @return list<string> */
function nexovirt_nat_chain_lines(string $save, string $chain): array
{
    $out = [];
    foreach (preg_split('/\r?\n/', $save) ?: [] as $line) {
        $line = trim((string) preg_replace('/^\[\d+:\d+\]\s+/', '', trim($line)));
        if (strpos($line, '-A ' . $chain . ' ') === 0) {
            $out[] = $line;
        }
    }

    return $out;
}

/** Every live rule that jumps/gotos $target, normalized to iptables-save text. @return list<string> */
function nexovirt_nat_chain_references(string $save, string $target): array
{
    $out = [];
    $re  = '/(^|\s)(-j|--jump|-g|--goto)\s+["\']?' . preg_quote($target, '/') . '["\']?(\s|$)/';
    foreach (preg_split('/\r?\n/', $save) ?: [] as $line) {
        $line = trim((string) preg_replace('/^\[\d+:\d+\]\s+/', '', trim($line)));
        // Text match, not the parser: a line the parser refuses still references the chain.
        if (strpos($line, '-A ') === 0 && preg_match($re, $line) === 1) {
            $out[] = $line;
        }
    }

    return $out;
}

/** Remove fully adopted user chains: jump first, then flush + delete that one chain. */
function nexovirt_nat_adopt_remove_chains(array $chains, callable $run): array
{
    $report = [];
    foreach ($chains as $c) {
        $row = ['chain' => $c['chain'], 'jump' => $c['jump_line'], 'rules' => array_column($c['rules'], 'line')];
        [$code, $save] = $run('iptables-save -t nat');
        $stored = array_map(static function (array $r): string {
            return trim((string) preg_replace('/^\[\d+:\d+\]\s+/', '', $r['line']));
        }, $c['rules']);
        $live = nexovirt_nat_chain_lines($save, $c['chain']);
        $jumpLine = trim((string) preg_replace('/^\[\d+:\d+\]\s+/', '', $c['jump_line']));
        $refs = nexovirt_nat_chain_references($save, $c['chain']);
        if ($code !== 0 || $live !== $stored || $refs !== [$jumpLine] || $run(nexovirt_nat_rule_cmd('-C', 'nat', $c['jump']))[0] !== 0) {
            $report[] = $row + ['status' => 'missing', 'detail' => 'The chain or its jump changed on the node; nothing in it was touched.'];
            continue;
        }
        $name = escapeshellarg($c['chain']);
        $steps = [['jump', nexovirt_nat_rule_cmd('-D', 'nat', $c['jump'])], ['flush', 'iptables -w -t nat -F ' . $name], ['delete', 'iptables -w -t nat -X ' . $name]];
        $done = [];
        foreach ($steps as [$step, $cmd]) {
            [$code, $out] = $run($cmd);
            if ($code !== 0) {
                $report[] = $row + ['status' => 'failed', 'changed' => $done !== [], 'steps' => $done, 'detail' => trim($out)];
                continue 2;
            }
            $done[] = $step;
        }
        $report[] = $row + ['status' => 'removed', 'changed' => true, 'steps' => $done, 'detail' => ''];
    }

    return $report;
}

/** Comment out / drop the named lines of each file, with a backup first. */
function nexovirt_nat_adopt_edit_files(array $files, string $root, string $stamp, string $date, array $scanned): array
{
    $report = [];
    foreach ($files as $f) {
        $real = $root . $f['path'];
        $row  = ['path' => $f['path'], 'mode' => $f['mode'], 'lines' => array_keys($f['lines'])];
        $body = @file_get_contents($real);
        if (! is_string($body)) {
            $report[] = $row + ['status' => 'failed', 'detail' => 'The file cannot be read.'];
            continue;
        }
        $lines   = explode("\n", $body);
        $changed = [];
        foreach ($f['lines'] as $n => $text) {
            // Only a line this agent's own scan lists as a NAT rule / NAT script hook of this file.
            if (($lines[$n - 1] ?? null) !== $text || ($scanned[$f['path']][$n] ?? null) !== $text) {
                $changed[] = $n;
            }
        }
        if ($changed !== []) {
            $report[] = $row + ['status' => 'changed', 'detail' => 'Line ' . implode(', ', $changed) . ' no longer reads as scanned (or is not a NAT rule line); the file was not edited.'];
            continue;
        }
        $backup = nexovirt_nat_backup_path($f['path'], $stamp);
        if (! nexovirt_nat_write_new($root . $backup, $body)) {
            $report[] = $row + ['status' => 'failed', 'detail' => 'The backup ' . $backup . ' could not be written; the file was not edited.'];
            continue;
        }
        foreach ($f['lines'] as $n => $text) {
            if ($f['mode'] === 'remove') {
                $lines[$n - 1] = null;
            } else {
                preg_match('/^\s*/', $text, $ws);
                $lines[$n - 1] = $ws[0] . '# nexovirt-adopted ' . $date . ': ' . ltrim($text);
            }
        }
        $new = implode("\n", array_filter($lines, static function ($l): bool {
            return $l !== null;
        }));
        if (! nexovirt_nat_atomic_write($real, $new)) {
            $report[] = $row + ['status' => 'failed', 'backup' => $backup, 'detail' => 'The file could not be written; it is unchanged.'];
            continue;
        }
        $report[] = $row + ['status' => 'edited', 'backup' => $backup, 'sha256' => hash('sha256', $new), 'detail' => ''];
    }

    return $report;
}

/**
 * nat_adopt_finalize: switch the adopted original rules off. Payload {rules, chains, files, units}.
 * Live removal first; files and units only when no live removal failed. Returns ['ok'=>bool,
 * 'result'=>report|error]. The report ends with a fresh read of the rule sets ('after').
 */
function nexovirt_nat_adopt_finalize(array $p, string $root = '', ?callable $run = null, ?int $now = null): array
{
    $run   = $run ?? 'nexovirt_nat_adopt_exec';
    $now   = $now ?? time();
    $files = [];
    foreach (nexovirt_nat_sources($root) as $s) {
        $files[$s['path']] = $s['kind'];
    }
    $units = array_column(array_filter(nexovirt_nat_script_sources($root), static function (array $s): bool {
        return $s['kind'] === 'systemd';
    }), 'unit');
    $v = nexovirt_nat_adopt_validate($p, $files, $units, false);
    if (! $v['ok']) {
        return ['ok' => false, 'result' => $v['error']];
    }
    if ($v['require'] !== []) {
        [$code, $save] = $run('iptables-save -t nat');
        $live = array_flip(array_map(static function (string $l): string {
            return trim((string) preg_replace('/^\[\d+:\d+\]\s+/', '', trim($l)));
        }, preg_split('/\r?\n/', (string) $save) ?: []));
        $missing = array_values(array_filter($v['require'], static function (string $l) use ($live): bool {
            return ! isset($live[$l]);
        }));
        if ($code !== 0 || $missing !== []) {
            return ['ok' => false, 'result' => 'NexoVirt\'s replacement rules are not all active on the node' . ($missing !== [] ? ' (missing: ' . $missing[0] . ')' : '')
                . '; nothing was switched off. Apply the NAT settings again, then retry.'];
        }
    }
    $report = ['stamp' => gmdate('Ymd-His', $now)];
    $report['chains'] = nexovirt_nat_adopt_remove_chains($v['chains'], $run);
    $report['rules']  = nexovirt_nat_adopt_remove_rules($v['rules'], $run);
    $failed = in_array('failed', array_merge(array_column($report['rules'], 'status'), array_column($report['chains'], 'status')), true);
    $report['files'] = [];
    $report['units'] = [];
    if ($failed) {
        foreach ($v['files'] as $f) {
            $report['files'][] = ['path' => $f['path'], 'mode' => $f['mode'], 'lines' => array_keys($f['lines']), 'status' => 'skipped', 'detail' => 'A live rule could not be removed, so no file was edited.'];
        }
        foreach ($v['units'] as $u) {
            $report['units'][] = ['unit' => $u, 'status' => 'skipped', 'detail' => 'A live rule could not be removed.'];
        }
    } else {
        $report['files'] = nexovirt_nat_adopt_edit_files($v['files'], $root, $report['stamp'], gmdate('Y-m-d', $now), nexovirt_nat_adopt_scanned_lines($root));
        foreach ($v['units'] as $u) {
            [, $state] = $run('systemctl is-enabled ' . escapeshellarg($u));
            if (trim($state) !== 'enabled') {
                $report['units'][] = ['unit' => $u, 'status' => 'not_enabled', 'detail' => 'The unit was not enabled; it was left as is.'];
                continue;
            }
            [$code, $out] = $run('systemctl disable ' . escapeshellarg($u));
            $report['units'][] = ['unit' => $u, 'status' => $code === 0 ? 'disabled' : 'failed', 'detail' => $code === 0 ? '' : trim($out)];
        }
    }
    $report['after'] = nexovirt_nat_adopt_read_after($run);
    $statuses = array_merge(array_column($report['rules'], 'status'), array_column($report['chains'], 'status'),
        array_column($report['files'], 'status'), array_column($report['units'], 'status'));
    $report['complete'] = array_diff($statuses, ['removed', 'missing', 'edited', 'disabled', 'not_enabled']) === [];

    return ['ok' => true, 'result' => $report];
}

/** A fresh read of the rule sets after a switch-off / restore (nat, raw, filter + nft). */
function nexovirt_nat_adopt_read_after(callable $run): array
{
    $ipt = '';
    $ok  = true;
    foreach (['nat', 'raw', 'filter'] as $t) {
        [$code, $out] = $run('iptables-save -t ' . $t);
        $ok = $ok && $code === 0;
        $ipt .= $out . "\n";
    }
    [$code, $nft] = $run('nft -a list ruleset');
    $ok = $ok && $code === 0;

    return ['ok' => $ok, 'iptables' => nexovirt_cap_output($ipt, NAT_INVENTORY_CAP), 'nft' => $code === 0 ? nexovirt_cap_output($nft, NAT_INVENTORY_CAP) : ''];
}

/**
 * nat_adopt_restore: put the original rules back. Payload {rules, chains, files: [{path, backup,
 * sha256}], units}. A file is restored from its backup only while it still holds exactly what the
 * switch-off wrote (sha256); live rules are re-added only when absent (idempotent).
 */
function nexovirt_nat_adopt_restore(array $p, string $root = '', ?callable $run = null): array
{
    $run   = $run ?? 'nexovirt_nat_adopt_exec';
    $files = [];
    foreach (nexovirt_nat_sources($root) as $s) {
        $files[$s['path']] = $s['kind'];
    }
    $units = array_column(array_filter(nexovirt_nat_script_sources($root), static function (array $s): bool {
        return $s['kind'] === 'systemd';
    }), 'unit');
    $v = nexovirt_nat_adopt_validate($p, $files, $units, true);
    if (! $v['ok']) {
        return ['ok' => false, 'result' => $v['error']];
    }
    $report = ['files' => [], 'chains' => [], 'rules' => [], 'units' => []];
    foreach ($v['files'] as $f) {
        $real = $root . $f['path'];
        $now  = @file_get_contents($real);
        $orig = @file_get_contents($root . $f['backup']);
        if (! is_string($orig)) {
            $report['files'][] = ['path' => $f['path'], 'status' => 'failed', 'detail' => 'The backup ' . $f['backup'] . ' is missing.'];
        } elseif (is_string($now) && hash_equals(hash('sha256', $orig), hash('sha256', $now))) {
            $report['files'][] = ['path' => $f['path'], 'status' => 'present', 'detail' => ''];
        } elseif (! is_string($now) || hash('sha256', $now) !== $f['sha256']) {
            $report['files'][] = ['path' => $f['path'], 'status' => 'changed', 'detail' => 'The file was edited after the switch-off; it was not restored. The backup is ' . $f['backup'] . '.'];
        } else {
            $ok = nexovirt_nat_atomic_write($real, $orig);
            $report['files'][] = ['path' => $f['path'], 'status' => $ok ? 'restored' : 'failed', 'detail' => $ok ? '' : 'The file could not be written.'];
        }
    }
    foreach ($v['chains'] as $c) {
        $name = escapeshellarg($c['chain']);
        [$saveCode, $save] = $run('iptables-save -t nat');
        $declared = preg_match('/^:' . preg_quote($c['chain'], '/') . '\s/m', $save) === 1;
        $wanted = array_map(static function (array $r): string {
            return trim((string) preg_replace('/^\[\d+:\d+\]\s+/', '', $r['line']));
        }, $c['rules']);
        $live = nexovirt_nat_chain_lines($save, $c['chain']);
        $wantedCounts = array_count_values($wanted);
        $liveCounts = array_count_values($live);
        $foreign = array_filter($liveCounts, static function (int $count, string $line) use ($wantedCounts): bool {
            return $count > ($wantedCounts[$line] ?? 0);
        }, ARRAY_FILTER_USE_BOTH);
        if ($saveCode !== 0 || $foreign !== []) {
            $report['chains'][] = ['chain' => $c['chain'], 'status' => 'changed', 'detail' => 'A chain with this name has foreign rules; it was not touched.'];
            continue;
        }
        $ok = true;
        if (! $declared && $run('iptables -w -t nat -N ' . $name)[0] !== 0) {
            $ok = false;
        }
        foreach ($c['rules'] as $i => $storedRule) {
            $line = $wanted[$i];
            if (($liveCounts[$line] ?? 0) > 0) {
                $liveCounts[$line]--;
                continue;
            }
            if ($run(nexovirt_nat_rule_cmd('-A', 'nat', $storedRule['rule']))[0] !== 0) {
                $ok = false;
            }
        }
        if ($ok && $run(nexovirt_nat_rule_cmd('-C', 'nat', $c['jump']))[0] !== 0 && $run(nexovirt_nat_rule_cmd('-A', 'nat', $c['jump']))[0] !== 0) {
            $ok = false;
        }
        $report['chains'][] = ['chain' => $c['chain'], 'status' => $ok ? ($declared && $live === $wanted ? 'present' : 'restored') : 'failed', 'detail' => ''];
    }
    foreach ($v['rules'] as $r) {
        if ($r['kind'] === 'ipt') {
            if ($r['count'] === 1) {
                $present = $run(nexovirt_nat_rule_cmd('-C', $r['table'], $r['rule']))[0] === 0 ? 1 : 0;
            } else {
                [, $save] = $run('iptables-save -t ' . escapeshellarg($r['table']));
                $needle = trim((string) preg_replace('/^\[\d+:\d+\]\s+/', '', trim($r['line'])));
                $present = count(array_filter(preg_split('/\r?\n/', $save) ?: [], static function (string $line) use ($needle): bool {
                    return trim((string) preg_replace('/^\[\d+:\d+\]\s+/', '', trim($line))) === $needle;
                }));
            }
            $code = 0;
            $out = '';
            for ($i = $present; $i < $r['count']; $i++) {
                [$code, $out] = $run(nexovirt_nat_rule_cmd('-A', $r['table'], $r['rule']));
                if ($code !== 0) {
                    break;
                }
            }
            $report['rules'][] = ['line' => $r['line'], 'status' => $code === 0 ? ($present >= $r['count'] ? 'present' : 'restored') : 'failed', 'restored' => max(0, $i - $present), 'detail' => trim($out)];
            continue;
        }
        $where = escapeshellarg($r['family']) . ' ' . escapeshellarg($r['table']) . ' ' . escapeshellarg($r['chain']);
        [$listCode, $list] = $run('nft -a list chain ' . $where);
        $present = false;
        if ($listCode === 0) {
            foreach (preg_split('/\r?\n/', $list) ?: [] as $line) {
                if (nexovirt_nat_nft_norm($line) === $r['body']) {
                    $present = true;
                    break;
                }
            }
        }
        if ($present) {
            $report['rules'][] = ['body' => $r['body'], 'status' => 'present', 'detail' => ''];
            continue;
        }
        $cmd = 'nft ' . escapeshellarg('add rule ' . $r['family'] . ' ' . $r['table'] . ' ' . $r['chain'] . ' ' . $r['body']);
        [$code, $out] = $run($cmd);
        $report['rules'][] = ['body' => $r['body'], 'status' => $code === 0 ? 'restored' : 'failed', 'detail' => trim($out)];
    }
    foreach ($v['units'] as $u) {
        [$code, $out] = $run('systemctl enable ' . escapeshellarg($u));
        $report['units'][] = ['unit' => $u, 'status' => $code === 0 ? 'enabled' : 'failed', 'detail' => $code === 0 ? '' : trim($out)];
    }
    $report['after'] = nexovirt_nat_adopt_read_after($run);
    $flat = array_merge(...array_map(static function (string $k) use ($report): array {
        return array_column($report[$k], 'status');
    }, ['files', 'chains', 'rules', 'units']));

    return ['ok' => true, 'result' => $report + ['complete' => ! in_array('failed', $flat, true) && ! in_array('changed', $flat, true) && ! empty($report['after']['ok'])]];
}

/** DRYRUN runner for the dispatcher: records nothing, every check passes, saves come from the fake env. */
function nexovirt_nat_adopt_dry_runner(): callable
{
    return static function (string $cmd): array {
        if (strpos($cmd, 'iptables-save') === 0) {
            return [0, (string) getenv('NEXOVIRT_AGENT_FAKE_IPT_NAT')];
        }
        if (strpos($cmd, 'nft -a list') === 0) {
            return [0, (string) getenv('NEXOVIRT_AGENT_FAKE_NFT')];
        }

        return [0, strpos($cmd, 'systemctl is-enabled') === 0 ? 'enabled' : ''];
    };
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

    // Never add NexoVirt NAT next to NAT the node already has, unless the admin explicitly allowed it.
    if (empty($config['allow_foreign'])) {
        $sets = nexovirt_nat_read_rulesets();
        if (! $sets['ok']) {
            return ['ok' => false, 'error' => $sets['error']];
        }
        $own     = array_values(array_filter((array) ($config['allowed_dest_cidrs'] ?? []), 'is_string'));
        $foreign = nexovirt_nat_foreign_rules($sets['ipt'], $sets['nft'], $own);
        if ($foreign !== []) {
            return ['ok' => false, 'error' => 'the node already has NAT rules NexoVirt did not create; NAT not changed: ' . implode(' | ', array_slice($foreign, 0, 5))];
        }
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
        return ['tools' => $stub, 'dhcp' => nexovirt_dhcp_read((string) getenv('NEXOVIRT_AGENT_ETC_ROOT'), nexovirt_node_dry_runner())];
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

    // DHCP pools + UDP 67 listeners (read-only): IP zone overlap warnings and the NAT DHCP conflict view.
    return ['tools' => $tools, 'dhcp' => nexovirt_dhcp_read('', nexovirt_node_runner())];
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
    // The NexoVirt VPN routes its clients to the guests: forwarding off would cut every VPN client off.
    if (! $enabled && (is_file(WG_UNIT_PATH) || is_file(WG_SYSCTL_PATH))) {
        return ['ok' => false, 'result' => 'The NexoVirt VPN is active on this host and requires IPv4 forwarding; turn the VPN off first'];
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

// ---------------------------------------------------------------------------
// DHCP on NAT networks (apply_dhcp) + DHCP pool discovery (read_firewall `dhcp`) + the fail2ban jail
// for the Proxmox web UI (apply_fail2ban, read_fail2ban, fail2ban_unban). Agent 0.25.0, fail2ban fixes 0.25.1.
//
// SAFETY CONTRACT: NexoVirt's dnsmasq instances use ONLY their own files (/etc/nexovirt-dhcp/<bridge>.conf
// loaded with -C, so /etc/dnsmasq.conf and /etc/dnsmasq.d are never read or written), their own unit
// template, lease and pid files. A bridge where another DHCP server already listens or is configured is
// refused. The fail2ban jail writes ONLY its two nexovirt-pve.conf files and never starts an admin's
// stopped fail2ban. Every payload field is validated fail-closed before anything is touched; every
// interpolated value is escapeshellarg'd. All paths take a $root prefix (the DRYRUN test seam).
// ---------------------------------------------------------------------------

const DHCP_DIR              = '/etc/nexovirt-dhcp';
const DHCP_LEASE_DIR        = '/var/lib/nexovirt-dhcp';
const DHCP_UNIT_PATH        = '/etc/systemd/system/nexovirt-dhcp@.service';
const DHCP_MAX_INSTANCES    = 16;
const DHCP_MAX_RESERVATIONS = 1024;
const DHCP_LEASE_TIME       = '12h';
const F2B_JAIL              = 'nexovirt-pve';
const F2B_JAIL_PATH         = '/etc/fail2ban/jail.d/nexovirt-pve.conf';
const F2B_FILTER_PATH       = '/etc/fail2ban/filter.d/nexovirt-pve.conf';
const F2B_MAX_IGNORE        = 32;
const F2B_ACCESS_LOG        = '/var/log/pveproxy/access.log';

/** Real command runner: [exit code, combined output]. apt-get runs with busy heartbeats ($tick) so the agent never looks stale. */
function nexovirt_node_runner(?callable $tick = null): callable
{
    return static function (string $cmd) use ($tick): array {
        if ($tick !== null && str_contains($cmd, 'apt-get')) {
            $r = nexovirt_run_with_ticks($cmd . ' 2>&1', $tick, 20);

            return [$r['code'], $r['out']];
        }

        return nexovirt_nat_adopt_exec($cmd);
    };
}

/**
 * DRYRUN runner: never executes anything. Outputs come from NEXOVIRT_AGENT_FAKE_CMDS, a JSON object of
 * command prefix => [code, output]; anything else answers [0, ''].
 */
function nexovirt_node_dry_runner(): callable
{
    $fakes = json_decode((string) getenv('NEXOVIRT_AGENT_FAKE_CMDS'), true);
    $fakes = is_array($fakes) ? $fakes : [];

    return static function (string $cmd) use ($fakes): array {
        foreach ($fakes as $prefix => $answer) {
            if (strpos($cmd, (string) $prefix) === 0 && is_array($answer)) {
                return [(int) ($answer[0] ?? 0), (string) ($answer[1] ?? '')];
            }
        }

        return [0, ''];
    };
}

/** [root, runner] for a job: the real node, or the DRYRUN seam. */
function nexovirt_node_ctx(array $config = []): array
{
    $tick = isset($config['busyTick']) && is_callable($config['busyTick']) ? $config['busyTick'] : null;

    return getenv('NEXOVIRT_AGENT_DRYRUN') === '1'
        ? [(string) getenv('NEXOVIRT_AGENT_ETC_ROOT'), nexovirt_node_dry_runner()]
        : ['', nexovirt_node_runner($tick)];
}

/** IPv4 dotted quad -> unsigned int, or null. PURE. */
function nexovirt_ip4_long(string $ip): ?int
{
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        return null;
    }

    return ip2long($ip) & 0xFFFFFFFF;
}

/** [network, broadcast, netmask] of a valid IPv4 CIDR. PURE. @return array{0:int,1:int,2:string} */
function nexovirt_dhcp_net(string $cidr): array
{
    [$net, $bits] = explode('/', $cidr, 2);
    $prefix = (int) $bits;
    $mask   = $prefix === 0 ? 0 : ((0xFFFFFFFF << (32 - $prefix)) & 0xFFFFFFFF);
    $first  = (ip2long($net) & 0xFFFFFFFF) & $mask;

    return [$first, $first | (~$mask & 0xFFFFFFFF), long2ip($mask)];
}

/** Bridge name for a NexoVirt DHCP instance (also a systemd instance name): starts alphanumeric. PURE. */
function nexovirt_dhcp_valid_bridge(string $b): bool
{
    return nexovirt_validate_iface($b) && ctype_alnum($b[0]);
}

/**
 * Validate an apply_dhcp payload (fail-closed: one bad field refuses the whole job). PURE.
 *
 * @return array{ok:bool,error:string,instances:list<array<string,mixed>>}
 */
function nexovirt_dhcp_validate(array $p): array
{
    $bad  = static fn (string $e): array => ['ok' => false, 'error' => $e, 'instances' => []];
    $list = $p['instances'] ?? null;
    if (! is_array($list) || array_values($list) !== $list || count($list) > DHCP_MAX_INSTANCES) {
        return $bad('instances must be a list of at most ' . DHCP_MAX_INSTANCES);
    }
    $out     = [];
    $bridges = [];
    foreach ($list as $i => $in) {
        if (! is_array($in)) {
            return $bad("instance {$i}: not an object");
        }
        $bridge = (string) ($in['bridge'] ?? '');
        $cidr   = (string) ($in['cidr'] ?? '');
        if (! nexovirt_dhcp_valid_bridge($bridge) || isset($bridges[$bridge])) {
            return $bad("instance {$i}: invalid or duplicate bridge");
        }
        $bridges[$bridge] = true;
        if (! nexovirt_validate_nat_cidr($cidr) || (int) explode('/', $cidr)[1] < 16 || (int) explode('/', $cidr)[1] > 30) {
            return $bad("instance {$i}: cidr must be a private /16../30");
        }
        [$net, $bcast, $mask] = nexovirt_dhcp_net($cidr);
        $usable = static function ($ip) use ($net, $bcast): ?int {
            $l = is_string($ip) ? nexovirt_ip4_long($ip) : null;

            return $l !== null && $l > $net && $l < $bcast ? $l : null;
        };
        $gw    = $usable($in['gateway'] ?? null);
        $start = $usable($in['range_start'] ?? null);
        $end   = $usable($in['range_end'] ?? null);
        if ($gw === null || $start === null || $end === null || $start > $end || ($gw >= $start && $gw <= $end)) {
            return $bad("instance {$i}: gateway and range must be usable addresses of {$cidr}, gateway outside the range");
        }
        $dns = $in['dns'] ?? [];
        if (! is_array($dns) || count($dns) > 3) {
            return $bad("instance {$i}: at most 3 dns servers");
        }
        foreach ($dns as $d) {
            if (! is_string($d) || nexovirt_ip4_long($d) === null) {
                return $bad("instance {$i}: invalid dns server");
            }
        }
        $res = $in['reservations'] ?? [];
        if (! is_array($res) || count($res) > DHCP_MAX_RESERVATIONS) {
            return $bad("instance {$i}: too many reservations");
        }
        $seen = [];
        $norm = [];
        foreach ($res as $r) {
            $vmid = is_array($r) ? (is_int($r['vmid'] ?? null) ? (string) $r['vmid'] : (string) ($r['vmid'] ?? '')) : '';
            $ip   = is_array($r) ? $usable($r['ip'] ?? null) : null;
            $type = is_array($r) ? (string) ($r['type'] ?? '') : '';
            if (! in_array($type, ['qemu', 'lxc'], true) || preg_match('/^[1-9][0-9]{2,8}$/', $vmid) !== 1 || $ip === null || $ip === $gw || isset($seen[$ip])) {
                return $bad("instance {$i}: invalid reservation");
            }
            $seen[$ip] = true;
            $norm[]    = ['type' => $type, 'vmid' => $vmid, 'ip' => long2ip($ip)];
        }
        $out[] = [
            'bridge' => $bridge, 'cidr' => $cidr, 'netmask' => $mask, 'gateway' => long2ip($gw),
            'range_start' => long2ip($start), 'range_end' => long2ip($end), 'dns' => array_values($dns), 'reservations' => $norm,
        ];
    }

    return ['ok' => true, 'error' => '', 'instances' => $out];
}

/** MAC of a guest NIC on $bridge from its PVE config (current section only), uppercase, or ''. */
function nexovirt_dhcp_guest_mac(string $root, string $type, string $vmid, string $bridge): string
{
    $dir  = $type === 'lxc' ? '/etc/pve/lxc/' : '/etc/pve/qemu-server/';
    $conf = @file_get_contents($root . $dir . $vmid . '.conf');
    if (! is_string($conf)) {
        return '';
    }
    $current = preg_split('/^\[/m', $conf)[0];
    foreach (preg_split('/\R/', $current) as $line) {
        if (preg_match('/^net\d+:\s*(\S+)/', $line, $m) !== 1) {
            continue;
        }
        $mac = '';
        $br  = '';
        foreach (explode(',', $m[1]) as $kv) {
            [$k, $v] = array_pad(explode('=', $kv, 2), 2, '');
            if ($k === 'bridge') {
                $br = $v;
            } elseif (preg_match('/^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/', $v) === 1) {
                $mac = strtoupper($v);
            }
        }
        if ($br === $bridge && $mac !== '') {
            return $mac;
        }
    }

    return '';
}

/** dnsmasq config of one instance. $macs = ip => MAC. PURE. */
function nexovirt_dhcp_conf(array $inst, array $macs): string
{
    $lines = [
        '# Managed by nexovirt-agent: rewritten on every apply. Not read by the system dnsmasq.',
        'port=0',
        'interface=' . $inst['bridge'],
        'except-interface=lo',
        'bind-interfaces',
        'no-resolv',
        'no-hosts',
        'dhcp-range=' . $inst['range_start'] . ',' . $inst['range_end'] . ',' . $inst['netmask'] . ',' . DHCP_LEASE_TIME,
        'dhcp-option=option:router,' . $inst['gateway'],
        'dhcp-leasefile=' . DHCP_LEASE_DIR . '/' . $inst['bridge'] . '.leases',
    ];
    if ($inst['dns'] !== []) {
        $lines[] = 'dhcp-option=option:dns-server,' . implode(',', $inst['dns']);
    }
    foreach ($macs as $ip => $mac) {
        $lines[] = 'dhcp-host=' . $mac . ',' . $ip;
    }

    return implode("\n", $lines) . "\n";
}

/** systemd template unit for the instances. PURE. */
function nexovirt_dhcp_unit(string $bin): string
{
    return "[Unit]\nDescription=NexoVirt DHCP on %i (dnsmasq, own config)\nAfter=network-online.target\nWants=network-online.target\n\n"
        . "[Service]\nType=simple\nExecStart={$bin} --keep-in-foreground --conf-file=" . DHCP_DIR . "/%i.conf --pid-file=/run/nexovirt-dhcp-%i.pid\n"
        . "Restart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n";
}

/** Strip a config comment (#, ;) and trim. PURE. */
function nexovirt_dhcp_strip(string $line): string
{
    return trim((string) preg_replace('/\s*[#;].*$/', '', $line));
}

/**
 * dhcp-range pools of dnsmasq config files ($files = path => content). The interface comes from an explicit
 * `interface:` token, else the `interface=` lines of the same file, of its directory, or of the main file
 * (dnsmasq.conf); none = '' (every interface). IPv4 ranges only. PURE.
 *
 * @return list<array{source:string,file:string,interface:string,start:string,end:string}>
 */
function nexovirt_dhcp_parse_dnsmasq(array $files, string $source = 'dnsmasq'): array
{
    $ifByFile = [];
    $ifByDir  = [];
    $mainIf   = [];
    foreach ($files as $path => $content) {
        foreach (preg_split('/\R/', (string) $content) as $line) {
            $l = nexovirt_dhcp_strip($line);
            if (preg_match('/^interface\s*=\s*(.+)$/', $l, $m) === 1) {
                foreach (array_filter(array_map('trim', explode(',', $m[1]))) as $if) {
                    $ifByFile[$path][]           = $if;
                    $ifByDir[dirname($path)][]   = $if;
                    if (basename($path) === 'dnsmasq.conf') {
                        $mainIf[] = $if;
                    }
                }
            }
        }
    }
    $pools = [];
    foreach ($files as $path => $content) {
        foreach (preg_split('/\R/', (string) $content) as $line) {
            $l = nexovirt_dhcp_strip($line);
            if (preg_match('/^dhcp-range\s*=\s*(.+)$/', $l, $m) !== 1) {
                continue;
            }
            $explicit = [];
            $addr     = [];
            foreach (array_map('trim', explode(',', $m[1])) as $tok) {
                if (str_starts_with($tok, 'interface:')) {
                    $explicit[] = substr($tok, 10);
                } elseif (! str_starts_with($tok, 'tag:') && ! str_starts_with($tok, 'set:')) {
                    $addr[] = $tok;
                }
            }
            if (count($addr) < 2 || nexovirt_ip4_long($addr[0]) === null || nexovirt_ip4_long($addr[1]) === null) {
                continue; // static / proxy / IPv6 ranges hand out no IPv4 pool
            }
            // A per-zone sub directory (PVE SDN dnsmasq@<zone>) is its own instance: no fallback to dnsmasq.conf.
            $main = in_array(dirname($path), ['/etc', '/etc/dnsmasq.d'], true) ? $mainIf : [];
            $ifs  = $explicit ?: ($ifByFile[$path] ?? ($ifByDir[dirname($path)] ?? $main)) ?: [''];
            foreach (array_unique($ifs) as $if) {
                $pools[] = ['source' => $source, 'file' => (string) $path, 'interface' => $if, 'start' => $addr[0], 'end' => $addr[1]];
            }
        }
    }

    return $pools;
}

/** isc-dhcp-server `range a b;` pools; interface from INTERFACESv4 when it names exactly one. PURE. */
function nexovirt_dhcp_parse_isc(string $conf, string $defaults, string $file = '/etc/dhcp/dhcpd.conf'): array
{
    $if = '';
    if (preg_match('/^\s*INTERFACESv4\s*=\s*"?([^"\n]*)"?/m', $defaults, $m) === 1) {
        $names = preg_split('/\s+/', trim($m[1])) ?: [];
        $if    = count($names) === 1 ? $names[0] : '';
    }
    $text = (string) preg_replace('/#.*$/m', '', $conf);
    preg_match_all('/\brange\s+(?:dynamic-bootp\s+)?(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s*;/', $text, $mm, PREG_SET_ORDER);
    $pools = [];
    foreach ($mm as $r) {
        $pools[] = ['source' => 'isc-dhcp-server', 'file' => $file, 'interface' => $if, 'start' => $r[1], 'end' => $r[2]];
    }

    return $pools;
}

/** Kea DHCPv4 pools ("a - b") when the file decodes as JSON once comment lines are dropped. PURE. */
function nexovirt_dhcp_parse_kea(string $json, string $file = '/etc/kea/kea-dhcp4.conf'): array
{
    $clean = implode("\n", array_filter(preg_split('/\R/', $json), static fn ($l) => ! preg_match('/^\s*(#|\/\/)/', $l)));
    $doc   = json_decode($clean, true);
    $d4    = is_array($doc) ? ($doc['Dhcp4'] ?? null) : null;
    if (! is_array($d4)) {
        return [];
    }
    $ifs = array_values(array_unique(array_map(static fn ($i) => explode('/', (string) $i)[0], (array) ($d4['interfaces-config']['interfaces'] ?? []))));
    $if  = count($ifs) === 1 && $ifs[0] !== '*' ? $ifs[0] : '';
    $pools = [];
    foreach ((array) ($d4['subnet4'] ?? []) as $subnet) {
        foreach ((array) ($subnet['pools'] ?? []) as $pool) {
            if (preg_match('/^\s*(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)\s*$/', (string) ($pool['pool'] ?? ''), $m) === 1) {
                $pools[] = ['source' => 'kea', 'file' => $file, 'interface' => $if, 'start' => $m[1], 'end' => $m[2]];
            }
        }
    }

    return $pools;
}

/**
 * UDP 67 sockets from `ss -H -lunp`: interface after '%' (bind-interfaces), else '' = every interface. PURE.
 *
 * @return list<array{interface:string,process:string,pid:int}>
 */
function nexovirt_dhcp_parse_listeners(string $ss): array
{
    $out = [];
    foreach (preg_split('/\R/', $ss) as $line) {
        if (preg_match('/\s(\S+):67\s/', $line . ' ', $m) !== 1) {
            continue;
        }
        $if = str_contains($m[1], '%') ? substr($m[1], strpos($m[1], '%') + 1) : '';
        preg_match('/users:\(\("([^"]+)",pid=(\d+)/', $line, $p);
        $out[] = ['interface' => $if, 'process' => (string) ($p[1] ?? 'unknown'), 'pid' => (int) ($p[2] ?? 0)];
    }

    return $out;
}

/** Readable regular config files under a directory (one level, plus one more for PVE SDN's per-zone dirs). */
function nexovirt_dhcp_conf_files(string $dir, bool $nested): array
{
    $paths = glob($dir . '/*') ?: [];
    if ($nested) {
        $paths = array_merge($paths, glob($dir . '/*/*') ?: []);
    }
    $out = [];
    foreach ($paths as $p) {
        $b = basename($p);
        if (is_file($p) && is_readable($p) && $b[0] !== '.' && ! str_ends_with($b, '~') && preg_match('/\.(dpkg-[a-z]+|bak|orig)$/', $b) !== 1) {
            $out[$p] = (string) @file_get_contents($p, false, null, 0, 262144);
        }
    }

    return $out;
}

/** Bridges with a NexoVirt DHCP instance (from the own config files). @return list<string> */
function nexovirt_dhcp_own_bridges(string $root): array
{
    return array_values(array_filter(array_map(static fn ($p) => basename($p, '.conf'), glob($root . DHCP_DIR . '/*.conf') ?: []), 'nexovirt_dhcp_valid_bridge'));
}

/**
 * Read-only DHCP picture of the node: every IPv4 pool (hand-made dnsmasq / isc-dhcp-server / kea, and
 * NexoVirt's own instances) and every UDP 67 listener (`own` when it is one of our pids).
 *
 * @return array{pools:list<array<string,string>>,listeners:list<array<string,mixed>>}
 */
function nexovirt_dhcp_read(string $root, callable $run): array
{
    $strip = static function (array $files) use ($root): array {
        $o = [];
        foreach ($files as $p => $c) {
            $o[substr($p, strlen($root))] = $c;
        }

        return $o;
    };
    $dnsmasq = $strip(nexovirt_dhcp_conf_files($root . '/etc/dnsmasq.d', true));
    if (is_readable($root . '/etc/dnsmasq.conf')) {
        $dnsmasq['/etc/dnsmasq.conf'] = (string) @file_get_contents($root . '/etc/dnsmasq.conf', false, null, 0, 262144);
    }
    $pools = array_merge(
        nexovirt_dhcp_parse_dnsmasq($dnsmasq),
        nexovirt_dhcp_parse_dnsmasq($strip(nexovirt_dhcp_conf_files($root . DHCP_DIR, false)), 'nexovirt'),
        nexovirt_dhcp_parse_isc((string) @file_get_contents($root . '/etc/dhcp/dhcpd.conf'), (string) @file_get_contents($root . '/etc/default/isc-dhcp-server')),
        nexovirt_dhcp_parse_kea((string) @file_get_contents($root . '/etc/kea/kea-dhcp4.conf'))
    );
    $ownPids = [];
    foreach (nexovirt_dhcp_own_bridges($root) as $b) {
        $pid = (int) trim((string) @file_get_contents($root . '/run/nexovirt-dhcp-' . $b . '.pid'));
        if ($pid > 0) {
            $ownPids[$pid] = true;
        }
    }
    [, $ss]    = $run("ss -H -lunp 'sport = :67'");
    $listeners = array_map(static fn ($l) => $l + ['own' => isset($ownPids[$l['pid']])], nexovirt_dhcp_parse_listeners((string) $ss));

    return ['pools' => $pools, 'listeners' => $listeners];
}

/** Why a new NexoVirt DHCP instance on $bridge would clash with a DHCP server it did not create. PURE. @return list<string> */
function nexovirt_dhcp_conflicts(string $bridge, array $read): array
{
    $why = [];
    foreach ($read['listeners'] as $l) {
        if (! $l['own'] && ($l['interface'] === $bridge || $l['interface'] === '')) {
            $why[] = $l['process'] . ' (pid ' . $l['pid'] . ') already answers DHCP on ' . ($l['interface'] === '' ? 'every interface' : $bridge);
        }
    }
    foreach ($read['pools'] as $p) {
        if ($p['source'] !== 'nexovirt' && $p['interface'] === $bridge) {
            $why[] = $p['source'] . ' config ' . $p['file'] . ' hands out ' . $p['start'] . '-' . $p['end'] . ' on ' . $bridge;
        }
    }

    return $why;
}

/** Commands that remove every NexoVirt DHCP instance (agent removal, mirrored by the panel). PURE. @return list<string> */
function nexovirt_dhcp_clear_cmds(): array
{
    return [
        'for f in ' . DHCP_DIR . '/*.conf; do [ -e "$f" ] && systemctl disable --now "nexovirt-dhcp@$(basename "$f" .conf).service" >/dev/null 2>&1; done; true',
        'rm -rf ' . DHCP_DIR . ' ' . DHCP_LEASE_DIR,
        'rm -f ' . DHCP_UNIT_PATH . ' /run/nexovirt-dhcp-*.pid',
    ];
}

/** Ensure a dnsmasq binary (installs dnsmasq-base: no service, no config). Returns the path or ''. */
function nexovirt_dhcp_ensure_bin(callable $run): string
{
    [$code, $out] = $run('command -v dnsmasq');
    if ($code === 0 && trim($out) !== '') {
        return trim($out);
    }
    $install = 'DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y dnsmasq-base';
    if ($run($install)[0] !== 0) {
        $run('DEBIAN_FRONTEND=noninteractive timeout 150 apt-get update');
        $run($install);
    }
    [$code, $out] = $run('command -v dnsmasq');

    return $code === 0 ? trim($out) : '';
}

/**
 * Reconcile NexoVirt's DHCP instances to the payload's full desired set.
 *
 * @return array{ok:bool,result:string}
 */
function nexovirt_apply_dhcp(array $p, string $root, callable $run): array
{
    $v = nexovirt_dhcp_validate($p);
    if (! $v['ok']) {
        return ['ok' => false, 'result' => 'invalid apply_dhcp payload: ' . $v['error']];
    }
    $own  = nexovirt_dhcp_own_bridges($root);
    $read = nexovirt_dhcp_read($root, $run);

    // Refuse before touching anything: a foreign DHCP server on a new bridge, or a bridge without an address in the CIDR.
    foreach ($v['instances'] as $inst) {
        $b = $inst['bridge'];
        if (! in_array($b, $own, true)) {
            $why = nexovirt_dhcp_conflicts($b, $read);
            if ($why !== []) {
                return ['ok' => false, 'result' => 'another DHCP server is already active on ' . $b . '; nothing changed: ' . implode(' | ', $why)];
            }
        }
        [, $addr] = $run('ip -4 -o addr show dev ' . escapeshellarg($b));
        preg_match_all('/\binet (\d+\.\d+\.\d+\.\d+)\//', (string) $addr, $m);
        if (array_filter($m[1], static fn ($ip) => nexovirt_nat_ip_in_cidr($ip, $inst['cidr'])) === []) {
            return ['ok' => false, 'result' => 'bridge ' . $b . ' has no address in ' . $inst['cidr'] . '; nothing changed'];
        }
    }

    $bin = '';
    if ($v['instances'] !== []) {
        $bin = nexovirt_dhcp_ensure_bin($run);
        if ($bin === '' || $bin[0] !== '/') {
            return ['ok' => false, 'result' => 'dnsmasq is not installed and dnsmasq-base could not be installed; nothing changed'];
        }
        @mkdir($root . DHCP_DIR, 0755, true);
        @mkdir($root . DHCP_LEASE_DIR, 0755, true);
        @mkdir(dirname($root . DHCP_UNIT_PATH), 0755, true);
        if (@file_put_contents($root . DHCP_UNIT_PATH, nexovirt_dhcp_unit($bin)) === false) {
            return ['ok' => false, 'result' => 'cannot write the DHCP unit'];
        }
    }

    $want    = array_column($v['instances'], 'bridge');
    $removed = [];
    foreach (array_diff($own, $want) as $b) {
        $run('systemctl disable --now ' . escapeshellarg('nexovirt-dhcp@' . $b . '.service'));
        @unlink($root . DHCP_DIR . '/' . $b . '.conf');
        @unlink($root . DHCP_LEASE_DIR . '/' . $b . '.leases');
        $removed[] = $b;
    }
    $run('systemctl daemon-reload');

    $states = [];
    $ok     = true;
    foreach ($v['instances'] as $inst) {
        $macs    = [];
        $skipped = [];
        foreach ($inst['reservations'] as $r) {
            $mac = nexovirt_dhcp_guest_mac($root, $r['type'], $r['vmid'], $inst['bridge']);
            if ($mac !== '') {
                $macs[$r['ip']] = $mac;
            } else {
                $skipped[] = $r['vmid'];
            }
        }
        $unit  = escapeshellarg('nexovirt-dhcp@' . $inst['bridge'] . '.service');
        $wrote = @file_put_contents($root . DHCP_DIR . '/' . $inst['bridge'] . '.conf', nexovirt_dhcp_conf($inst, $macs)) !== false;
        $err   = '';
        if (! $wrote) {
            $err = 'cannot write the config';
        } else {
            $run('systemctl enable ' . $unit);
            [$code, $out] = $run('systemctl restart ' . $unit);
            [, $active]   = $run('systemctl is-active ' . $unit);
            if ($code !== 0 || trim($active) !== 'active') {
                [, $log] = $run('journalctl -u ' . $unit . ' -n 5 --no-pager');
                $err     = trim($out . "\n" . $log) ?: 'the DHCP service did not start';
            }
        }
        $ok       = $ok && $err === '';
        $states[] = ['bridge' => $inst['bridge'], 'state' => $err === '' ? 'active' : 'failed', 'error' => nexovirt_cap_output($err, 2000), 'reserved' => count($macs), 'skipped' => $skipped];
    }
    if ($v['instances'] === []) {
        @unlink($root . DHCP_UNIT_PATH);
        $run('systemctl daemon-reload');
    }

    return ['ok' => $ok, 'result' => nexovirt_json(['instances' => $states, 'removed' => $removed])];
}

/** An IP or CIDR (v4 prefix >= 8, v6 prefix >= 16, so "ignore everyone" is impossible). PURE. */
function nexovirt_f2b_valid_addr(string $a): bool
{
    [$ip, $bits] = array_pad(explode('/', $a, 2), 2, null);
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        return false;
    }
    if ($bits === null) {
        return true;
    }
    $v6 = str_contains($ip, ':');

    return ctype_digit($bits) && (int) $bits >= ($v6 ? 16 : 8) && (int) $bits <= ($v6 ? 128 : 32);
}

/** Validate an apply_fail2ban payload. PURE. @return array{ok:bool,error:string,cfg:array<string,mixed>} */
function nexovirt_f2b_validate(array $p): array
{
    $bad = static fn (string $e): array => ['ok' => false, 'error' => $e, 'cfg' => []];
    $int = static fn ($v, int $min, int $max): ?int => (is_int($v) || (is_string($v) && ctype_digit($v))) && (int) $v >= $min && (int) $v <= $max ? (int) $v : null;
    if (empty($p['enabled'])) {
        return ['ok' => true, 'error' => '', 'cfg' => ['enabled' => false]];
    }
    $ban   = $int($p['bantime'] ?? null, 60, 2592000);
    $find  = $int($p['findtime'] ?? null, 60, 86400);
    $retry = $int($p['maxretry'] ?? null, 1, 100);
    if ($ban === null || $find === null || $retry === null) {
        return $bad('bantime 60..2592000, findtime 60..86400, maxretry 1..100');
    }
    $panel = (string) ($p['panel_ip'] ?? '');
    if (filter_var($panel, FILTER_VALIDATE_IP) === false) {
        return $bad('panel_ip must be the panel\'s address (it is never banned)');
    }
    $user = $p['pve_user'] ?? '';
    if (! is_string($user) || ($user !== '' && ! nexovirt_f2b_valid_user($user))) {
        return $bad('pve_user must be a Proxmox user id');
    }
    $ignore = $p['ignore'] ?? [];
    if (! is_array($ignore) || count($ignore) > F2B_MAX_IGNORE) {
        return $bad('ignore must be a list of at most ' . F2B_MAX_IGNORE);
    }
    foreach ($ignore as $a) {
        if (! is_string($a) || ! nexovirt_f2b_valid_addr($a)) {
            return $bad('invalid ignore entry');
        }
    }

    return ['ok' => true, 'error' => '', 'cfg' => ['enabled' => true, 'bantime' => $ban, 'findtime' => $find, 'maxretry' => $retry,
        'ignore' => array_values(array_unique(array_merge(['127.0.0.1/8', '::1', $panel], $ignore)))]];
}

/** The filter: pvedaemon's failed web UI / API logins. PURE. */
function nexovirt_f2b_filter(): string
{
    return "# Managed by nexovirt-agent.\n[Definition]\n"
        . "failregex = pvedaemon\\[.*authentication (verification )?failure; rhost=(::ffff:)?<HOST> user=.* msg=.*\n"
        . "ignoreregex =\n";
}

/** The jail for the Proxmox web UI (port 8006). PURE. */
function nexovirt_f2b_jail(array $cfg): string
{
    return "# Managed by nexovirt-agent.\n[" . F2B_JAIL . "]\nenabled = true\nport = 8006\nfilter = " . F2B_JAIL . "\n"
        . "backend = systemd\njournalmatch = _SYSTEMD_UNIT=pvedaemon.service\n"
        . 'maxretry = ' . $cfg['maxretry'] . "\nfindtime = " . $cfg['findtime'] . "\nbantime = " . $cfg['bantime'] . "\n"
        . 'ignoreip = ' . implode(' ', $cfg['ignore']) . "\n";
}

/** Commands that remove the NexoVirt jail (agent removal, mirrored by the panel). PURE. @return list<string> */
function nexovirt_f2b_clear_cmds(): array
{
    return [
        'if [ -f ' . F2B_JAIL_PATH . ' ]; then fail2ban-client stop ' . F2B_JAIL . ' >/dev/null 2>&1; fi; true',
        'rm -f ' . F2B_JAIL_PATH . ' ' . F2B_FILTER_PATH,
    ];
}

/** A Proxmox user id (user@realm, optionally !tokenid) as pveproxy logs it. PURE. */
function nexovirt_f2b_valid_user(string $u): bool
{
    return preg_match('/^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9._-]{1,64}(![A-Za-z0-9._-]{1,64})?$/', $u) === 1;
}

/**
 * Client addresses of the panel's AUTHENTICATED API calls in pveproxy's access.log (lines
 * `<ip> - <user> [..] "<METHOD> <path> ..." <status>`): only 2xx answers, never the login itself
 * (POST /api2/json/access/ticket), so a failed or attempted login with the panel's user name never lands
 * here. Most recent first, with counts. SUGGESTIONS ONLY: never added to ignoreip. PURE.
 * @return list<array{ip:string,count:int}>
 */
function nexovirt_f2b_panel_addrs(string $log, string $user): array
{
    $seen = [];
    foreach (array_reverse(preg_split('/\R/', $log) ?: []) as $line) {
        if (preg_match('/^(\S+) - (\S+) \[[^\]]*\] "(\S+) (\S+)[^"]*" (\d{3})\b/', $line, $m) !== 1 || $m[2] !== $user
            || $m[5][0] !== '2' || ($m[3] === 'POST' && str_starts_with($m[4], '/api2/json/access/ticket'))) {
            continue;
        }
        $ip = (string) preg_replace('/^::ffff:(?=\d+\.)/', '', $m[1]);
        if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
            $seen[$ip] = ($seen[$ip] ?? 0) + 1;
        }
    }
    $out = [];
    foreach (array_slice($seen, 0, 20, true) as $ip => $n) {
        $out[] = ['ip' => (string) $ip, 'count' => $n];
    }

    return $out;
}

/** The panel's addresses as the node sees them (last 2000 lines of pveproxy's access.log). */
function nexovirt_f2b_read_panel_addrs(string $root, string $user, callable $run): array
{
    if (! nexovirt_f2b_valid_user($user)) {
        return [];
    }
    [$code, $log] = $run('tail -n 2000 ' . escapeshellarg($root . F2B_ACCESS_LOG));

    return $code === 0 ? nexovirt_f2b_panel_addrs((string) $log, $user) : [];
}

/**
 * Hand-made jails that already watch the Proxmox web UI: a section in jail.local / jail.d/*.conf|*.local
 * (never NexoVirt's own file) whose body or filter mentions pvedaemon or port 8006. Only enabled ones.
 * @return list<array{name:string,file:string}>
 */
function nexovirt_f2b_foreign_jails(string $root): array
{
    $files = array_merge([$root . '/etc/fail2ban/jail.local'], glob($root . '/etc/fail2ban/jail.d/*.conf') ?: [], glob($root . '/etc/fail2ban/jail.d/*.local') ?: []);
    $found = [];
    foreach ($files as $f) {
        if (! is_file($f) || $f === $root . F2B_JAIL_PATH) {
            continue;
        }
        $section = null;
        $bodies  = [];
        foreach (preg_split('/\R/', (string) @file_get_contents($f)) ?: [] as $line) {
            $t = trim($line);
            if ($t === '' || $t[0] === '#' || $t[0] === ';') {
                continue;
            }
            if (preg_match('/^\[([^\]]+)\]$/', $t, $m) === 1) {
                $section = trim($m[1]);
                $bodies[$section] = $bodies[$section] ?? '';
                continue;
            }
            if ($section !== null) {
                $bodies[$section] .= $t . "\n";
            }
        }
        foreach ($bodies as $name => $body) {
            if ($name === 'DEFAULT' || $name === 'INCLUDES' || $name === F2B_JAIL
                || preg_match('/^enabled\s*=\s*(true|yes|1|on)\s*$/mi', $body) !== 1) {
                continue;
            }
            $hit = preg_match('/pvedaemon|\b8006\b/', $body) === 1;
            if (! $hit && preg_match('/^filter\s*=\s*([A-Za-z0-9._-]+)/mi', $body, $fm) === 1) {
                foreach (['.conf', '.local'] as $ext) {
                    $hit = $hit || str_contains((string) @file_get_contents($root . '/etc/fail2ban/filter.d/' . $fm[1] . $ext), 'pvedaemon');
                }
            }
            if ($hit) {
                $found[] = ['name' => (string) $name, 'file' => substr($f, strlen($root))];
            }
        }
    }

    return $found;
}

/** Restore our two files to what they were before (null = remove). */
function nexovirt_f2b_restore(string $root, ?string $jail, ?string $filter): void
{
    foreach ([F2B_JAIL_PATH => $jail, F2B_FILTER_PATH => $filter] as $path => $old) {
        $old === null ? @unlink($root . $path) : @file_put_contents($root . $path, $old);
    }
}

/** Remove the jail: delete our files, full reload (drops jails no longer configured), verify it is gone. */
function nexovirt_f2b_disable(string $root, bool $haveClient, callable $run): array
{
    @unlink($root . F2B_JAIL_PATH);
    @unlink($root . F2B_FILTER_PATH);
    if ($haveClient && $run('fail2ban-client status ' . F2B_JAIL)[0] === 0) {
        $run('fail2ban-client reload');
        if ($run('fail2ban-client status ' . F2B_JAIL)[0] === 0) {
            $run('fail2ban-client stop ' . F2B_JAIL);
            if ($run('fail2ban-client status ' . F2B_JAIL)[0] === 0) {
                return ['ok' => false, 'result' => 'the files are removed but the jail nexovirt-pve is still running; run fail2ban-client reload on the node'];
            }
        }
    }

    return ['ok' => true, 'result' => nexovirt_json(['enabled' => false])];
}

/** Write (enabled) or remove (disabled) the NexoVirt fail2ban jail. @return array{ok:bool,result:string} */
function nexovirt_apply_fail2ban(array $p, string $root, callable $run): array
{
    $v = nexovirt_f2b_validate($p);
    if (! $v['ok']) {
        return ['ok' => false, 'result' => 'invalid apply_fail2ban payload: ' . $v['error']];
    }
    $haveClient = $run('command -v fail2ban-client')[0] === 0;

    if (! $v['cfg']['enabled']) {
        return nexovirt_f2b_disable($root, $haveClient, $run);
    }

    $foreign = nexovirt_f2b_foreign_jails($root);
    if ($foreign !== [] && empty($p['allow_existing'])) {
        $names = implode(', ', array_map(static fn ($j) => "'" . $j['name'] . "' (" . $j['file'] . ')', $foreign));

        return ['ok' => false, 'result' => 'fail2ban on ' . gethostname() . ' already has a jail for the web UI: ' . $names
            . '. Tick "Add NexoVirt\'s jail next to it" to add NexoVirt\'s jail anyway. Nothing changed'];
    }

    $installed = false;
    if (! $haveClient) {
        $install = 'DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y fail2ban python3-systemd';
        if ($run($install)[0] !== 0) {
            $run('DEBIAN_FRONTEND=noninteractive timeout 150 apt-get update');
            $run($install);
        }
        if ($run('command -v fail2ban-client')[0] !== 0) {
            return ['ok' => false, 'result' => 'fail2ban is not installed and could not be installed; nothing changed'];
        }
        $installed = true;
    } elseif (trim($run('systemctl is-active fail2ban')[1]) !== 'active') {
        return ['ok' => false, 'result' => 'fail2ban is installed but not running on this node; NexoVirt does not start an existing fail2ban. Start it yourself, then try again. Nothing changed'];
    }

    // ignoreip is exactly localhost + the admin's panel_ip + ignore CIDRs (never log-derived addresses).
    $cfg = $v['cfg'];
    $wasRunning = ! $installed && $run('fail2ban-client status ' . F2B_JAIL)[0] === 0;
    $oldJail    = is_file($root . F2B_JAIL_PATH) ? (string) file_get_contents($root . F2B_JAIL_PATH) : null;
    $oldFilter  = is_file($root . F2B_FILTER_PATH) ? (string) file_get_contents($root . F2B_FILTER_PATH) : null;
    @mkdir(dirname($root . F2B_FILTER_PATH), 0755, true);
    @mkdir(dirname($root . F2B_JAIL_PATH), 0755, true);
    if (@file_put_contents($root . F2B_FILTER_PATH, nexovirt_f2b_filter()) === false
        || @file_put_contents($root . F2B_JAIL_PATH, nexovirt_f2b_jail($cfg)) === false) {
        nexovirt_f2b_restore($root, $oldJail, $oldFilter);

        return ['ok' => false, 'result' => 'cannot write the fail2ban files'];
    }
    [$tCode, $tOut] = $run('fail2ban-client -t');
    if ($tCode !== 0) {
        nexovirt_f2b_restore($root, $oldJail, $oldFilter);

        return ['ok' => false, 'result' => 'the fail2ban configuration test failed, NexoVirt\'s files were taken back: ' . nexovirt_cap_output(trim((string) $tOut), 2000)];
    }
    if ($installed) {
        [$code, $out] = $run('systemctl enable --now fail2ban');
    } else {
        // A jail fail2ban does not run yet only starts with a full reload ("reload <jail>" says it does not exist).
        [$code, $out] = $run($wasRunning ? 'fail2ban-client reload ' . F2B_JAIL : 'fail2ban-client reload');
    }
    [$sCode] = $run('fail2ban-client status ' . F2B_JAIL);
    if ($code !== 0 || $sCode !== 0) {
        return ['ok' => false, 'result' => 'the jail did not start: ' . nexovirt_cap_output(trim((string) $out), 2000)];
    }

    return ['ok' => true, 'result' => nexovirt_json(['enabled' => true, 'installed_now' => $installed])];
}

/** Banned IPs + failure count from `fail2ban-client status <jail>`. PURE. */
function nexovirt_f2b_parse_status(string $out): array
{
    $banned = [];
    if (preg_match('/Banned IP list:\s*(.*)$/m', $out, $m) === 1) {
        $banned = array_values(array_filter(preg_split('/\s+/', trim($m[1])) ?: [], static fn ($ip) => filter_var($ip, FILTER_VALIDATE_IP) !== false));
    }
    $failed = preg_match('/Currently failed:\s*(\d+)/', $out, $f) === 1 ? (int) $f[1] : 0;

    return ['banned' => $banned, 'failed' => $failed];
}

/** Read-only fail2ban state of the node: our jail, hand-made web UI jails (with their bans), the panel's addresses. */
function nexovirt_read_fail2ban(string $root, string $pveUser, callable $run): array
{
    $installed = $run('command -v fail2ban-client')[0] === 0;
    $running   = $installed && trim($run('systemctl is-active fail2ban')[1]) === 'active';
    $status    = ['banned' => [], 'failed' => 0];
    $jail      = false;
    if ($running) {
        [$code, $out] = $run('fail2ban-client status ' . F2B_JAIL);
        $jail         = $code === 0;
        $status       = $jail ? nexovirt_f2b_parse_status($out) : $status;
    }
    $foreign = [];
    foreach (nexovirt_f2b_foreign_jails($root) as $j) {
        [$code, $out] = $running ? $run('fail2ban-client status ' . escapeshellarg($j['name'])) : [1, ''];
        $foreign[]    = $j + ['active' => $code === 0, 'banned' => $code === 0 ? nexovirt_f2b_parse_status((string) $out)['banned'] : []];
    }

    return [
        'installed' => $installed, 'running' => $running, 'jail_active' => $jail,
        'files' => is_file($root . F2B_JAIL_PATH), 'banned' => $status['banned'], 'failed' => $status['failed'],
        'foreign_jails' => $foreign, 'panel_addrs' => nexovirt_f2b_read_panel_addrs($root, $pveUser, $run),
    ];
}

/** Lift one ban of the NexoVirt jail. @return array{ok:bool,result:string} */
function nexovirt_f2b_unban(string $ip, callable $run): array
{
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        return ['ok' => false, 'result' => 'invalid fail2ban_unban payload'];
    }
    [$code, $out] = $run('fail2ban-client set ' . F2B_JAIL . ' unbanip ' . escapeshellarg($ip));

    return ['ok' => $code === 0, 'result' => $code === 0 ? 'unbanned' : nexovirt_cap_output(trim($out), 2000)];
}

// ---------------------------------------------------------------------------
// One-click apps: lxc_app_install, lxc_app_status (spec 2026-10-20-lxc-app-store-design)
// ---------------------------------------------------------------------------

const APP_DIR        = '/var/lib/nexovirt/app';
const APP_LOG_DIR    = '/var/log/nexovirt';
const APP_MAX_SCRIPT = 65536;
const APP_MAX_ENV    = 20;
const APP_ENV_RE     = '/^NX_[A-Z][A-Z0-9_]{0,30}$/';
const APP_CT_DIR     = '/root/.nexovirt-app';

/**
 * The FIXED script that runs inside the container (no payload value is formatted into it): wait for
 * DNS, load and delete the env file, then run the pushed install script with its output appended to
 * /var/log/nexovirt-app.log inside the CT. Exit status = the install script's (pipefail).
 */
const APP_INNER = <<<'SH'
set -o pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root DEBIAN_FRONTEND=noninteractive
for i in $(seq 1 60); do getent hosts deb.debian.org >/dev/null 2>&1 && break; sleep 2; done
set -a
. /root/.nexovirt-app/env
set +a
rm -f /root/.nexovirt-app/env
cd /root
echo "=== NexoVirt app install $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" >> /var/log/nexovirt-app.log
/bin/bash /root/.nexovirt-app/install.sh 2>&1 | tee -a /var/log/nexovirt-app.log
SH;

function nexovirt_app_unit(int $vmid): string
{
    return 'nexovirt-app-' . $vmid;
}

function nexovirt_app_log(int $vmid): string
{
    return APP_LOG_DIR . '/app-' . $vmid . '.log';
}

function nexovirt_app_exit_file(int $vmid): string
{
    return APP_LOG_DIR . '/app-' . $vmid . '.exit';
}

/**
 * Validate an lxc_app_install payload (fail-closed). PURE.
 *
 * @param array<string,mixed> $p
 * @return array{ok:bool, error?:string, vmid?:int, script?:string, env?:array<string,string>, timeout?:int}
 */
function nexovirt_app_validate(array $p): array
{
    $vmid = $p['vmid'] ?? null;
    if (! is_int($vmid) || $vmid < 100 || $vmid > 999999999) {
        return ['ok' => false, 'error' => 'invalid lxc_app_install payload: vmid'];
    }
    $script = $p['script'] ?? null;
    $sha    = $p['sha256'] ?? null;
    if (! is_string($script) || trim($script) === '' || strlen($script) > APP_MAX_SCRIPT || strpos($script, "\0") !== false) {
        return ['ok' => false, 'error' => 'invalid lxc_app_install payload: script'];
    }
    if (! is_string($sha) || preg_match('/^[a-f0-9]{64}$/', $sha) !== 1 || ! hash_equals($sha, hash('sha256', $script))) {
        return ['ok' => false, 'error' => 'invalid lxc_app_install payload: the script does not match its checksum'];
    }
    $env = $p['env'] ?? [];
    if (! is_array($env) || count($env) > APP_MAX_ENV) {
        return ['ok' => false, 'error' => 'invalid lxc_app_install payload: env'];
    }
    foreach ($env as $k => $v) {
        if (! is_string($k) || preg_match(APP_ENV_RE, $k) !== 1 || ! is_string($v) || strlen($v) > 1024 || strpbrk($v, "\0\r\n") !== false) {
            return ['ok' => false, 'error' => 'invalid lxc_app_install payload: env'];
        }
    }
    $timeout = $p['timeout'] ?? null;
    if (! is_int($timeout) || $timeout < 300 || $timeout > 7200) {
        return ['ok' => false, 'error' => 'invalid lxc_app_install payload: timeout'];
    }

    return ['ok' => true, 'vmid' => $vmid, 'script' => $script, 'env' => $env, 'timeout' => $timeout];
}

/**
 * The env file the inner script sources: one NAME='value' line per setting, single quotes escaped as
 * '\''. Names and values are validated first (no NUL/CR/LF), so a value can never end the quoting. PURE.
 *
 * @param array<string,string> $env
 */
function nexovirt_app_env_file(array $env): string
{
    $out = '';
    foreach ($env as $k => $v) {
        $out .= $k . "='" . str_replace("'", "'\\''", $v) . "'\n";
    }

    return $out;
}

/** The host-side runner (only the integer vmid is formatted in). PURE. */
function nexovirt_app_runner(int $vmid): string
{
    return "#!/bin/sh\n"
        . 'pct exec ' . escapeshellarg((string) $vmid) . ' -- /bin/bash -c ' . escapeshellarg(APP_INNER) . "\n"
        . 'echo "$?" > ' . escapeshellarg(nexovirt_app_exit_file($vmid)) . "\n";
}

/** The detached systemd-run command for a validated vmid + timeout. PURE. */
function nexovirt_app_start_cmd(int $vmid, int $timeout): string
{
    $log = nexovirt_app_log($vmid);

    return 'systemd-run --unit=' . nexovirt_app_unit($vmid) . ' --collect --quiet'
        . ' --property=RuntimeMaxSec=' . $timeout
        . ' --property=StandardOutput=append:' . $log . ' --property=StandardError=append:' . $log
        . ' /bin/sh ' . escapeshellarg(APP_DIR . '/' . $vmid . '/run.sh');
}

/** Start a stopped CT and wait (bounded) until it runs. */
function nexovirt_app_ensure_running(int $vmid): bool
{
    $id = escapeshellarg((string) $vmid);
    if (strpos(nexovirt_run_cmd("pct status {$id} 2>&1"), 'running') !== false) {
        return true;
    }
    nexovirt_run_cmd("pct start {$id} 2>&1", 120);
    for ($i = 0; $i < 30; $i++) {
        sleep(1);
        if (strpos(nexovirt_run_cmd("pct status {$id} 2>&1"), 'running') !== false) {
            return true;
        }
    }

    return false;
}

/**
 * Push the install script + env into the CT and start the detached install. Returns at once.
 *
 * @param array<string,mixed> $p
 * @return array{ok:bool, result?:array<string,mixed>, error?:string}
 */
function nexovirt_lxc_app_install(array $p): array
{
    $v = nexovirt_app_validate($p);
    if (! $v['ok']) {
        return ['ok' => false, 'error' => $v['error']];
    }
    $vmid = $v['vmid'];
    $id   = escapeshellarg((string) $vmid);
    $dir  = APP_DIR . '/' . $vmid;
    if (getenv('NEXOVIRT_AGENT_DRYRUN') === '1') {
        return ['ok' => true, 'result' => ['started' => true, 'unit' => nexovirt_app_unit($vmid),
            'env_file' => nexovirt_app_env_file($v['env']), 'runner' => nexovirt_app_runner($vmid),
            'cmd' => nexovirt_app_start_cmd($vmid, $v['timeout'])]];
    }
    if (! nexovirt_bin_installed('pct') || ! nexovirt_bin_installed('systemd-run')) {
        return ['ok' => false, 'error' => 'pct or systemd-run is not available on this node.'];
    }
    $code = 1;
    $out  = [];
    exec("pct config {$id} >/dev/null 2>&1", $out, $code);
    if ($code !== 0) {
        return ['ok' => false, 'error' => 'Container ' . $vmid . ' was not found on this node.'];
    }
    if (in_array(trim(nexovirt_run_cmd('systemctl is-active ' . nexovirt_app_unit($vmid))), ['active', 'activating', 'reloading'], true)) {
        return ['ok' => false, 'error' => 'An app install is already running in container ' . $vmid . '.'];
    }
    if (! nexovirt_app_ensure_running($vmid)) {
        return ['ok' => false, 'error' => 'Container ' . $vmid . ' did not start.'];
    }
    foreach ([APP_DIR, $dir, APP_LOG_DIR] as $d) {
        if (! is_dir($d)) {
            @mkdir($d, 0700, true);
        }
        @chmod($d, 0700);
    }
    @unlink(nexovirt_app_exit_file($vmid));
    if (! nexovirt_write_private($dir . '/install.sh', $v['script'])
        || ! nexovirt_write_private($dir . '/env', nexovirt_app_env_file($v['env']))
        || ! nexovirt_write_private($dir . '/run.sh', nexovirt_app_runner($vmid))
        || ! nexovirt_write_private(nexovirt_app_log($vmid), '')) {
        @unlink($dir . '/env');

        return ['ok' => false, 'error' => 'Could not write the install files in ' . APP_DIR . '.'];
    }
    $push = [
        "pct exec {$id} -- /bin/sh -c " . escapeshellarg('mkdir -p ' . APP_CT_DIR . ' && chmod 700 ' . APP_CT_DIR),
        "pct push {$id} " . escapeshellarg($dir . '/install.sh') . ' ' . escapeshellarg(APP_CT_DIR . '/install.sh') . ' --perms 0700',
        "pct push {$id} " . escapeshellarg($dir . '/env') . ' ' . escapeshellarg(APP_CT_DIR . '/env') . ' --perms 0600',
    ];
    foreach ($push as $cmd) {
        $o = [];
        $c = 1;
        exec($cmd . ' 2>&1', $o, $c);
        if ($c !== 0) {
            @unlink($dir . '/env');

            return ['ok' => false, 'error' => 'Could not copy the install script into the container: ' . nexovirt_cap_output(implode("\n", $o), 500)];
        }
    }
    @unlink($dir . '/env'); // the secrets now live only in the CT, until the inner script deletes them
    $o = [];
    $c = 1;
    exec(nexovirt_app_start_cmd($vmid, $v['timeout']) . ' 2>&1', $o, $c);
    if ($c !== 0) {
        return ['ok' => false, 'error' => 'Could not start the install: ' . nexovirt_cap_output(implode("\n", $o), 500)];
    }

    return ['ok' => true, 'result' => ['started' => true, 'unit' => nexovirt_app_unit($vmid)]];
}

/**
 * While the install runs, hand out whole lines only (a trailing partial line is read again next time),
 * so the panel can use the byte offset as is. A full chunk without any newline is passed through. PURE.
 *
 * @param array{log:string,offset:int} $tail
 * @return array{log:string,offset:int}
 */
function nexovirt_app_whole_lines(array $tail, bool $running): array
{
    $cut = strrpos($tail['log'], "\n");
    if (! $running || strlen($tail['log']) >= APT_LOG_CHUNK) {
        return $tail;
    }
    $keep = $cut === false ? 0 : $cut + 1;

    return ['log' => substr($tail['log'], 0, $keep), 'offset' => $tail['offset'] - (strlen($tail['log']) - $keep)];
}

/**
 * State of an app install: running / succeeded / failed (+ exit code) / idle, and the log after $offset.
 *
 * @return array<string,mixed>
 */
function nexovirt_lxc_app_status(int $vmid, int $offset): array
{
    if (getenv('NEXOVIRT_AGENT_DRYRUN') === '1') {
        $log = "[nexovirt-app] Installing\n[nexovirt-app] Ready.\n";

        return ['state' => 'succeeded', 'exit_code' => 0, 'log' => substr($log, min($offset, strlen($log))), 'offset' => strlen($log)];
    }
    $active = trim(nexovirt_run_cmd('systemctl is-active ' . nexovirt_app_unit($vmid)));
    $exit   = is_readable(nexovirt_app_exit_file($vmid)) ? trim((string) @file_get_contents(nexovirt_app_exit_file($vmid))) : '';
    $code   = null;
    if (in_array($active, ['active', 'activating', 'reloading'], true)) {
        $state = 'running';
    } elseif ($exit !== '' && ctype_digit($exit)) {
        $code  = (int) $exit;
        $state = $code === 0 ? 'succeeded' : 'failed';
    } else {
        // No exit code: killed (timeout) or never started.
        $state = is_file(nexovirt_app_log($vmid)) ? 'failed' : 'idle';
    }
    $tail = nexovirt_log_tail(nexovirt_app_log($vmid), $offset);
    $tail = nexovirt_app_whole_lines($tail, $state === 'running');

    return ['state' => $state, 'exit_code' => $code, 'log' => $tail['log'], 'offset' => $tail['offset']];
}

// ---------------------------------------------------------------------------
// Backup jobs: disks per job (vzdump hook, agent 0.27.0)
// ---------------------------------------------------------------------------
// PVE reads a disk's backup flag from the guest config before the guest is backed up and has no per-job
// disk list. A job with a disk selection runs `<hook dir>/<job>.sh`, which calls this agent with
// `--vzdump-hook <job> <phase> [mode vmid]`: job-start sets the listed disks of this node's guests to the
// wanted flag (compare-and-set, every change recorded in <job>.state), backup-end/backup-abort puts that
// guest's disks back, job-end/job-abort puts back what is left. A disk changed by someone in between is
// left alone. The hook never fails the backup: a disk it could not switch is backed up as configured.

const NEXOVIRT_BACKUP_HOOK_DIR = '/var/lib/nexovirt/backup-hooks';

function nexovirt_backup_hook_dir(): string
{
    $d = getenv('NEXOVIRT_AGENT_BACKUP_HOOK_DIR');

    return is_string($d) && $d !== '' ? rtrim($d, '/') : NEXOVIRT_BACKUP_HOOK_DIR;
}

function nexovirt_backup_hook_path(string $jobId): string
{
    return nexovirt_backup_hook_dir() . '/' . $jobId . '.sh';
}

function nexovirt_valid_backup_job_id(string $id): bool
{
    return preg_match('/^[A-Za-z][A-Za-z0-9_-]{2,63}$/', $id) === 1;
}

/** The disk value with backup=0|1 set: an existing backup= part is replaced in place, else appended. */
function nexovirt_backup_flag_value(string $value, bool $include): string
{
    $parts = explode(',', $value);
    $flag  = 'backup=' . ($include ? '1' : '0');
    $found = false;
    foreach ($parts as $i => $p) {
        if ($i > 0 && str_starts_with($p, 'backup=')) {
            $parts[$i] = $flag;
            $found     = true;
        }
    }
    if (! $found) {
        $parts[] = $flag;
    }

    return implode(',', $parts);
}

/**
 * Fail-closed payload check: {jobs: {<id>: {guests: [{vmid, type, disks: {<key>: bool}}]}}}.
 *
 * @return array{ok:bool,jobs:array<string,array{guests:list<array{vmid:int,type:string,disks:array<string,bool>}>}>,error:string}
 */
function nexovirt_validate_backup_hooks(array $p): array
{
    $bad  = static fn (string $e): array => ['ok' => false, 'jobs' => [], 'error' => $e];
    $jobs = $p['jobs'] ?? [];
    if (! is_array($jobs) || count($jobs) > 500) {
        return $bad('jobs must be a map');
    }
    $out = [];
    foreach ($jobs as $id => $job) {
        if (! is_string($id) || ! nexovirt_valid_backup_job_id($id) || ! is_array($job) || ! is_array($job['guests'] ?? null) || count($job['guests']) > 1000) {
            return $bad('invalid job');
        }
        $guests = [];
        foreach ($job['guests'] as $g) {
            $type  = is_array($g) ? ($g['type'] ?? '') : '';
            $vmid  = is_array($g) ? ($g['vmid'] ?? 0) : 0;
            $disks = is_array($g) ? ($g['disks'] ?? null) : null;
            if (! in_array($type, ['qemu', 'lxc'], true) || ! is_int($vmid) || $vmid < 100 || $vmid > 999999999 || ! is_array($disks) || count($disks) > 64) {
                return $bad('invalid guest');
            }
            $keyRe = $type === 'lxc' ? '/^mp\d{1,3}$/' : '/^(scsi|sata|ide|virtio)\d{1,2}$/';
            $clean = [];
            foreach ($disks as $k => $on) {
                if (! is_string($k) || preg_match($keyRe, $k) !== 1 || ! is_bool($on)) {
                    return $bad('invalid disk');
                }
                $clean[$k] = $on;
            }
            $guests[] = ['vmid' => $vmid, 'type' => $type, 'disks' => $clean];
        }
        $out[$id] = ['guests' => $guests];
    }

    return ['ok' => true, 'jobs' => $out, 'error' => ''];
}

/** Atomic write (tmp + rename) with the mode set before the rename. */
function nexovirt_backup_hook_put(string $file, string $content, int $mode): bool
{
    $tmp = $file . '.tmp';

    return @file_put_contents($tmp, $content) !== false && @chmod($tmp, $mode) && @rename($tmp, $file);
}

/**
 * Write the full desired set of hooks: <job>.json + <job>.sh per job; hooks of jobs no longer listed are
 * removed (their leftover changes put back first).
 *
 * @return array{ok:bool,result:string}
 */
function nexovirt_backup_hooks_apply(array $jobs, ?callable $write = null): array
{
    $dir = nexovirt_backup_hook_dir();
    if (! is_dir($dir) && ! @mkdir($dir, 0700, true)) {
        return ['ok' => false, 'result' => 'could not create ' . $dir];
    }
    foreach ($jobs as $id => $job) {
        $php = is_executable('/usr/bin/php') ? '/usr/bin/php' : PHP_BINARY; // survives a PHP minor upgrade
        $sh  = "#!/bin/sh\n# NexoVirt: disks of backup job {$id}. Managed by the NexoVirt agent.\nexec "
            . escapeshellarg($php) . ' ' . escapeshellarg(__FILE__) . ' --vzdump-hook ' . escapeshellarg($id) . " \"\$@\"\n";
        if (! nexovirt_backup_hook_put("{$dir}/{$id}.json", json_encode($job), 0600) || ! nexovirt_backup_hook_put("{$dir}/{$id}.sh", $sh, 0755)) {
            return ['ok' => false, 'result' => 'could not write the hook of ' . $id];
        }
    }
    foreach (glob($dir . '/*.json') ?: [] as $file) {
        $id = basename($file, '.json');
        if (isset($jobs[$id])) {
            continue;
        }
        if (is_file("{$dir}/{$id}.state")) {
            nexovirt_backup_hook_restore($id, null, $write ?? 'nexovirt_backup_flag_write');
        }
        @unlink($file);
        @unlink("{$dir}/{$id}.sh");
    }

    return ['ok' => true, 'result' => count($jobs) . ' backup job hook(s)'];
}

/** Value of $key in the guest's live config section (lines before the first [snapshot] header), null if absent. */
function nexovirt_backup_conf_value(string $type, int $vmid, string $key): ?string
{
    $etc  = getenv('NEXOVIRT_AGENT_PVE_ETC');
    $file = (is_string($etc) && $etc !== '' ? $etc : '/etc/pve') . ($type === 'lxc' ? '/lxc/' : '/qemu-server/') . $vmid . '.conf';
    $raw  = @file_get_contents($file);
    if ($raw === false) {
        return null;
    }
    foreach (explode("\n", $raw) as $line) {
        if (str_starts_with($line, '[')) {
            break;
        }
        if (str_starts_with($line, $key . ':')) {
            return trim(substr($line, strlen($key) + 1));
        }
    }

    return null;
}

/**
 * Compare-and-set one config key under PVE's config lock, straight into the config (not pending), so it
 * holds for running guests too. False when the value is no longer $old or the write failed.
 */
function nexovirt_backup_flag_write(string $type, int $vmid, string $key, string $old, string $new): bool
{
    $perl = 'use strict; use warnings; use PVE::QemuConfig; use PVE::LXC::Config;'
        . ' my $c = $ENV{NX_T} eq "lxc" ? "PVE::LXC::Config" : "PVE::QemuConfig"; my $v = $ENV{NX_VMID};'
        . ' $c->lock_config($v, sub { my $conf = $c->load_config($v);'
        . ' die "changed\n" if !defined($conf->{$ENV{NX_KEY}}) || $conf->{$ENV{NX_KEY}} ne $ENV{NX_OLD};'
        . ' $conf->{$ENV{NX_KEY}} = $ENV{NX_NEW}; $c->write_config($v, $conf); }); print "ok\n";';
    $cmd = 'NX_T=' . escapeshellarg($type) . ' NX_VMID=' . escapeshellarg((string) $vmid) . ' NX_KEY=' . escapeshellarg($key)
        . ' NX_OLD=' . escapeshellarg($old) . ' NX_NEW=' . escapeshellarg($new) . ' perl -e ' . escapeshellarg($perl) . ' 2>&1';

    return trim(nexovirt_run_cmd($cmd, 30)) === 'ok';
}

/** @return list<array{vmid:int,type:string,key:string,set:string,orig:string}> */
function nexovirt_backup_state_read(string $jobId): array
{
    $s = json_decode((string) @file_get_contents(nexovirt_backup_hook_dir() . '/' . $jobId . '.state'), true);

    return is_array($s) ? array_values(array_filter($s, 'is_array')) : [];
}

function nexovirt_backup_state_write(string $jobId, array $state): void
{
    $file = nexovirt_backup_hook_dir() . '/' . $jobId . '.state';
    if ($state === []) {
        @unlink($file);

        return;
    }
    nexovirt_backup_hook_put($file, json_encode(array_values($state)), 0600);
}

/**
 * Put back the recorded changes of one guest ($vmid) or all. A disk whose value is no longer the one the
 * hook set was changed by someone else and is left alone.
 *
 * @return list<string> log lines
 */
function nexovirt_backup_hook_restore(string $jobId, ?int $vmid, callable $write): array
{
    $log  = [];
    $keep = [];
    foreach (nexovirt_backup_state_read($jobId) as $e) {
        if ($vmid !== null && (int) $e['vmid'] !== $vmid) {
            $keep[] = $e;
            continue;
        }
        $cur = nexovirt_backup_conf_value((string) $e['type'], (int) $e['vmid'], (string) $e['key']);
        if ($cur !== (string) $e['set']) {
            $log[] = "NexoVirt: {$e['vmid']} {$e['key']} was changed during the backup, left as is";
            continue;
        }
        $log[] = $write((string) $e['type'], (int) $e['vmid'], (string) $e['key'], (string) $e['set'], (string) $e['orig'])
            ? "NexoVirt: {$e['vmid']} {$e['key']} backup flag restored"
            : "NexoVirt: {$e['vmid']} {$e['key']} could not be restored";
    }
    nexovirt_backup_state_write($jobId, $keep);

    return $log;
}

/**
 * The hook. Never fails the backup.
 *
 * @return list<string> log lines (printed into the vzdump task log)
 */
function nexovirt_backup_hook_run(string $jobId, string $phase, ?int $vmid, ?callable $write = null): array
{
    $write ??= 'nexovirt_backup_flag_write';
    if (! nexovirt_valid_backup_job_id($jobId)) {
        return ['NexoVirt: invalid job id'];
    }
    if (in_array($phase, ['backup-end', 'backup-abort'], true) && $vmid !== null) {
        return nexovirt_backup_hook_restore($jobId, $vmid, $write);
    }
    if (in_array($phase, ['job-end', 'job-abort'], true)) {
        return nexovirt_backup_hook_restore($jobId, null, $write);
    }
    if ($phase !== 'job-start') {
        return [];
    }
    $log = nexovirt_backup_hook_restore($jobId, null, $write); // leftovers of an interrupted run
    $job = json_decode((string) @file_get_contents(nexovirt_backup_hook_dir() . '/' . $jobId . '.json'), true);
    $ok  = nexovirt_validate_backup_hooks(['jobs' => [$jobId => is_array($job) ? $job : []]]);
    if (! $ok['ok']) {
        return array_merge($log, ['NexoVirt: disk selection unreadable, disks are backed up as configured']);
    }
    $state = [];
    foreach ($ok['jobs'][$jobId]['guests'] as $g) {
        foreach ($g['disks'] as $key => $include) {
            $cur = nexovirt_backup_conf_value($g['type'], $g['vmid'], $key);
            if ($cur === null) {
                continue; // guest not on this node, or the disk is gone
            }
            $new = nexovirt_backup_flag_value($cur, $include);
            if ($new === $cur) {
                continue;
            }
            if ($write($g['type'], $g['vmid'], $key, $cur, $new)) {
                $state[] = ['vmid' => $g['vmid'], 'type' => $g['type'], 'key' => $key, 'set' => $new, 'orig' => $cur];
                nexovirt_backup_state_write($jobId, $state); // recorded right away: a crash can always be undone
                $log[] = "NexoVirt: {$g['vmid']} {$key} " . ($include ? 'included in' : 'excluded from') . ' this backup';
            } else {
                $log[] = "NexoVirt: {$g['vmid']} {$key} could not be switched, backed up as configured";
            }
        }
    }

    return $log;
}

/** Put back the changes of jobs that ended without their job-end hook (node crash, killed task). */
function nexovirt_backup_hooks_recover(?callable $write = null, ?callable $backupRunning = null): void
{
    $files = glob(nexovirt_backup_hook_dir() . '/*.state') ?: [];
    if ($files === []) {
        return;
    }
    $running = $backupRunning ?? static function (): bool {
        exec('pgrep -f ' . escapeshellarg(':vzdump:') . ' >/dev/null 2>&1', $o, $code);

        return $code === 0;
    };
    if ($running()) {
        return;
    }
    foreach ($files as $f) {
        nexovirt_backup_hook_restore(basename($f, '.state'), null, $write ?? 'nexovirt_backup_flag_write');
    }
}

// ── Guest network isolation (L2): `isolated on` for the bridge ports of isolated guests ──────────
// The panel sends the full desired set (bridge_isolation_apply: guest vmids of this connection plus
// bridges to leave alone, e.g. SDN project VNets). The main loop re-checks it every second
// (nexovirt_isolation_tick), because PVE recreates a guest's tap/veth on every start. Only ports the
// agent switched on itself are listed in isolation.ports and only those are ever switched off again.
const ISOLATION_STATE_DIR = '/var/lib/nexovirt';
const ISOLATION_MAX_VMIDS = 5000;
const ISOLATION_MAX_SKIP  = 64;

function nexovirt_isolation_net_dir(): string
{
    $d = getenv('NEXOVIRT_AGENT_SYSFS_NET');

    return is_string($d) && $d !== '' ? rtrim($d, '/') : '/sys/class/net';
}

function nexovirt_isolation_dir(): string
{
    $d = getenv('NEXOVIRT_AGENT_ISOLATION_DIR');

    return is_string($d) && $d !== '' ? rtrim($d, '/') : ISOLATION_STATE_DIR;
}

/** @return array{ok:bool,error:string,vmids:list<int>,skip:list<string>} */
function nexovirt_validate_isolation(array $p): array
{
    $bad = static fn (string $e): array => ['ok' => false, 'error' => $e, 'vmids' => [], 'skip' => []];
    $vm  = $p['vmids'] ?? [];
    $sk  = $p['skip_bridges'] ?? [];
    if (! is_array($vm) || count($vm) > ISOLATION_MAX_VMIDS) {
        return $bad('vmids');
    }
    if (! is_array($sk) || count($sk) > ISOLATION_MAX_SKIP) {
        return $bad('skip_bridges');
    }
    $vmids = [];
    foreach ($vm as $v) {
        $s = is_int($v) ? (string) $v : (is_string($v) ? $v : '');
        if (preg_match('/^[1-9]\d{2,8}$/', $s) !== 1) {
            return $bad('vmid');
        }
        $vmids[(int) $s] = (int) $s;
    }
    $skip = [];
    foreach ($sk as $b) {
        if (! is_string($b) || preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/', $b) !== 1) {
            return $bad('bridge');
        }
        $skip[$b] = $b;
    }
    ksort($vmids);
    sort($skip);

    return ['ok' => true, 'error' => '', 'vmids' => array_values($vmids), 'skip' => array_values($skip)];
}

/** The vmid of a guest bridge port name (tap<vmid>i<n>, veth<vmid>i<n>, fwpr<vmid>p<n>), else null. */
function nexovirt_isolation_port_vmid(string $name): ?int
{
    return preg_match('/^(?:tap(\d+)i\d+|veth(\d+)i\d+|fwpr(\d+)p\d+)$/', $name, $m) === 1
        ? (int) ($m[1] !== '' ? $m[1] : ($m[2] !== '' ? $m[2] : $m[3]))
        : null;
}

/**
 * The bridge ports that should be isolated: ports of the listed guests whose master is a bridge
 * that is neither a PVE firewall bridge (fwbr*: the vmbr side is fwpr*) nor skipped.
 *
 * @return list<string>
 */
function nexovirt_isolation_desired(array $vmids, array $skip, string $netDir): array
{
    if ($vmids === []) {
        return [];
    }
    $want = array_flip($vmids);
    $out  = [];
    foreach ((array) @scandir($netDir) as $name) {
        $name = (string) $name;
        $vmid = nexovirt_isolation_port_vmid($name);
        if ($vmid === null || ! isset($want[$vmid]) || ! is_file("{$netDir}/{$name}/brport/isolated")) {
            continue;
        }
        $link   = @readlink("{$netDir}/{$name}/master");
        $master = is_string($link) ? basename($link) : '';
        if ($master === '' || str_starts_with($master, 'fwbr') || in_array($master, $skip, true)) {
            continue;
        }
        $out[] = $name;
    }
    sort($out);

    return $out;
}

/** In-memory state (loaded once from disk): vmids, skip, marked (port => true). */
function nexovirt_isolation_state(): array
{
    if (is_array($GLOBALS['nexovirt_isolation'] ?? null)) {
        return $GLOBALS['nexovirt_isolation'];
    }
    $dir   = nexovirt_isolation_dir();
    $cfg   = @json_decode((string) @file_get_contents($dir . '/isolation.json'), true);
    $v     = nexovirt_validate_isolation(is_array($cfg) ? $cfg : []);
    $state = ['vmids' => $v['ok'] ? $v['vmids'] : [], 'skip' => $v['ok'] ? $v['skip'] : [], 'marked' => []];
    foreach (explode("\n", (string) @file_get_contents($dir . '/isolation.ports')) as $p) {
        if (nexovirt_isolation_port_vmid(trim($p)) !== null) {
            $state['marked'][trim($p)] = true;
        }
    }

    return $GLOBALS['nexovirt_isolation'] = $state;
}

function nexovirt_isolation_save_marked(array $marked): void
{
    $dir = nexovirt_isolation_dir();
    @mkdir($dir, 0755, true);
    $names = array_keys($marked);
    sort($names);
    @file_put_contents($dir . '/isolation.ports', $names === [] ? '' : implode("\n", $names) . "\n");
}

/**
 * One reconcile pass: switch isolation on for desired ports that lost it (recreated tap) and off for
 * ports the agent marked that are no longer desired. Returns the desired ports. Cheap no-op without state.
 *
 * @return list<string>
 */
function nexovirt_isolation_tick(): array
{
    $state = nexovirt_isolation_state();
    if ($state['vmids'] === [] && $state['marked'] === []) {
        return [];
    }
    $net     = nexovirt_isolation_net_dir();
    $desired = nexovirt_isolation_desired($state['vmids'], $state['skip'], $net);
    $marked  = $state['marked'];
    foreach ($desired as $port) {
        $f = "{$net}/{$port}/brport/isolated";
        if (trim((string) @file_get_contents($f)) === '0' && @file_put_contents($f, '1') !== false) {
            $marked[$port] = true;
        }
    }
    $keep = array_flip($desired);
    foreach (array_keys($marked) as $port) {
        if (isset($keep[$port])) {
            continue;
        }
        $f = "{$net}/{$port}/brport/isolated";
        if (is_file($f) && trim((string) @file_get_contents($f)) === '1' && @file_put_contents($f, '0') === false) {
            continue; // retry next pass
        }
        unset($marked[$port]);
    }
    if ($marked !== $state['marked']) {
        nexovirt_isolation_save_marked($marked);
    }
    $state['marked']               = $marked;
    $GLOBALS['nexovirt_isolation'] = $state;

    return $desired;
}

/** bridge_isolation_apply: store the desired set, reconcile at once, report the isolated ports. */
function nexovirt_isolation_apply(array $vmids, array $skip): array
{
    $dir = nexovirt_isolation_dir();
    @mkdir($dir, 0755, true);
    if (@file_put_contents($dir . '/isolation.json', nexovirt_json(['vmids' => $vmids, 'skip_bridges' => $skip])) === false) {
        return ['ok' => false, 'result' => 'could not write ' . $dir . '/isolation.json'];
    }
    $state                         = nexovirt_isolation_state();
    $state['vmids']                = $vmids;
    $state['skip']                 = $skip;
    $GLOBALS['nexovirt_isolation'] = $state;
    $desired                       = nexovirt_isolation_tick();
    $net                           = nexovirt_isolation_net_dir();
    $on                            = array_values(array_filter($desired, static fn ($p) => trim((string) @file_get_contents("{$net}/{$p}/brport/isolated")) === '1'));

    return ['ok' => true, 'result' => nexovirt_json(['isolated' => $on, 'not_isolated' => array_values(array_diff($desired, $on)), 'vmids' => count($vmids)])];
}

/**
 * Heartbeat report (0.28.1): which listed guests have their bridge port isolated right now, which have a
 * port still waiting for the next tick, and which sit only on skipped (SDN project) bridges. Guests
 * without any port (stopped) are in no list. Null without isolation state (nothing to report).
 *
 * @return array{isolated:list<int>,pending:list<int>,sdn:list<int>}|null
 */
function nexovirt_isolation_report(): ?array
{
    $state = nexovirt_isolation_state();
    if ($state['vmids'] === []) {
        return null;
    }
    $net  = nexovirt_isolation_net_dir();
    $want = array_flip($state['vmids']);
    $out  = ['isolated' => [], 'pending' => [], 'sdn' => []];
    foreach (nexovirt_isolation_desired($state['vmids'], $state['skip'], $net) as $port) {
        $vmid = (int) nexovirt_isolation_port_vmid($port);
        $key  = trim((string) @file_get_contents("{$net}/{$port}/brport/isolated")) === '1' ? 'isolated' : 'pending';
        $out[$key][$vmid] = $vmid;
    }
    foreach ((array) @scandir($net) as $name) {
        $vmid = nexovirt_isolation_port_vmid((string) $name);
        if ($vmid === null || ! isset($want[$vmid]) || isset($out['isolated'][$vmid]) || isset($out['pending'][$vmid])) {
            continue;
        }
        $link = @readlink("{$net}/{$name}/master");
        if (is_string($link) && in_array(basename($link), $state['skip'], true)) {
            $out['sdn'][$vmid] = $vmid;
        }
    }
    foreach ($out as $k => $v) {
        sort($v);
        $out[$k] = array_values($v);
    }
    $out['isolated'] = array_values(array_diff($out['isolated'], $out['pending']));

    return $out;
}

/** Sleep $seconds in 1 s steps, keeping port isolation current in between. */
function nexovirt_sleep_with_isolation(int $seconds): void
{
    for ($i = 0; $i < max(1, $seconds); $i++) {
        sleep(1);
        nexovirt_isolation_tick();
    }
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

    if ($type === 'backup_hooks_apply') {
        $v = nexovirt_validate_backup_hooks($p);
        if (! $v['ok']) {
            return ['id' => $id, 'ok' => false, 'result' => 'invalid backup_hooks_apply payload: ' . $v['error']];
        }
        $r = nexovirt_backup_hooks_apply($v['jobs']);
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['result']];
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

    if ($type === 'bridge_isolation_apply') {
        $v = nexovirt_validate_isolation($p);
        if (! $v['ok']) {
            return ['id' => $id, 'ok' => false, 'result' => 'invalid bridge_isolation_apply payload: ' . $v['error']];
        }
        $r = nexovirt_isolation_apply($v['vmids'], $v['skip']);
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

    if ($type === 'nat_inventory') {
        // Read-only (NAT adoption scan + verify); the only field is the validated probe list.
        $r = nexovirt_nat_inventory($p);
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['ok'] ? nexovirt_json($r['result']) : $r['result']];
    }

    if ($type === 'nat_adopt_finalize' || $type === 'nat_adopt_restore') {
        // NAT adoption switch-off / restore: every field is re-validated against the node's own allowlists.
        $dry  = getenv('NEXOVIRT_AGENT_DRYRUN') === '1';
        $root = $dry ? (string) getenv('NEXOVIRT_AGENT_ETC_ROOT') : '';
        $run  = $dry ? nexovirt_nat_adopt_dry_runner() : null;
        $r    = $type === 'nat_adopt_finalize' ? nexovirt_nat_adopt_finalize($p, $root, $run) : nexovirt_nat_adopt_restore($p, $root, $run);
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['ok'] ? nexovirt_json($r['result']) : $r['result']];
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

    if ($type === 'apply_dhcp') {
        // Full desired set of NexoVirt DHCP instances; re-validated fail-closed, refuses next to a foreign DHCP server.
        [$root, $run] = nexovirt_node_ctx($config);
        $r = nexovirt_apply_dhcp($p, $root, $run);
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['result']];
    }

    if ($type === 'apply_fail2ban') {
        [$root, $run] = nexovirt_node_ctx($config);
        $r = nexovirt_apply_fail2ban($p, $root, $run);
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['result']];
    }

    if ($type === 'read_fail2ban') {
        // Read-only; pve_user (validated) picks the panel's lines in pveproxy's access.log.
        [$root, $run] = nexovirt_node_ctx();
        return ['id' => $id, 'ok' => true, 'result' => nexovirt_json(nexovirt_read_fail2ban($root, (string) ($p['pve_user'] ?? ''), $run))];
    }

    if ($type === 'fail2ban_unban') {
        [, $run] = nexovirt_node_ctx();
        $r = nexovirt_f2b_unban((string) ($p['ip'] ?? ''), $run);
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['result']];
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

    if ($type === 'lxc_app_install') {
        // Every field is re-validated here (vmid, script checksum, env names/values, timeout).
        $r = nexovirt_lxc_app_install($p);
        return ['id' => $id, 'ok' => $r['ok'], 'result' => $r['ok'] ? nexovirt_json($r['result']) : $r['error']];
    }

    if ($type === 'lxc_app_status') {
        $vmid = $p['vmid'] ?? null;
        if (! is_int($vmid) || $vmid < 100) {
            return ['id' => $id, 'ok' => false, 'result' => 'invalid lxc_app_status payload'];
        }
        return ['id' => $id, 'ok' => true, 'result' => nexovirt_json(nexovirt_lxc_app_status($vmid, max(0, (int) ($p['offset'] ?? 0))))];
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

// vzdump hook of a backup job with a disk selection (written by backup_hooks_apply).
if (getenv('NEXOVIRT_AGENT_NO_MAIN') !== '1' && ($argv[1] ?? '') === '--vzdump-hook') {
    $hookVmid = isset($argv[5]) && ctype_digit((string) $argv[5]) ? (int) $argv[5] : null;
    foreach (nexovirt_backup_hook_run((string) ($argv[2] ?? ''), (string) ($argv[3] ?? ''), $hookVmid) as $line) {
        fwrite(STDOUT, $line . "\n");
    }
    exit(0);
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
            nexovirt_backup_hooks_recover();
            $sweepLast = time();
        }

        if (! $once) {
            nexovirt_sleep_with_isolation($hadJobs ? 3 : (int) $config['interval']);
        }
    } while (! $once);
}
