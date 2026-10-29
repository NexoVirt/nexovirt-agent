# NexoVirt Host Agent

The node agent of [NexoVirt](https://nexovirt.com), the self-hosted control panel for Proxmox VE.
One standalone PHP file (`nexovirt-agent.php`, version **0.28.5**) that runs as root on a Proxmox VE node,
sends a heartbeat to your NexoVirt panel and runs a fixed, allowlisted set of jobs the panel queues for it.

- Website: [nexovirt.com](https://nexovirt.com)
- Documentation: [docs.nexovirt.com](https://docs.nexovirt.com)
- Panel REST API SDKs: [Python](https://github.com/NexoVirt/nexovirt-python), [Node.js](https://github.com/NexoVirt/nexovirt-node), [C#](https://github.com/NexoVirt/nexovirt-csharp)

This repository is published so you can read and audit exactly what runs as root on your nodes.
You normally never install it by hand: the panel installs, updates and removes it over SSH.

---

## Security model

- **No remote shell.** The agent only runs the job types listed below. Unknown job types are rejected.
- **The agent does not trust the panel.** Every job input is validated on the node (fail-closed) and every
  shell argument is `escapeshellarg`'d. NAT, VPN and firewall changes only touch the agent's own
  `NEXOVIRT-*` chains; built-in and Proxmox chains are never flushed. Non-private MASQUERADE sources,
  internal download targets (SSRF) and https-to-http redirects are refused.
- **No inbound port.** The agent calls the panel over HTTPS (`http://` is refused unless explicitly allowed
  for local development) and picks up jobs from the heartbeat response.
- **Secrets stay off the command line.** Passwords go via STDIN, tokens via 0600 header files; the
  WireGuard host key is generated on the node and never sent.
- **Per-agent token**, revoked when the agent is removed from the panel.

Found a security issue? Please report it privately via [nexovirt.com](https://nexovirt.com) instead of
opening a public issue.

---
## Requirements

- PHP **8.0+** CLI on the PVE node (`apt install php-cli`); the `curl` PHP extension is recommended
  (falls back to `file_get_contents`), `mbstring` optional
- The `curl` binary (image / CT template downloads)
- **HTTPS** access from the node to the panel. The agent refuses to start with an `http://` panel URL
  unless `NEXOVIRT_ALLOW_INSECURE=1` is set (local development only: the token and job payloads,
  including root passwords, would travel unencrypted)

---

## Jobs

| Job | What it does |
|---|---|
| `write_snippet` | Writes a cloud-init vendor snippet into the `local` storage's snippets dir (only `local` is accepted) |
| `ensure_storage` | Idempotently creates a PVE `dir` storage (the managed `nexovirt-images`) |
| `download_image` / `delete_image` | Downloads a QEMU image or CT template into `nexovirt-images` / deletes it. SSRF-guarded (internal, reserved and mapped addresses refused, DNS resolved once and pinned with `--resolve`), redirects followed up to 5 hops with every hop re-validated (no https-to-http downgrade), the result must look like a real image (qcow2 magic, no HTML page), 64 GiB size cap, needs 2 GiB free space. Sends `busy` heartbeats every ~60 s while running |
| `image_cache_start` | (0.24.0) `{url, filename: nxc-<templateId>-<10 hex>.<ext>, expected_sha256?}`: starts a DETACHED download into the image cache (`systemd-run --unit=nexovirt-img-<hash>`, the agent script in `--image-download <file>` mode) and returns at once, so the agent keeps taking jobs. Same SSRF/redirect/content rules as `download_image`, plus: https required unless a SHA-256 is given, resume of an existing `.part` (`curl -C -`), no total time cap (stall guard: under 1 KiB/s for 5 min aborts), free space checked against the remaining Content-Length + 1 GiB while running, SHA-256 computed and verified (mismatch deletes the file). State per file in `<images>/.nexovirt-state/<file>.json`. Every heartbeat carries `stats.images` (name, size, state ready/queued/running/verifying/error/other, bytes, total, sha256, error) and `stats.images_free`. `delete_image` on a cached file also stops its download and removes its state. Stale `.part` files (untouched 24 h, no live download) are swept hourly |
| `apply_nat` / `clear_nat` | Programs / removes NexoVirt NAT + port-forwards in the dedicated `NEXOVIRT-*` iptables chains only |
| `read_firewall`, `read_system`, `read_pve`, `read_logs`, `read_pve_logs` | Read-only host inspection |
| `probe_sdn_dhcp`, `ensure_sdn_dhcp`, `ensure_sdn_egress`, `set_ip_forward` | SDN DHCP backend + IPv4 forwarding (forwarding cannot be turned off while NexoVirt NAT or the NexoVirt VPN is active) |
| `lxc_root_ssh`, `lxc_set_password` | Enable root SSH / set the root password inside an LXC (starts a stopped CT first) |
| `scan_ips` | Ping + ARP sweep of a private CIDR (max /22) for IPAM |
| `probe_tcp` | TCP reachability probe (host = IP or DNS name, port 1-65535, 5s timeout) used by migration pre-flight |
| `guest_unlock` | `pct unlock` / `qm unlock` for one guest (type `lxc`/`qemu`, numeric vmid). PVE leaves a remote-migration source locked and its API cannot remove a container lock |
| `dyndns_configure` | `{enabled, token, endpoint_v4, endpoint_v6}`: writes `/etc/nexovirt-dyndns.hdr` (the `Authorization: Bearer` header) + `/etc/nexovirt-dyndns.conf` (endpoints), both 0600, or removes them when `enabled=false`. Token must be 64 alphanumerics; endpoints must be `https://*.nexovirt.com` (no userinfo, port or query). The agent then calls each endpoint every 300 s with `curl -4`/`-6 -H @/etc/nexovirt-dyndns.hdr`, so the token never appears on a command line |
| `apply_wireguard` | `{enabled, port, address, subnet, peers:[{public_key, preshared_key?, allowed_ips:[own /32, then the device's /32s on other nodes], role: admin\|customer, allow:[/32 or SDN subnet]}], forward_nets:[cidr]}`: installs `wireguard-tools` if missing, generates the host key once (`/etc/nexovirt-wg/private.key`, 0600, never sent), writes `/etc/nexovirt-wg/wg-nexovirt.conf` (0600), brings up / live-syncs `wg-nexovirt`, persists via `nexovirt-wg.service`, and programs the `NEXOVIRT-VPN`, `NEXOVIRT-VPN-IN` and `NEXOVIRT-VPN-NAT` chains (default DROP for wg traffic; admin peers reach every forward net + the host VPN address, customer peers only their `allow` entries: guest /32s, or since 0.23.2 whole SDN project subnets (/16 to /31, network-aligned, never overlapping the VPN subnet, with MASQUERADE from the peer's addresses)). `enabled=false` removes interface, unit, chains and files but keeps the host key. A device's addresses on other nodes get accept rules, a route into the tunnel and MASQUERADE like the own subnet (a multi-node client sends from its first address). The optional per-peer `preshared_key` (base64, 32 bytes, validated like a key) is written as `PresharedKey` and never logged or returned. Subnet, forward nets and allow entries must be RFC1918, port 1024-65535, at most 1000 peers. Result: `{public_key, listening, peers:[{public_key, latest_handshake, rx, tx}]}` |
| `read_wireguard` | Same status as above from `wg show wg-nexovirt dump` (no private or preshared key), plus read-only readiness facts `diag:{wg_tools, iface_up, listen_port, ip_forward, blockers:[INPUT rules before the NEXOVIRT-VPN-IN jump, nftables input hooks with a drop policy, active ufw], local_ipv4}` |
| `apt_refresh` | `apt-get update` (150 s timeout), then `apt list --upgradable` parsed into `[{name, from, to, origin, kernel}]` plus an `apt-get -s dist-upgrade` summary (upgrade/new/remove/kept), the newly installed packages and whether a kernel package is involved. An update error (e.g. 401 from the enterprise repository without a subscription, DNS, a held lock) is returned verbatim with a reason code next to the list. Sends `busy` heartbeats while running |
| `apt_simulate` | `{names:[...]}` (1-500 names matching `^[a-z0-9][a-z0-9+.-]{0,127}$`, escapeshellarg'd): `apt-get -s install --only-upgrade <names>`, returns what would really be upgraded/installed. A selection that would remove packages is refused with the list |
| `apt_upgrade_start` | `{mode: all\|selected, names}`: `dist-upgrade` or `install --only-upgrade <names>` with `DEBIAN_FRONTEND=noninteractive` and `--force-confdef --force-confold`, started DETACHED via `systemd-run --unit=nexovirt-apt-upgrade --collect` (output in `/var/log/nexovirt/apt-upgrade.log`, 0600; exit code in `apt-upgrade.exit`). Refuses while the unit is active or dpkg is locked; returns at once with a run id. Never reboots |
| `apt_upgrade_status` | `{offset}`: `running`/`succeeded`/`failed`/`idle` + exit code, the log after the byte offset (64 KiB per call) and `reboot_required` (newer kernel installed than running, or `/var/run/reboot-required`) |
| `nat_inventory` | (0.24.5) Read-only: the node's NAT rules (iptables-save nat/raw/filter, `nft -a list ruleset`), the NAT lines of `/etc/network/interfaces(.d)`, `/etc/iptables/rules.v4`, `/etc/nftables.conf` + includes, units and interface hooks that set NAT, optional TCP probes (max 32). Used to adopt hand-made NAT |
| `nat_adopt_finalize` | (0.24.5) After an adoption was verified: removes exactly the adopted rules (iptables `-C` then `-D` from the original tokens, nft by handle after re-reading the rule), comments out their source lines with a never-overwritten backup, disables ticked units. Only rules in the adoption scope (nat DNAT/SNAT/MASQUERADE, raw PREROUTING CT, filter FORWARD ACCEPT); refuses unless every NexoVirt replacement rule is live |
| `nat_adopt_restore` | (0.24.5) Undoes a finalize: restores backed-up files only while they still have the switch-off checksum, re-adds absent rules and chains, re-enables units |
| `apply_dhcp` | (0.25.0) Full desired set of DHCP pools on NAT bridges: one `dnsmasq` per bridge (`nexovirt-dhcp@<bridge>`, `port=0`, bind-interfaces), MAC reservations from the guest configs. Refuses a bridge with a foreign DHCP server |
| `apply_fail2ban` / `read_fail2ban` / `fail2ban_unban` | (0.25.1) Web UI login jail: writes only `/etc/fail2ban/{jail,filter}.d/nexovirt-pve.conf` (pvedaemon journal, port 8006), tests the config first, installs fail2ban only when missing, reports existing jails watching 8006, unbans only in its own jail |
| `lxc_app_install` / `lxc_app_status` | (0.25.0) One-click apps: runs a signed catalog install script inside a container (`pct exec`, settings as environment variables, script SHA-256 checked) detached, and reports its status and log tail |
| `backup_hooks_apply` | (0.27.0) Disks per backup job: writes one vzdump hook per backup job to `/var/lib/nexovirt/backup-hooks/<job>.sh` (+ `.json`). The hook sets each listed disk's `backup` flag at job-start (compare-and-set under the Proxmox config lock) and puts the old value back after that guest and at job end; a disk changed meanwhile is left alone, leftovers are restored hourly when no backup runs. Job ids, disk keys (`scsi/sata/ide/virtio N`, `mpN`) and VMIDs are validated |
| `bridge_isolation_apply` | (0.28.0) Guest network isolation, layer 2: `{vmids:[...], skip_bridges:[...]}` is the full list of isolated guests of the connection. Sets `brport/isolated` to 1 on their bridge ports (`tap<vmid>i<n>`, `veth<vmid>i<n>`, `fwpr<vmid>p<n>`; never `fwbr*` or skipped SDN bridges), stores the list in `/var/lib/nexovirt/isolation.{json,ports}` and re-checks every second because Proxmox recreates a port when a guest starts. Only ports the agent switched on itself are ever switched off again. From 0.28.1 the heartbeat reports `isolation:{isolated, pending, sdn}` (guest ids) so the panel can show the status per guest. Since 0.28.2 it fails closed: a state file that cannot be read or validated never un-isolates anything (marked ports stay isolated, the heartbeat reports `error`), and the per-second check also runs inside long jobs. Since 0.28.4 an ARP filter in the agent's own nft table `bridge nexovirt_arp` limits isolated ports with a static IPv4 address: ARP requests only for the gateway or the guest's own address. Since 0.28.5 every ARP packet must carry the guest's own sender IP (0.0.0.0 for probes) and the NIC's configured MAC (Ethernet and ARP sender), RARP and 802.1Q/802.1ad frames from isolated ports are dropped (a PVE trunk NIC keeps only its `trunks=` VLAN ids, single-tagged, with the same ARP checks inside the tag), and a missing table is detected by nft's exit code and re-applied within 30 s. Proxmox firewall tables are never touched; agent removal deletes the table |

Unknown job types are rejected. A job whose handler throws reports a generic error (details go to the
journal) instead of killing the agent. Results that could not be delivered are re-sent with the next
heartbeat (at most 50, dropped after 1 hour).

### NAT and the Proxmox firewall

NAT leaves `net.bridge.bridge-nf-call-iptables` at its default (`1`), so the Proxmox firewall keeps
filtering guest traffic. To make MASQUERADE work for guests behind a PVE firewall bridge (`fwbrN`), the
agent adds the documented Proxmox conntrack-zone rule (`-t raw ... -i fwbr+ -j CT --zone 1`) in its own
`NEXOVIRT-RAW` chain. Agents up to 0.17 set `bridge-nf-call-iptables=0` instead; applying or clearing NAT
with 0.18+ restores it to `1` and removes the old sysctl line and `br_netfilter` modules-load file.

### WireGuard VPN

The VPN lives entirely in its own interface (`wg-nexovirt`), files (`/etc/nexovirt-wg/`), unit
(`nexovirt-wg.service`) and chains (`NEXOVIRT-VPN*`); it never flushes built-in, Proxmox or NAT chains.
Forwarded wg traffic is dropped unless a rule for that peer allows it, so customer devices only reach
their own guests. Guests whose default gateway is not the host still answer because the VPN subnet is
masqueraded towards each forward network. The host must accept UDP on the configured port (forward it
on the router when the host sits behind NAT).

---

## Manual install

```bash
scp nexovirt-agent.php root@<pve-host>:/opt/nexovirt-agent.php

cat > /etc/nexovirt-agent.conf << 'EOF'
NEXOVIRT_URL=https://your-nexovirt-panel.example.com
NEXOVIRT_AGENT_TOKEN=<token from: php spark agent:register --host=<id> "label">
EOF
chmod 600 /etc/nexovirt-agent.conf

php /opt/nexovirt-agent.php --once   # single heartbeat, then exit
```

Systemd unit (`/etc/systemd/system/nexovirt-agent.service`, as written by the panel's onboarding):

```ini
[Unit]
Description=NexoVirt Host Agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/php /opt/nexovirt-agent.php
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now nexovirt-agent
journalctl -u nexovirt-agent -f
```

---

## Configuration reference

Read from the environment, else from `nexovirt-agent.conf` next to the script, else `/etc/nexovirt-agent.conf`.

| Variable | Required | Default | Description |
|---|---|---|---|
| `NEXOVIRT_URL` | Yes | | Panel base URL, must be `https://` |
| `NEXOVIRT_AGENT_TOKEN` | Yes | | Bearer token from `agent:register` |
| `NEXOVIRT_ALLOW_INSECURE` | No | unset | `1` allows an `http://` panel URL (dev only, logs a warning) |
| `NEXOVIRT_CA_BUNDLE` | No | system | CA bundle for a self-signed panel certificate |
| `INTERVAL` | No | `15` | Seconds between heartbeats (min 5; 3 while jobs are flowing) |
| `SNIPPETS_DIR` | No | `/var/lib/vz/snippets` | Target dir for `write_snippet` |
| `NEXOVIRT_IMAGES_DIR` | No | `/var/lib/nexovirt/images` | Base dir of the managed image storage |

---

## Heartbeat

`POST {NEXOVIRT_URL}/api/v1/agent/heartbeat` with `{version, stats, results[]}`. The response may carry
`data.jobs[]`. While a long job runs the agent sends `{..., "results": [], "busy": true}` about every
60 s; the panel then only refreshes `last_seen` and hands out no jobs.

Stats: `hostname`, `uptime`, `loadavg`, `mem_total_kb`, `mem_used_kb`, `mem_free_kb` (fields that
cannot be read are omitted).

---

## License

MIT, see [LICENSE](LICENSE). The NexoVirt panel itself is a separate product: [nexovirt.com](https://nexovirt.com).
