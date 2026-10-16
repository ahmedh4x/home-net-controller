# Supported Router Backends & Capability Matrix

NetCutter defines a dynamic capability model where each backend honestly declares its supported features.

## Capability Matrix

| Capability Flag | OpenWrt 22.03+ / 23.05+ | Generic Linux Gateway | MikroTik RouterOS 7.1+ | Simulator / Mock |
| :--- | :---: | :---: | :---: | :---: |
| **MAC_BLOCKING** | SUPPORTED | SUPPORTED | SUPPORTED (via IP mapping) | SUPPORTED |
| **IPV4_BLOCKING** | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED |
| **IPV6_BLOCKING** | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED |
| **UPLOAD_SHAPING** | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED |
| **DOWNLOAD_SHAPING** | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED |
| **CONNTRACK_FLUSHING** | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED |
| **FASTTRACK_BYPASS** | N/A | N/A | SUPPORTED | N/A |
| **DISCOVERY** | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED |
| **NFTABLES_SETS** | SUPPORTED | SUPPORTED | N/A (Address Lists) | SUPPORTED |
| **TRAFFIC_COUNTERS** | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED |

---

## Backend Configurations

### 1. OpenWrt (Primary Backend)
- **Transport:** SSH over port 22.
- **Prerequisites:** OpenWrt with `nftables`, `tc-full` (or `kmod-sched-cake` / `kmod-sched-core`), `conntrack-tools`.
- **Discovery Sources:** `/tmp/dhcp.leases`, `/proc/net/arp`, `ip -6 neigh show`, `ubus call luci-rpc getDHCPLeases`.
- **Enforcement:** `table inet netcutter` with dynamic sets `blocked_macs`, `blocked_ipv4`, `blocked_ipv6`.

### 2. Linux Gateway (Debian / Ubuntu / Alpine)
- **Transport:** SSH over port 22.
- **Enforcement:** Standard Linux kernel `nftables` + `iproute2` `tc`.

### 3. MikroTik RouterOS 7.1+
- **Transport:** Native HTTPS / HTTP REST API (`/rest/...`) with HTTP Basic Authentication.
- **Enforcement:**
  - Firewalls: `/rest/ip/firewall/address-list` & `/rest/ipv6/firewall/address-list`.
  - Simple Queues: `/rest/queue/simple` with `max-limit=<upload>/<download>`.
  - Connections: `/rest/ip/firewall/connection/remove`.
