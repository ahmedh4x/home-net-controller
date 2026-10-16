# Home Net Controller (HNC) — System Architecture & Engineering Specifications

## 1. Executive Architectural Blueprint

Home Net Controller is built on a **Controller Orchestration + Gateway-Native Enforcement** paradigm. The application separates management and observation from packet-forwarding enforcement.

```
+-----------------------------------------------------------------------------------------+
|                                    DESKTOP GUI LAYER                                    |
|                                                                                         |
|   Dashboard      Devices      Policies     Bandwidth      Gateways     Diagnostics      |
+--------------------------------------------+--------------------------------------------+
                                             | (Service Calls)
                                             v
+-----------------------------------------------------------------------------------------+
|                                APPLICATION SERVICES LAYER                               |
|                                                                                         |
|  DeviceService      IdentityEngine     PolicyService      ReconciliationEngine          |
|  (Discovery Sync)   (OUI / LAA / DUID) (Block / QoS)      (Desired vs Observed Drift)   |
+--------------------------------------------+--------------------------------------------+
                                             | (Repository CRUD)
                                             v
+-----------------------------------------------------------------------------------------+
|                                   PERSISTENCE LAYER                                     |
|                                                                                         |
|  SQLite Database (WAL Mode)               SecretStore (AES-GCM-256)                     |
|  - Devices, Gateways, Audit, Settings     - Windows DPAPI-Protected Master Key          |
+--------------------------------------------+--------------------------------------------+
                                             | (Backend Invocation)
                                             v
+-----------------------------------------------------------------------------------------+
|                                GATEWAY ABSTRACTION LAYER                                |
|                                                                                         |
|  IGatewayBackend Contract & BackendCapabilities Flag Set                                |
|         |                                  |                                 |          |
|         v                                  v                                 v          |
|  OpenWrtBackend                   LinuxGatewayBackend             MikroTikBackend       |
|  (SSH / ubus / leases)            (SSH / nftables / tc)           (RouterOS 7 REST API) |
+-----------------------------------------------------------------------------------------+
```

## 2. Packet Flow & Enforcement Mechanics

### Internet Blocking (Drops)
- Drops are applied exclusively to the Linux kernel **forward** chain at `priority -10`.
- Priority -10 executes *before* fw4 (priority 0) and *before* conntrack `established : accept` or hardware flowtable offloading (`flowtable ft`).
- Dropping via dynamic nftables sets (`ether saddr @blocked_macs counter drop`) provides $O(1)$ memory lookup efficiency.
- Because Layer-2 Ethernet source matching is utilized, **both IPv4 and IPv6 packets from the client are dropped with 100% certainty**, eliminating IPv6 privacy address bypasses.
- Local router services (DNS on port 53, DHCP on port 67) connect to the `input` chain and remain untouched.

### Traffic Shaping (QoS)
- **Upload:** Shaped on the router's **WAN interface egress** using pre-NAT packet marks (`meta mark set 0x100 + id`) applied in PREROUTING mangle before SNAT masquerade. HTB leaf classes enforce `rate` and `ceil` with `fq_codel` leaf queues to eliminate bufferbloat.
- **Download:** Shaped on the router's **LAN bridge egress** (`br-lan`) matching destination client IP.
