# Quality of Service (QoS) & Bandwidth Shaping Architecture

## Why Classless CAKE Alone Is Insufficient
A common pitfall in network tooling is attempting to use CAKE (`sch_cake`) directly as a per-device rate limiter. CAKE is a classless queueing discipline; it does not support attaching multiple sub-classes with arbitrary bandwidth rates (e.g. 5 Mbps for Client A, 20 Mbps for Client B). CAKE balances flows using fair-share hashing across hosts, but cannot impose asymmetric custom caps per client within a single qdisc instance.

## NetCutter QoS Hierarchy: HTB + fq_codel / CAKE Leafs

```
                    +-----------------------------+
                    |  Root HTB Qdisc (handle 1:) |
                    +--------------+--------------+
                                   |
                +------------------+------------------+
                |                                     |
   +------------v------------+           +------------v------------+
   | Default Class (1:1)     |           | Leaf Class (1:10)       |
   | Rate: Line Rate (1Gbps) |           | Client A: Rate 5M / 5M  |
   +-------------------------+           +------------+------------+
                                                      |
                                         +------------v------------+
                                         | Leaf Qdisc: fq_codel    |
                                         | Eliminates Bufferbloat  |
                                         +-------------------------+
```

## Directionality & NAT Handling
1. **Upload (Client -> WAN):**
   - Packets traverse from `br-lan` to `wan` (`eth1`).
   - SNAT (Masquerade) occurs at `POSTROUTING`, destroying the client's internal IP address.
   - NetCutter tags the packet in `PREROUTING` via nftables `meta mark set 0x100 + id` based on source MAC/IP.
   - The WAN egress HTB filter matches the fwmark: `tc filter add dev wan handle 0x110 fw flowid 1:10`.

2. **Download (WAN -> Client):**
   - Packets arrive on `wan` and are routed to `br-lan`.
   - Conntrack un-masquerades the destination IP back to the internal client IP.
   - HTB on `br-lan` matches destination IP: `tc filter add dev br-lan u32 match ip dst 192.168.1.101 flowid 1:10`.
