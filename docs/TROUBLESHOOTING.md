# Troubleshooting & Diagnostics Guide

## 1. Gateway Status Displays "OFFLINE"
- **SSH Port Closed:** Verify port 22 is open on the router (`nc -zv 192.168.1.1 22`).
- **Wrong Password:** Open Gateways page in the GUI, click "Edit Gateway", re-enter password, and click "Test Connection".
- **MikroTik REST:** Ensure the RouterOS REST service is enabled: `/ip service enable www-ssl` or `www`.

## 2. Blocked Device Still Streams Traffic
- **Conntrack Flows:** Some older Linux kernels lack the `conntrack` userspace CLI. Run `opkg update && opkg install conntrack` on OpenWrt.
- **FastTrack on MikroTik:** In RouterOS, verify that the forward drop rule is placed before the `fasttrack-connection` rule.

## 3. Bandwidth Limit Not Enforced
- **Missing tc modules on OpenWrt:** Ensure `tc-full`, `kmod-sched-core`, and `kmod-sched-cake` packages are installed:
  ```sh
  opkg update
  opkg install tc-full kmod-sched-core kmod-sched-cake
  ```
- **Interface Name Mismatch:** In Gateways settings, ensure LAN bridge is set to `br-lan` and WAN is set to `eth1` (or your actual WAN interface name).

## 4. Policy Drift Detected Badge
- Indicates that the router kernel state was altered out-of-band (e.g. router rebooted or an admin deleted the rule via SSH).
- Click "Reconcile All Drifted" on the Policies page or run `python main.py reconcile`.
