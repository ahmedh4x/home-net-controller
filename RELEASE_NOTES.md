# Home Net Controller v0.0.1 — Release Notes

**Author & Maintainer:** Ahmed Ibrahim  
**GitHub:** [https://github.com/ahmedh4x](https://github.com/ahmedh4x)  
**LinkedIn:** [https://www.linkedin.com/in/ahmed-ibrahim-h4x/](https://www.linkedin.com/in/ahmed-ibrahim-h4x/)  
**Initial Public Release:** `v0.0.1` (Public Beta)  
**Target Platform:** Windows 10 / Windows 11 x64 exclusively (Desktop GUI & CLI)  
**License:** Apache License 2.0  
**Verification Baseline:** **111/111 Automated Tests Passed on Windows (100% Green)**  

---

## 🌟 Welcome to Home Net Controller (HNC)

Home Net Controller (HNC) is an open-source Windows desktop network management, policy control, and device intelligence application designed for home and lab environments. It provides visibility into connected network clients, real-time traffic statistics, granular access controls, and domain blocking.

### Core Features

1. **Dual-Binary Windows Architecture:**
   - `HomeNetController.exe`: High-performance windowed desktop GUI built with PySide6 / Qt 6. Completely eliminates unwanted terminal console popups (`console=False`).
   - `hnc-cli.exe`: Standalone automation console tool supporting structured `--json` output across all operational subcommands.
2. **Modern Obsidian Visual Interface:**
   - Dark obsidian surfaces with vivid Cyan (`#00f0ff`) and Emerald (`#10b981`) accent indicators.
   - Bespoke vector SVG icons for all device categories and navigation views.
   - High-density, unclipped data tables with responsive column widths and status badges.
3. **Gateway-Native & Off-Path LAN Dual Modes:**
   - *Gateway-Native Mode (OpenWrt, Linux nftables, MikroTik RouterOS):* Forwarding-path rule management on remote routers with bidirectional HTB rate shaping and IPv6 parity.
   - *Windows LAN Mode (Off-Path):* Layer-2 ARP packet orchestration fallback for local subnets with safety watchdogs and self-exclusion protections.
4. **Website & Domain Blocking:**
   - Offline domain validation supporting exact hostnames and wildcard subdomains.
   - Intercepts UDP/TCP port 53 DNS queries with instant sinkhole response.
5. **Real-Time Traffic Accounting:**
   - Live upload and download bandwidth calculation with per-device attribution and exponential smoothing.
6. **Multi-Tier Device Intelligence:**
   - 4-level evidence hierarchy categorizing discovered nodes across 10 hardware types with vendor OUI lookup and randomized MAC detection.
7. **Windows DPAPI Security & Crash Protection:**
   - Root credential vault protected via Windows Data Protection API (DPAPI) and AES-GCM-256 authenticated encryption.
   - Global exception handling and sanitized diagnostic bundles redacting passwords, private keys, and secret tokens.

---

## 📦 Verified Release Binaries & Checksums

| Artifact | Subsystem | File Size | SHA-256 Checksum |
| :--- | :--- | :--- | :--- |
| `dist/HomeNetController/HomeNetController.exe` | Windows GUI | 9,843,754 bytes | `b6cba6e35c6b174c383d4f9359cd479a389d6cdff3146cad742ddc1457d34bce` |
| `dist/HomeNetController/hnc-cli.exe` | Windows CLI | 9,848,874 bytes | `8db4a3ba831acce682aed0ff263d2f19b28cfa20530b23b55128e40628989784` |
| `HomeNetController-v0.0.1-windows-x64.zip` | Full Portable Bundle | 71,997,758 bytes | `f8de6ce5a6f42bfa363faa05c70feba1920d94ff3955537e3b4f1975a69901ee` |

---

## 🛠️ Automated Verification Suite

- **Total Tests:** 111 passed on Windows
- **Categories Tested:**
  - GUI & Desktop Shell (`test_qt_app.py` - 10 tests)
  - Device Classification Engine (`test_device_classification.py` - 5 tests)
  - Crash Protection & Diagnostics (`test_crash_recovery.py` - 3 tests)
  - Backend Integration & Lifecycle (`test_backends.py` - 3 tests)
  - Database & Repository Persistence (`test_persistence.py` - 2 tests)
  - State Reconciliation Engine (`test_reconciliation.py` - 1 test)
  - QoS Traffic Shaping (`test_qos_shaping.py` - 1 test)
  - AI Assistant & Deterministic Engine (`test_ai_assistant.py` - 4 tests)
  - AI Privacy & Redaction Engine (`test_ai_privacy.py` - 2 tests)
  - Headless CLI Automation (`test_cli.py` - 7 tests)
  - Domain & Website Blocking (`test_domain_blocking.py` - 10 tests)
  - Enforcement Supervisor & Safety Watchdog (`test_enforcement_supervisor.py` - 5 tests)
  - Hardened Router Enforcement & TLS Pinning (`test_hardened_enforcement.py` - 8 tests)
  - Identity Resolution & MAC Normalization (`test_identity.py` - 5 tests)
  - Installation Service & Dependency Doctor (`test_installation_service.py` - 5 tests)
  - Logging & Sanitized Support Bundles (`test_logging_and_support_bundle.py` - 4 tests)
  - Mock Backend Fault Injection (`test_mock_fault_injection.py` - 4 tests)
  - Health Monitoring & Safe Mode (`test_notification_and_health.py` - 2 tests)
  - Policy Differencing Engine (`test_policy_diff.py` - 5 tests)
  - Policy Preview & Pre-Flight Gating (`test_policy_preview.py` - 3 tests)
  - Windows DPAPI Secret Vault & Migration (`test_secret_store.py` - 3 tests)
  - Network State Finite Machine (`test_state_engine.py` - 5 tests)
  - Traffic Accounting & LANtern Integration (`test_traffic_accounting.py` - 5 tests)
  - Windows LAN Interceptor Safety (`test_windows_lan.py` - 9 tests)
