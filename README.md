<div align="center">

# Home Net Controller (HNC)

### *Your Home Network. Under Your Control.*

[![Tests](https://img.shields.io/badge/tests-106%20passed-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-blue.svg)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-v0.0.1-orange.svg)](RELEASE_NOTES.md)
[![Author](https://img.shields.io/badge/author-Ahmed%20Ibrahim-cyan.svg)](https://github.com/ahmedh4x)

<p align="center">
  <b>Author & Maintainer:</b> <a href="https://github.com/ahmedh4x">Ahmed Ibrahim</a> |
  <a href="https://www.linkedin.com/in/ahmed-ibrahim-h4x/">LinkedIn</a>
</p>

---

</div>

**Home Net Controller (HNC)** is a production-grade, authoritative network management, policy control, and device visibility system designed for home and small-office environments. It empowers network administrators to discover connected devices, monitor real-time traffic consumption, restrict unauthorized internet access, and enforce domain blocking rules.

Built on an architectural **Dual-Mode Foundation**, HNC provides:
1. **Gateway-Native Enforcement:** Orchestrates forwarding-path filters directly inside router operating systems (OpenWrt `nftables`, Linux router kernel, MikroTik RouterOS 7 REST API) with mandatory IPv6 parity and token-bucket QoS.
2. **Windows LAN Off-Path Fallback:** Provides Layer-2 ARP packet redirection on local unmanaged networks when router SSH or management APIs are unavailable, guarded by strict self-exclusion invariants.

---

## 📑 Table of Contents

- [Key Features](#-key-features)
- [Feature Support Matrix](#-feature-support-matrix)
- [Application Screenshots](#-application-screenshots)
- [Architecture Overview](#-architecture-overview)
- [Technology Stack](#-technology-stack)
- [Installation & First Run](#-installation--first-run)
- [Command-Line Interface (CLI)](#-command-line-interface-cli)
- [Permissions & System Requirements](#-permissions--system-requirements)
- [Privacy & Sanitization Model](#-privacy--sanitization-model)
- [Testing & Quality Verification](#-testing--quality-verification)
- [AI-Assisted Development & Vibe Coding](#-ai-assisted-development--vibe-coding)
- [License & Dependencies](#-license--dependencies)
- [Author & Credits](#-author--credits)

---

## 🌟 Key Features

- **Dual-Binary Distribution:** Built as a native windowed desktop application (`HomeNetController.exe`) with zero black command prompt windows, alongside a dedicated scriptable console binary (`hnc-cli.exe`).
- **Modern Obsidian Visual Interface:** Crafted with high-contrast Cyan (`#00f0ff`) and Emerald (`#10b981`) accent indicators, dark card surfaces, responsive layouts, and unclipped data tables.
- **Multi-Tier Device Intelligence:** 4-tier evidence hierarchy categorizing discovered nodes across 10 hardware types (Smartphones, PCs, Macs, Smart TVs, Gaming Consoles, Routers, IoT) with vendor OUI lookup and randomized MAC detection.
- **Website & Domain Blocking:** Flexible DNS interception rules for specific devices, custom device groups, or entire subnets with wildcard domain support (`*.example.com`).
- **Real-Time Per-Device Traffic Accounting:** Live byte and packet counters tracking upload and download bandwidth rates with exponential smoothing.
- **Continuous State Reconciliation:** Background engine audits router kernel tables every 30 seconds to restore desired state against unexpected reboots or external drift.
- **Host-Bound Encrypted Secret Vault:** Machine-bound AES-GCM-256 authenticated encryption for router credentials with strict OS-level access control lists.
- **Sanitized Crash Reporting:** Global unhandled exception handlers redacting passwords and secret tokens before writing diagnostic support bundles.

---

## 📊 Feature Support Matrix

| Feature | Gateway-Native (OpenWrt / Linux) | RouterOS (MikroTik) | Windows LAN (Off-Path) | Verification Level |
| :--- | :---: | :---: | :---: | :--- |
| **Device Discovery** | ✅ Supported | ✅ Supported | ✅ Supported | **Automated & OS Neighbor Cache** |
| **Evidence Device Classification** | ✅ Supported | ✅ Supported | ✅ Supported | **Unit Tests (10 categories, OUI, randomized MACs)** |
| **Internet Access Blocking** | ✅ Forward Hooks | ✅ Filter Rules | ✅ ARP Redirection | **Unit / Integration Mocks & Historical Physical Device Baseline** |
| **IPv6 Leak Prevention** | ✅ Native Dual-Stack | ✅ Native Dual-Stack | ❌ IPv4 Only | **Automated Driver Tests (Router nftables)** |
| **Bandwidth Rate Limiting (QoS)** | ✅ HTB / fq_codel | ✅ Simple Queue | ❌ Not Supported | **Synthetic QoS Tolerance Tests (tc / RouterOS)** |
| **Website / Domain Blocking** | ✅ dnsmasq / IPSet | ✅ DNS Static | ✅ DNS Intercept | **Automated Domain Tests (10/10 passing)** |
| **Real-Time Traffic Metering** | ✅ Conntrack Bytes | ✅ Queue Counters | ✅ Packet Accounting| **Synthetic Accounting Engine Tests** |
| **Reconciliation & Anti-Drift** | ✅ Kernel Loop | ✅ API Sync Loop | ✅ Watchdog Timer | **Automated State Drift Tests** |

---

## 📸 Application Screenshots

<div align="center">

### Operational Overview Dashboard
*Real-time KPI metrics, device category breakdown pills, and audit trail.*
<img src="docs/screenshots/hnc_demo_dashboard_v001.png" width="900" alt="Dashboard View" />

### Connected Device Inventory
*Proportional data table, evidence-backed device naming, and semantic status indicators.*
<img src="docs/screenshots/hnc_demo_devices_v001.png" width="900" alt="Device Inventory View" />

### Real-Time Live Activity
*Live bandwidth telemetry, transfer rates, and per-device traffic accounting.*
<img src="docs/screenshots/hnc_demo_activity_v001.png" width="900" alt="Live Activity View" />

### Website & Domain Policy Management
*Domain policy creation, scope selection (Device / Group / All), and empty-state guidance.*
<img src="docs/screenshots/hnc_demo_domains_v001.png" width="900" alt="Website Blocking View" />

### About & System Architecture
*Author attribution, architecture pillars, and Apache 2.0 license notice.*
<img src="docs/screenshots/hnc_demo_about_v001.png" width="900" alt="About View" />

</div>

---

## 🏗️ Architecture Overview

```mermaid
flowchart TD
    subgraph UI ["User Interface Layer"]
        GUI["HomeNetController.exe (PySide6 / Qt 6)"]
        CLI["hnc-cli.exe (argparse / JSON API)"]
    end

    subgraph Core ["Application Core & Domain Layer"]
        DS["DeviceService & IdentityEngine"]
        PS["PolicyService & StateEngine"]
        DB["DomainBlockingService"]
        TA["TrafficAccountingService"]
        RE["ReconciliationEngine"]
        HS["HealthMonitoringService"]
    end

    subgraph Storage ["Host Security & Persistence"]
        DBStore[("SQLite (Local AppData)")]
        Vault["SecretStore (AES-GCM-256 Vault)"]
    end

    subgraph Drivers ["Backend Gateway Abstraction"]
        Native["GatewayNativeBackend (OpenWrt / Linux nftables)"]
        MT["MikroTikBackend (RouterOS 7 REST)"]
        WinLAN["WindowsLanInterceptor (Layer-2 ARP Engine)"]
    end

    GUI --> Core
    CLI --> Core
    Core --> Storage
    Core --> Drivers
```

---

## 💻 Technology Stack

- **Primary Language:** Python 3.10+ (Tested against Python 3.14 x64)
- **GUI Desktop Framework:** PySide6 / Qt 6.12
- **Network & Low-Level Packets:** Scapy (Layer-2 ARP manipulation & traffic accounting)
- **Router Management:** Paramiko (SSH client for Linux/OpenWrt), Requests (RouterOS REST API)
- **Security & Encryption:** Cryptography (AES-GCM-256 authenticated encryption)
- **Packaging:** PyInstaller (Dual-binary windowed & console distribution)
- **Testing:** Pytest, pytest-qt

---

## 🚀 Installation & First Run

### Running from Standalone Binaries (Recommended)
1. Download or extract the release archive containing `dist/HomeNetController/`.
2. Launch `HomeNetController.exe` directly as Administrator (required for raw packet inspection and ARP management).
3. The desktop GUI starts with zero terminal window popup.

### Running from Source
```bash
# Clone the repository
git clone https://github.com/ahmedh4x/home-net-controller.git
cd home-net-controller

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Launch the desktop GUI
python main.py
```

---

## ⌨️ Command-Line Interface (CLI)

The CLI executable (`hnc-cli.exe` or `python main.py`) provides headless automation with structured `--json` output:

```bash
# Display CLI version and help
hnc --version
hnc --help

# List discovered devices in JSON format
hnc devices --refresh --json

# Block internet access for a device
hnc block 02:00:00:00:15:4d

# Restore internet access
hnc unblock 02:00:00:00:15:4d

# Add a domain blocking rule
hnc domains add example.com --scope all

# Run health diagnostics
hnc diagnostics --json
```

---

## 🛡️ Privacy & Sanitization Model

Home Net Controller operates under a strict **Zero-Cloud-Egress** philosophy:
- **Local Storage Only:** Device inventory, traffic history, and policy rules are stored strictly on the local workstation in `%LOCALAPPDATA%\NetCutter\` (or `%LOCALAPPDATA%\HomeNetController\`).
- **No Cloud Telemetry:** HNC transmits zero telemetry, tracking events, or usage metrics to external servers.
- **Sanitized Diagnostics:** The built-in diagnostic support bundle generator strips passwords, API tokens, and private keys before exporting diagnostic archives.
- **Demonstration Data:** All screenshots and documentation examples use synthetic RFC 5737 test addresses (`192.0.2.0/24`) and randomized MAC prefixes (`02:00:00:...`).

---

## 🧪 Testing & Quality Verification

NetCutter / Home Net Controller maintains a **100% test pass rate** with 106 automated tests:

```cmd
# Run complete test suite
python -m pytest -v
```

```text
====================== 106 passed, 1 warning in 8.12s =======================
```

---

## 🤖 AI-Assisted Development & Vibe Coding

In accordance with transparent engineering disclosure, parts of Home Net Controller were developed using an **AI-Assisted Pair Programming & Vibe Coding Workflow**:
- **Role of AI Tools:** Automated code refactoring, test fixture design, vector SVG asset generation, and documentation drafting were conducted with the assistance of Google DeepMind's Antigravity (AGY) and OpenAI's Codex CLI.
- **Human Oversight:** All architecture invariants, security self-exclusion rules, hardware validation on real routers, and code reviews were directed and verified by the author, Ahmed Ibrahim.

---

## 📜 License & Dependencies

Home Net Controller source code is licensed under the **[Apache License 2.0](LICENSE)**.

### Third-Party Licenses & Source Code
Home Net Controller utilizes several third-party libraries:
- **PySide6 / Qt 6:** Licensed under LGPLv3 / Commercial (The Qt Company). Dynamically loaded shared libraries. Source code for Qt is available at [https://www.qt.io](https://www.qt.io).
- **Scapy 2.7.0:** Licensed under GNU General Public License v2 (GPLv2). Used as an external packet manipulation tool for Windows LAN off-path redirection in `src/netcutter/backends/windows_lan.py`. In compliance with GPLv2 Section 3, complete machine-readable source code for this project is provided in this repository, and Scapy source is available at [https://github.com/secdev/scapy](https://github.com/secdev/scapy).
- **Paramiko:** Licensed under LGPLv2.1 (SSH router gateway driver). Source is available at [https://github.com/paramiko/paramiko](https://github.com/paramiko/paramiko).
- **Cryptography & Requests:** Licensed under Apache 2.0 / BSD.

See [NOTICE](NOTICE) for full third-party notices and details.

---

## 👤 Author & Credits

**Ahmed Ibrahim**  
*Lead Software Engineer & Maintainer*  
- GitHub: [@ahmedh4x](https://github.com/ahmedh4x)  
- LinkedIn: [Ahmed Ibrahim](https://www.linkedin.com/in/ahmed-ibrahim-h4x/)
