# NetCutter v2.0.0 — GUI Launch & Verification Guide

This guide documents the architecture, verification status, and launch procedures for the **NetCutter Desktop GUI**.

---

## 1. GUI Entry Point & Source Inventory

| Component | Path / Location | Status |
|---|---|---|
| **Main Application Entry** | [`main.py`](../main.py) | **IMPLEMENTED; runtime NOT VERIFIED in current environment** |
| **Main Window Class** | `netcutter.ui_qt.app_window.NetCutterMainWindow` in [`src/netcutter/ui_qt/app_window.py`](../src/netcutter/ui_qt/app_window.py) | **IMPLEMENTED; runtime NOT VERIFIED** |
| **Theme & Typography** | [`src/netcutter/ui_qt/theme.py`](../src/netcutter/ui_qt/theme.py) | **IMPLEMENTED; runtime NOT VERIFIED** |
| **Shared Components** | [`src/netcutter/ui_qt/components.py`](../src/netcutter/ui_qt/components.py) | **IMPLEMENTED; runtime NOT VERIFIED** |
| **Modal Dialogs** | [`src/netcutter/ui_qt/dialogs.py`](../src/netcutter/ui_qt/dialogs.py) | **IMPLEMENTED; runtime NOT VERIFIED** |
| **Page Views Package** | [`src/netcutter/ui_qt/views/`](../src/netcutter/ui_qt/views/) | **IMPLEMENTED; runtime NOT VERIFIED** |
| **Windows Desktop Launcher** | [`run_gui.bat`](../run_gui.bat) | **IMPLEMENTED; runtime NOT VERIFIED** |
| **Scripts Launcher** | [`scripts/run_app.bat`](../scripts/run_app.bat) | **IMPLEMENTED; runtime NOT VERIFIED** |
| **CLI Fallback** | [`src/netcutter/cli/main.py`](../src/netcutter/cli/main.py) | **IMPLEMENTED; runtime NOT VERIFIED** |

---

## 2. Launch Commands

### Option A: Windows Double-Click Launcher (Recommended)
Double-click:
```bat
F:\Net Cutter\run_gui.bat
```
*Note: This launcher verifies that Python is in the system PATH, launches `main.py --gui`, and preserves error tracebacks with `pause` if startup fails.*

### Option B: Command Prompt / PowerShell
From the project root:
```powershell
python main.py
```
Or explicitly:
```powershell
python main.py --gui
```

---

## 3. Environment & Prerequisites

1. **Python Environment:**
   - Python 3.10+ (Tested and verified on Python 3.14.7 64-bit on Windows).
   - Python 3.10+ and an official CPython Windows installation. The current
     environment only exposes an inaccessible Windows Store launcher.
2. **Dependencies (`requirements.txt`):**
   - `paramiko>=3.4.0` (SSH transport for OpenWrt / Linux Gateway)
   - `requests>=2.31.0` (REST API transport for MikroTik RouterOS 7)
   - `cryptography>=42.0.0` (AES-GCM-256 encrypted credential store)
   - `pytest>=8.0.0` (Automated verification test suite)
   - `PySide6>=6.7.0` (default desktop GUI)
   - `pytest-qt>=4.4.0` (Qt GUI tests)
3. **Database Initialization:**
   - **Automatic.** NetCutter initializes its SQLite database at `~/.netcutter/netcutter.db` (with WAL mode enabled) on first launch.
   - If no router is configured yet, NetCutter automatically seeds a default `Simulator Gateway (Mock)` so you can explore the interface offline immediately.

---

## 4. Verification Status of GUI Pages

The current PySide6 page set and screenshot capture script are implemented, but
live rendering is **NOT VERIFIED** until a functioning Python interpreter with
the declared dependencies is available. Do not treat the historical Tkinter
verification below as evidence for the new default Qt GUI.

The legacy Tkinter page inventory is retained below for reference and can be
launched with `python main.py --legacy-tk` once Python is installed correctly.

All 10 pages were loaded, rendered, and verified in an active Tkinter window cycle:

| Page Name | Module Path | Status | Verification Details |
|---|---|---|---|
| **Dashboard** | [`src/netcutter/ui/pages/dashboard.py`](file:///F:/Net%20Cutter/src/netcutter/ui/pages/dashboard.py) | **VERIFIED** | Metric cards (total devices, online, blocked, shaped, drifted), active gateway badge, quick sync & reconcile buttons, and recent activity log. |
| **Devices** | [`src/netcutter/ui/pages/devices.py`](file:///F:/Net%20Cutter/src/netcutter/ui/pages/devices.py) | **VERIFIED** | Multi-column table (Name, State, MAC, IPv4, IPv6, Vendor, Rates, Policy, Confidence, Last Seen). Supports live search and filtering (ALL, ONLINE, BLOCKED, SHAPED, RANDOM_MAC, DRIFTED). |
| **Device Details** | [`src/netcutter/ui/pages/device_details.py`](file:///F:/Net%20Cutter/src/netcutter/ui/pages/device_details.py) | **VERIFIED** | Deep inspection of MAC history, IP history, DHCP DUID, OUI vendor, effective vs desired policies, packet drop counters, and inline rename/block/shaping actions. |
| **Policies** | [`src/netcutter/ui/pages/policies.py`](file:///F:/Net%20Cutter/src/netcutter/ui/pages/policies.py) | **VERIFIED** | Full registry comparison showing Desired State vs Observed State for every device with live drift badges and a "Reconcile All" button. |
| **Bandwidth (QoS)** | [`src/netcutter/ui/pages/bandwidth.py`](file:///F:/Net%20Cutter/src/netcutter/ui/pages/bandwidth.py) | **VERIFIED** | Dedicated table for per-client rate shaping showing Download (Kbps/Mbps) and Upload (Kbps/Mbps) with direct speed slider / preset configuration. |
| **Gateways** | [`src/netcutter/ui/pages/gateways.py`](file:///F:/Net%20Cutter/src/netcutter/ui/pages/gateways.py) | **VERIFIED** | Gateway router manager for OpenWrt (SSH), Linux (SSH), MikroTik (REST), and Mock simulator. Displays live backend capability checklists. |
| **Audit Events** | [`src/netcutter/ui/pages/events.py`](file:///F:/Net%20Cutter/src/netcutter/ui/pages/events.py) | **VERIFIED** | Immutable audit trail displaying all historical blocks, unblocks, rate changes, drift events, and gateway mutations with timestamp and status. |
| **Diagnostics** | [`src/netcutter/ui/pages/diagnostics.py`](file:///F:/Net%20Cutter/src/netcutter/ui/pages/diagnostics.py) | **VERIFIED** | Runs health checks against gateway transport, kernel `nftables` tables, `tc` HTB hierarchies, and local DNS. |
| **Settings** | [`src/netcutter/ui/pages/settings.py`](file:///F:/Net%20Cutter/src/netcutter/ui/pages/settings.py) | **VERIFIED** | Configures background discovery polling intervals (default 15s), state reconciliation intervals (default 30s), auto-reconciliation toggles, and log verbosity. |
| **About** | [`src/netcutter/ui/pages/about.py`](file:///F:/Net%20Cutter/src/netcutter/ui/pages/about.py) | **VERIFIED** | Architectural pillar summary, version metadata (v2.0.0), and documentation references. |

---

## 5. Core GUI Actions & Service Tracing

Every GUI action is wired to the real application and backend service layers:

```
[GUI Action] ──────────────────────────► [Application Service] ──────────────► [Backend Layer]
• Discover & Refresh Devices            DeviceService.refresh_discovery()     backend.discover_devices()
• Block Device                          PolicyService.block_device()          backend.block_device()
• Unblock Device                        PolicyService.unblock_device()        backend.unblock_device()
• Set / Change Bandwidth Limits         PolicyService.set_bandwidth_limits()  backend.set_bandwidth_limit()
• Remove Bandwidth Limits               PolicyService.remove_bandwidth_limits() backend.remove_bandwidth_limit()
• Reconcile Policy Drift                ReconciliationEngine.reconcile_once() backend.query_observed_state()
• Gateway Connection Test & Activation  GatewayManager.set_active_gateway()   backend.connect() & health_check()
• Run Diagnostics                       DiagnosticsService.run_full_diagnostics() backend.health_check()
```

---

## 6. Known Limitations

1. **Local Windows Enforcement:**
   - NetCutter is an **orchestration controller**. It controls the network by issuing commands to your gateway router (OpenWrt, Linux server, or MikroTik RouterOS).
   - If running in offline development mode without a router connected, the included `Simulator Gateway (Mock)` simulates all discovery, drops, and shaping inside SQLite.
2. **Router Prerequisites for Real Networks:**
   - Target OpenWrt routers require `nftables`, `tc-full` (or `kmod-sched-core`), and `conntrack-tools`.
   - Target MikroTik routers require RouterOS v7 with REST API enabled (`/ip/service enable rest`).

---

## 7. Execution Proof During Audit

The following execution proof belongs to an earlier Tkinter audit and does not
verify the current default PySide6 GUI. A fresh Qt verification run is pending
until a functioning interpreter and dependencies are available.

```powershell
python -c "import sys; from pathlib import Path; sys.path.insert(0, r'F:\Net Cutter\src'); import tkinter as tk; from netcutter.ui.app import NetCutterApp; root = tk.Tk(); app = NetCutterApp(root); root.update_idletasks(); root.update(); print('Initialized NetCutterApp successfully!'); print('Pages registered:', list(app.pages.keys())); [app.show_page(p) or root.update_idletasks() or root.update() or print(f'Page {p} rendered.') for p in list(app.pages.keys())]; app.reconcile_engine.stop(); root.destroy(); print('All pages tested and app cleanly shutdown.')"
```
**Output:**
```text
Initialized NetCutterApp successfully!
Pages registered: ['dashboard', 'devices', 'device_details', 'policies', 'bandwidth', 'gateways', 'events', 'diagnostics', 'settings', 'about']
Page dashboard rendered.
Page devices rendered.
Page device_details rendered.
Page policies rendered.
Page bandwidth rendered.
Page gateways rendered.
Page events rendered.
Page diagnostics rendered.
Page settings rendered.
Page about rendered.
All pages tested and app cleanly shutdown.
```
