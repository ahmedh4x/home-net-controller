# Home Net Controller Windows Executable Build & Validation Guide

**Target Application:** Home Net Controller Desktop (Windows 10/11 x64)  
**Distribution Type:** Standalone Windows Distribution (`dist/HomeNetController/HomeNetController.exe` & `dist/HomeNetController/hnc-cli.exe`)  
**Specification:** `hnc.spec`

---

## 1. Prerequisites

- Python 3.10+ (x64) installed with development tools.
- Home Net Controller dependencies: `pip install -e .` or `pip install -r requirements.txt`.
- PyInstaller: `pip install pyinstaller>=6.0.0`.
- (Optional for off-path ARP redirection): Npcap installed with "WinPcap API-compatible mode".

---

## 2. Reproducible Build Steps

To generate a clean standalone executable build:

```cmd
# Clean previous build artifacts
rmdir /s /q build dist

# Run PyInstaller build
python -m PyInstaller hnc.spec --clean --noconfirm
```

Output directory: `dist\HomeNetController\`  
Main GUI binary: `dist\HomeNetController\HomeNetController.exe`  
Main CLI binary: `dist\HomeNetController\hnc-cli.exe`

---

## 3. Data & Persistence Location

Home Net Controller does **not** write state or configuration into the installation directory, ensuring compatibility with protected locations (`C:\Program Files\`):

- Database path: `%LOCALAPPDATA%\HomeNetController\hnc.db` (with legacy fallback to `%LOCALAPPDATA%\NetCutter\netcutter.db`)
- Encryption master key: `%LOCALAPPDATA%\HomeNetController\master.key` (with user-only ACL)
- Audit log ring buffer: In-memory with optional support bundle export to user-selected folder.

---

## 4. Release Validation Checklist

Before distributing a release build:

- [ ] Verify `hnc-cli.exe --help` executes cleanly and lists all CLI subcommands.
- [ ] Verify `HomeNetController.exe` launches PySide6 desktop GUI and system tray icon without DLL errors.
- [ ] Verify `%LOCALAPPDATA%\HomeNetController\` is created automatically on first run.
- [ ] Verify mock gateway simulation operates without network dependencies.
- [ ] Verify virus scanner / SmartScreen does not flag binary (code-signing recommended for production).
