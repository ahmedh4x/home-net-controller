# Changelog

All notable changes to **Home Net Controller (HNC)** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.0.1] - 2026-10-16
 
 ### Added
 - **Windows-Exclusive Architecture:** Engineered, verified, and packaged strictly for Microsoft Windows 10 and 11 x64, with native Windows DPAPI key protection and Windows LAN Npcap off-path packet interception.
 - **Modern Obsidian Desktop GUI:** High-performance desktop shell built on PySide6 / Qt 6 featuring custom vector SVGs, high-contrast cyan (`#00f0ff`) and emerald (`#10b981`) accents, dark card surfaces, responsive layouts, and zero console popup windows.
 - **Dual-Binary Windows Packaging:** Dedicated windowed executable (`HomeNetController.exe`) and standalone CLI (`hnc-cli.exe`) produced via PyInstaller.
 - **Website & Domain Blocking:** Domain policy enforcement supporting exact and subdomain wildcard rules with offline regex validation and real-time DNS interception.
 - **Real-Time Per-Device Traffic Accounting:** Continuous byte and packet counters tracking live upload and download bandwidth rates.
 - **Multi-Tier Device Identity Engine:** Fingerprinting categorizing devices across 10 hardware types with vendor OUI lookup and randomized MAC detection.
 - **Hardware Gateway Drivers:** Support for remote OpenWrt (`nftables` / `tc`), Linux routers, and MikroTik RouterOS 7 REST API managed from the Windows controller.
 - **Off-Path Windows LAN Mode:** Layer-2 ARP packet orchestration for unmanaged home networks with strict self-exclusion invariants.
 - **Safety Watchdogs & Emergency Recovery:** Pre-flight target validation preventing gateway or controller disruption and automatic restoration timers.
 - **Windows DPAPI Secret Store:** Root credential vault protected via Windows Data Protection API (DPAPI) and AES-GCM-256 authenticated encryption with automatic migration from plaintext keys.
 - **Hardened MikroTik TLS:** Enforced TLS certificate verification by default with support for pinned SHA256 fingerprints for self-signed certificates.
 - **Privacy-Preserving AI Assistant:** Local deterministic diagnostic engine by default; strictly opt-in external LLM egress (`HNC_ENABLE_AI_EGRESS=1`) with automated IP/MAC pseudonymization and credential redaction.
 - **Crash Recovery & Ring Buffer:** Global unhandled exception catching, sanitized stack trace logging, and single-click diagnostic support bundle generator.
 - **Comprehensive Windows Test Suite:** 111 automated tests passing on Windows across Python 3.11 and 3.12.
