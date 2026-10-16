"""
About Page View for NetCutter.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from netcutter.ui.theme import Theme


class AboutPage(ttk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, padding=24, **kwargs)

        ttk.Label(self, text="NetCutter Network Control System", style="Header.TLabel").pack(anchor="w", pady=(0, 4))
        ttk.Label(self, text="Version 2.0.0 (Production Release)", style="Subheader.TLabel").pack(anchor="w", pady=(0, 20))

        card = ttk.Frame(self, style="Card.TFrame", padding=18)
        card.pack(fill="both", expand=True)

        desc = (
            "NetCutter is an authorized network management and policy enforcement tool built on\n"
            "Gateway-Native Architecture (OpenWrt Linux & MikroTik RouterOS 7).\n\n"
            "Key Architectural Pillars:\n"
            "• True Forwarding-Path Drops: Kernel nftables dynamic sets at priority -10\n"
            "• Bidirectional Traffic Shaping: WAN egress & LAN bridge egress HTB hierarchies with fq_codel\n"
            "• Mandatory IPv6 Parity: Zero-leakage dual-stack blocking using Layer-2 ether saddr\n"
            "• Desired vs Observed State: Continuous background reconciliation loop with drift detection\n"
            "• Identity Stability: DeviceGuid anchoring, OUI resolution, and MAC randomization heuristics\n"
            "• Zero Shell Injection: Strict parameter tokenization and AES-GCM-256 credential encryption\n\n"
            "Architecture Decision Records (ADRs) are documented in docs/ADRs/.\n"
        )
        ttk.Label(card, text=desc, style="Card.TLabel", justify="left").pack(anchor="w")
