"""
Diagnostics & Health Verification Page View for NetCutter.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional
from netcutter.diagnostics.health import DiagnosticsReport
from netcutter.ui.components import StatusBadge
from netcutter.ui.theme import Theme


class DiagnosticsPage(ttk.Frame):
    def __init__(self, parent, on_run_diagnostics: Callable[[], None], **kwargs):
        super().__init__(parent, padding=20, **kwargs)
        self.on_run_diagnostics = on_run_diagnostics

        # Top Bar
        top_bar = ttk.Frame(self)
        top_bar.pack(fill="x", pady=(0, 16))

        ttk.Label(top_bar, text="System Diagnostics & Path Verification", style="Header.TLabel").pack(side="left")

        ttk.Button(
            top_bar, text="Run Full Diagnostics", style="Primary.TButton", command=self.on_run_diagnostics
        ).pack(side="right")

        # Health Summary Card
        self.summary_card = ttk.Frame(self, style="Card.TFrame", padding=16)
        self.summary_card.pack(fill="x", pady=(0, 16))

        self.lbl_target = ttk.Label(self.summary_card, text="Target: No Gateway Selected", style="CardTitle.TLabel")
        self.lbl_target.pack(anchor="w")

        self.badge_overall = StatusBadge(self.summary_card, "UNKNOWN", "UNKNOWN")
        self.badge_overall.pack(anchor="w", pady=6)

        # Checks Container
        self.checks_frame = ttk.Frame(self)
        self.checks_frame.pack(fill="both", expand=True)

    def set_report(self, report: DiagnosticsReport):
        self.lbl_target.configure(text=f"Target: {report.gateway_name} (Checked at {report.timestamp.strftime('%H:%M:%S UTC')})")
        
        overall_str = "SYSTEM HEALTHY" if report.overall_healthy else "ISSUES DETECTED"
        badge_type = "ONLINE" if report.overall_healthy else "OFFLINE"
        self.badge_overall.update_status(overall_str, badge_type)

        for w in self.checks_frame.winfo_children():
            w.destroy()

        for check in report.checks:
            card = ttk.Frame(self.checks_frame, style="Card.TFrame", padding=14)
            card.pack(fill="x", pady=4)

            top = ttk.Frame(card, style="Card.TFrame")
            top.pack(fill="x")

            status_str = "PASS" if check.passed else "FAIL"
            b_type = "ONLINE" if check.passed else "OFFLINE"
            badge = StatusBadge(top, status_str, b_type)
            badge.pack(side="left", padx=(0, 10))

            ttk.Label(top, text=check.name, font=Theme.FONT_BODY_BOLD, style="Card.TLabel").pack(side="left")

            ttk.Label(card, text=check.details, style="Card.TLabel").pack(anchor="w", pady=(6, 0))
