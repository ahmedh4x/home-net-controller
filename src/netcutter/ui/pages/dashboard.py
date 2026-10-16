"""
Dashboard Page View for NetCutter.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable
from netcutter.domain.models import GatewayStatus, InternetAccessState, PolicyStatus
from netcutter.ui.components import MetricCard, StatusBadge
from netcutter.ui.theme import Theme


class DashboardPage(ttk.Frame):
    def __init__(
        self,
        parent,
        on_refresh: Callable[[], None],
        on_reconcile: Callable[[], None],
        on_open_device: Callable[[str], None],
        **kwargs,
    ):
        super().__init__(parent, padding=20, **kwargs)
        self.on_refresh = on_refresh
        self.on_reconcile = on_reconcile
        self.on_open_device = on_open_device

        # Top Header Bar
        header = ttk.Frame(self)
        header.pack(fill="x", pady=(0, 20))

        ttk.Label(header, text="Operations Dashboard", style="Header.TLabel").pack(side="left")

        btn_box = ttk.Frame(header)
        btn_box.pack(side="right")
        ttk.Button(
            btn_box, text="Sync & Discover", style="Primary.TButton", command=self.on_refresh
        ).pack(side="left", padx=4)
        ttk.Button(
            btn_box, text="Reconcile Drift", style="Secondary.TButton", command=self.on_reconcile
        ).pack(side="left", padx=4)

        # Status strip
        self.strip = ttk.Frame(self, style="Card.TFrame", padding=(12, 10))
        self.strip.pack(fill="x", pady=(0, 20))

        ttk.Label(self.strip, text="Active Gateway:", style="CardTitle.TLabel").pack(side="left", padx=(0, 6))
        self.lbl_gw = ttk.Label(self.strip, text="None", font=Theme.FONT_BODY_BOLD, style="Card.TLabel")
        self.lbl_gw.pack(side="left", padx=(0, 16))

        self.badge_status = StatusBadge(self.strip, "OFFLINE", "OFFLINE")
        self.badge_status.pack(side="left", padx=(0, 24))

        ttk.Label(self.strip, text="IPv4 Forwarding:", style="CardTitle.TLabel").pack(side="left", padx=(0, 6))
        self.badge_ipv4 = StatusBadge(self.strip, "ACTIVE", "ONLINE")
        self.badge_ipv4.pack(side="left", padx=(0, 20))

        ttk.Label(self.strip, text="IPv6 Dual-Stack:", style="CardTitle.TLabel").pack(side="left", padx=(0, 6))
        self.badge_ipv6 = StatusBadge(self.strip, "ACTIVE", "ONLINE")
        self.badge_ipv6.pack(side="left", padx=(0, 20))

        ttk.Label(self.strip, text="Policy Synchronization:", style="CardTitle.TLabel").pack(side="left", padx=(0, 6))
        self.badge_sync = StatusBadge(self.strip, "SYNCHRONIZED", "SYNCHRONIZED")
        self.badge_sync.pack(side="left")

        # Metric Cards Row
        cards_row = ttk.Frame(self)
        cards_row.pack(fill="x", pady=(0, 20))
        cards_row.columnconfigure((0, 1, 2, 3), weight=1, uniform="card")

        self.card_total = MetricCard(cards_row, "Connected Devices", "0", "Discovered on LAN", Theme.ACCENT_BLUE)
        self.card_total.grid(row=0, column=0, padx=6, sticky="nsew")

        self.card_blocked = MetricCard(cards_row, "Blocked Devices", "0", "Internet access severed", Theme.ACCENT_RED)
        self.card_blocked.grid(row=0, column=1, padx=6, sticky="nsew")

        self.card_limited = MetricCard(cards_row, "Bandwidth Shaped", "0", "Active rate throttles", Theme.ACCENT_PURPLE)
        self.card_limited.grid(row=0, column=2, padx=6, sticky="nsew")

        self.card_drift = MetricCard(cards_row, "Policy Drift", "0", "Desynchronized rules", Theme.ACCENT_AMBER)
        self.card_drift.grid(row=0, column=3, padx=6, sticky="nsew")

        # Recent Events Feed Section
        feed_frame = ttk.Frame(self, style="Card.TFrame", padding=16)
        feed_frame.pack(fill="both", expand=True)

        ttk.Label(feed_frame, text="Recent Gateway & Policy Events", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 8))

        columns = ("timestamp", "action", "target", "details", "status")
        self.tree = ttk.Treeview(feed_frame, columns=columns, show="headings", height=8)
        self.tree.heading("timestamp", text="Time (UTC)")
        self.tree.heading("action", text="Action")
        self.tree.heading("target", text="Target Device")
        self.tree.heading("details", text="Details")
        self.tree.heading("status", text="Result")

        self.tree.column("timestamp", width=140, anchor="w")
        self.tree.column("action", width=160, anchor="w")
        self.tree.column("target", width=160, anchor="w")
        self.tree.column("details", width=360, anchor="w")
        self.tree.column("status", width=90, anchor="center")

        scrollbar = ttk.Scrollbar(feed_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def update_view(self, devices, active_gw, recent_events):
        total = len(devices)
        blocked = sum(1 for d in devices if d.desired_policy.is_blocked)
        limited = sum(1 for d in devices if d.desired_policy.has_download_limit or d.desired_policy.has_upload_limit)
        drift = sum(1 for d in devices if d.policy_status == PolicyStatus.DRIFTED)

        self.card_total.set_value(str(total), f"{sum(1 for d in devices if d.is_online)} online now")
        self.card_blocked.set_value(str(blocked), f"{blocked} enforced on gateway")
        self.card_limited.set_value(str(limited), f"{limited} throttled devices")
        self.card_drift.set_value(str(drift), "All synchronized" if drift == 0 else f"{drift} require reconciliation")

        if active_gw:
            self.lbl_gw.configure(text=f"{active_gw.name} ({active_gw.host}) [{active_gw.backend_type.value}]")
            self.badge_status.update_status(active_gw.status.value, active_gw.status.value)
        else:
            self.lbl_gw.configure(text="None")
            self.badge_status.update_status("OFFLINE", "OFFLINE")

        if drift > 0:
            self.badge_sync.update_status("DRIFT DETECTED", "DRIFTED")
        else:
            self.badge_sync.update_status("SYNCHRONIZED", "SYNCHRONIZED")

        # Update event tree
        for item in self.tree.get_children():
            self.tree.delete(item)
        for ev in recent_events[:15]:
            self.tree.insert(
                "",
                "end",
                values=(
                    ev.timestamp.strftime("%H:%M:%S"),
                    ev.action.value,
                    ev.device_name or "Gateway",
                    ev.details,
                    ev.status,
                ),
            )
