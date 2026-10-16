"""
Policies Management Page View for NetCutter.
Global registry of all active access and QoS policies with drift reconciliation.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, List
from netcutter.domain.models import Device, PolicyStatus
from netcutter.ui.theme import Theme


class PoliciesPage(ttk.Frame):
    def __init__(
        self,
        parent,
        on_reconcile_all: Callable[[], None],
        on_open_device: Callable[[str], None],
        **kwargs,
    ):
        super().__init__(parent, padding=20, **kwargs)
        self.on_reconcile_all = on_reconcile_all
        self.on_open_device = on_open_device
        self._devices: List[Device] = []

        # Top Control Bar
        top_bar = ttk.Frame(self)
        top_bar.pack(fill="x", pady=(0, 16))

        ttk.Label(top_bar, text="Active Policy Registry & Reconciliation", style="Header.TLabel").pack(side="left")

        ttk.Button(
            top_bar,
            text="Reconcile All Drifted",
            style="Primary.TButton",
            command=self.on_reconcile_all,
        ).pack(side="right")

        # Table Card
        table_frame = ttk.Frame(self, style="Card.TFrame", padding=12)
        table_frame.pack(fill="both", expand=True)

        columns = (
            "device", "mac", "desired_access", "desired_dl", "desired_ul",
            "observed_access", "observed_dl", "observed_ul", "sync_status", "last_sync"
        )
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        self.tree.heading("device", text="Device")
        self.tree.heading("mac", text="MAC")
        self.tree.heading("desired_access", text="Desired Access")
        self.tree.heading("desired_dl", text="Desired DL")
        self.tree.heading("desired_ul", text="Desired UL")
        self.tree.heading("observed_access", text="Observed Access")
        self.tree.heading("observed_dl", text="Observed DL")
        self.tree.heading("observed_ul", text="Observed UL")
        self.tree.heading("sync_status", text="Sync State")
        self.tree.heading("last_sync", text="Last Verified")

        self.tree.column("device", width=140, anchor="w")
        self.tree.column("mac", width=130, anchor="w")
        self.tree.column("desired_access", width=100, anchor="center")
        self.tree.column("desired_dl", width=80, anchor="center")
        self.tree.column("desired_ul", width=80, anchor="center")
        self.tree.column("observed_access", width=100, anchor="center")
        self.tree.column("observed_dl", width=80, anchor="center")
        self.tree.column("observed_ul", width=80, anchor="center")
        self.tree.column("sync_status", width=110, anchor="center")
        self.tree.column("last_sync", width=100, anchor="w")

        scrollbar_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar_y.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar_y.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", self._on_double_click)

    def set_devices(self, devices: List[Device]):
        self._devices = devices
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Show devices that have non-default policy or drift
        for d in devices:
            has_policy = (
                d.desired_policy.is_blocked
                or d.desired_policy.has_download_limit
                or d.desired_policy.has_upload_limit
                or d.policy_status == PolicyStatus.DRIFTED
            )
            if not has_policy:
                continue

            dl_des = f"{d.desired_policy.download_limit_kbps}k" if d.desired_policy.download_limit_kbps else "Unlim"
            ul_des = f"{d.desired_policy.upload_limit_kbps}k" if d.desired_policy.upload_limit_kbps else "Unlim"
            dl_obs = f"{d.observed_policy.download_limit_kbps}k" if d.observed_policy.download_limit_kbps else "Unlim"
            ul_obs = f"{d.observed_policy.upload_limit_kbps}k" if d.observed_policy.upload_limit_kbps else "Unlim"

            self.tree.insert(
                "",
                "end",
                iid=d.device_guid,
                values=(
                    d.display_name,
                    d.primary_mac,
                    d.desired_policy.internet_access.value,
                    dl_des,
                    ul_des,
                    d.observed_policy.internet_access.value,
                    dl_obs,
                    ul_obs,
                    d.policy_status.value,
                    d.last_sync.strftime("%H:%M:%S") if d.last_sync else "Never",
                ),
            )

    def _on_double_click(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.on_open_device(item)
