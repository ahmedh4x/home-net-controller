"""
Bandwidth & Traffic Shaping (QoS) Page View for NetCutter.
Dedicated controls for per-device rate limiting and queue inspection.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, List, Optional
from netcutter.domain.models import Device
from netcutter.ui.theme import Theme


class BandwidthPage(ttk.Frame):
    def __init__(
        self,
        parent,
        on_set_bandwidth: Callable[[Device], None],
        on_open_device: Callable[[str], None],
        **kwargs,
    ):
        super().__init__(parent, padding=20, **kwargs)
        self.on_set_bandwidth = on_set_bandwidth
        self.on_open_device = on_open_device
        self._devices: List[Device] = []

        # Top Bar
        top_bar = ttk.Frame(self)
        top_bar.pack(fill="x", pady=(0, 16))

        ttk.Label(top_bar, text="Bandwidth Control & Traffic Shaping (QoS)", style="Header.TLabel").pack(side="left")

        # Explanatory card
        info_card = ttk.Frame(self, style="Card.TFrame", padding=14)
        info_card.pack(fill="x", pady=(0, 16))
        ttk.Label(
            info_card,
            text=(
                "Architecture: Independent Bidirectional Shaping (HTB + fq_codel / CAKE)\n"
                "• Upload: Shaped on WAN interface egress using pre-NAT packet marks.\n"
                "• Download: Shaped on LAN bridge egress towards internal client destination IP.\n"
                "• Active rate changes apply in real-time without restarting router network services."
            ),
            style="Card.TLabel",
        ).pack(anchor="w")

        # Table Card
        table_frame = ttk.Frame(self, style="Card.TFrame", padding=12)
        table_frame.pack(fill="both", expand=True)

        columns = ("device", "mac", "ipv4", "dl_rate", "ul_rate", "dl_mbps", "ul_mbps", "sync_state")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        self.tree.heading("device", text="Device Name")
        self.tree.heading("mac", text="MAC Address")
        self.tree.heading("ipv4", text="IPv4 Address")
        self.tree.heading("dl_rate", text="Download (Kbps)")
        self.tree.heading("ul_rate", text="Upload (Kbps)")
        self.tree.heading("dl_mbps", text="Download (Mbps)")
        self.tree.heading("ul_mbps", text="Upload (Mbps)")
        self.tree.heading("sync_state", text="Queue State")

        self.tree.column("device", width=160, anchor="w")
        self.tree.column("mac", width=130, anchor="w")
        self.tree.column("ipv4", width=120, anchor="w")
        self.tree.column("dl_rate", width=110, anchor="center")
        self.tree.column("ul_rate", width=110, anchor="center")
        self.tree.column("dl_mbps", width=110, anchor="center")
        self.tree.column("ul_mbps", width=110, anchor="center")
        self.tree.column("sync_state", width=110, anchor="center")

        scrollbar_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar_y.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar_y.pack(side="right", fill="y")

        # Bottom Actions
        act_bar = ttk.Frame(self)
        act_bar.pack(fill="x", pady=(12, 0))

        ttk.Button(
            act_bar, text="Modify Bandwidth Limit", style="Primary.TButton", command=self._action_edit
        ).pack(side="left", padx=4)

        ttk.Button(
            act_bar, text="Open Device Details", style="Secondary.TButton", command=self._action_details
        ).pack(side="left", padx=4)

    def set_devices(self, devices: List[Device]):
        self._devices = devices
        for item in self.tree.get_children():
            self.tree.delete(item)

        for d in devices:
            dl_kbps = d.desired_policy.download_limit_kbps
            ul_kbps = d.desired_policy.upload_limit_kbps
            dl_mbps = f"{dl_kbps/1024.0:.1f} Mbps" if dl_kbps else "Unlimited"
            ul_mbps = f"{ul_kbps/1024.0:.1f} Mbps" if ul_kbps else "Unlimited"
            dl_str = f"{dl_kbps} Kbps" if dl_kbps else "Unlimited"
            ul_str = f"{ul_kbps} Kbps" if ul_kbps else "Unlimited"

            self.tree.insert(
                "",
                "end",
                iid=d.device_guid,
                values=(
                    d.display_name,
                    d.primary_mac,
                    d.primary_ipv4,
                    dl_str,
                    ul_str,
                    dl_mbps,
                    ul_mbps,
                    d.policy_status.value,
                ),
            )

    def _get_selected(self) -> Optional[Device]:
        sel = self.tree.selection()
        if not sel:
            return None
        guid = sel[0]
        return next((d for d in self._devices if d.device_guid == guid), None)

    def _action_edit(self):
        dev = self._get_selected()
        if dev:
            self.on_set_bandwidth(dev)

    def _action_details(self):
        dev = self._get_selected()
        if dev:
            self.on_open_device(dev.device_guid)
