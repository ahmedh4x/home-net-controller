"""
Devices Page View for NetCutter.
Searchable, filterable table of discovered network clients.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable, List, Optional
from netcutter.domain.models import Device, InternetAccessState, PolicyStatus
from netcutter.ui.components import SearchBar
from netcutter.ui.theme import Theme


class DevicesPage(ttk.Frame):
    def __init__(
        self,
        parent,
        on_open_device: Callable[[str], None],
        on_block_device: Callable[[Device], None],
        on_unblock_device: Callable[[str], None],
        on_set_bandwidth: Callable[[Device], None],
        on_refresh: Callable[[], None],
        **kwargs,
    ):
        super().__init__(parent, padding=20, **kwargs)
        self.on_open_device = on_open_device
        self.on_block_device = on_block_device
        self.on_unblock_device = on_unblock_device
        self.on_set_bandwidth = on_set_bandwidth
        self.on_refresh = on_refresh

        self._devices: List[Device] = []
        self._search_query: str = ""
        self._filter_type: str = "ALL"

        # Top Control Bar
        top_bar = ttk.Frame(self)
        top_bar.pack(fill="x", pady=(0, 16))

        ttk.Label(top_bar, text="Connected Devices", style="Header.TLabel").pack(side="left")

        btn_box = ttk.Frame(top_bar)
        btn_box.pack(side="right")
        ttk.Button(
            btn_box, text="Refresh Discovery", style="Primary.TButton", command=self.on_refresh
        ).pack(side="left", padx=4)

        # Filters and Search Bar Row
        filter_bar = ttk.Frame(self)
        filter_bar.pack(fill="x", pady=(0, 12))

        self.search_bar = SearchBar(filter_bar, on_search=self._on_search)
        self.search_bar.pack(side="left", fill="x", expand=True, padx=(0, 12))

        filter_card = ttk.Frame(filter_bar, style="Card.TFrame", padding=(8, 4))
        filter_card.pack(side="right")
        ttk.Label(filter_card, text="Filter:", style="CardTitle.TLabel").pack(side="left", padx=(4, 6))

        self.filter_var = tk.StringVar(value="ALL")
        combo = ttk.Combobox(
            filter_card,
            textvariable=self.filter_var,
            values=["ALL", "ONLINE", "BLOCKED", "SHAPED", "RANDOM_MAC", "DRIFTED"],
            state="readonly",
            width=14,
        )
        combo.pack(side="left")
        combo.bind("<<ComboboxSelected>>", lambda _: self._on_filter_changed())

        # Devices Table
        table_frame = ttk.Frame(self, style="Card.TFrame", padding=12)
        table_frame.pack(fill="both", expand=True)

        columns = (
            "name", "status", "mac", "ipv4", "ipv6", "vendor", "dl", "ul", "policy", "sync", "confidence", "last_seen"
        )
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        
        self.tree.heading("name", text="Device Name")
        self.tree.heading("status", text="State")
        self.tree.heading("mac", text="MAC Address")
        self.tree.heading("ipv4", text="IPv4")
        self.tree.heading("ipv6", text="IPv6")
        self.tree.heading("vendor", text="Vendor / OUI")
        self.tree.heading("dl", text="Download")
        self.tree.heading("ul", text="Upload")
        self.tree.heading("policy", text="Internet")
        self.tree.heading("sync", text="Sync State")
        self.tree.heading("confidence", text="Confidence")
        self.tree.heading("last_seen", text="Last Seen")

        self.tree.column("name", width=150, anchor="w")
        self.tree.column("status", width=70, anchor="center")
        self.tree.column("mac", width=130, anchor="w")
        self.tree.column("ipv4", width=110, anchor="w")
        self.tree.column("ipv6", width=140, anchor="w")
        self.tree.column("vendor", width=140, anchor="w")
        self.tree.column("dl", width=80, anchor="center")
        self.tree.column("ul", width=80, anchor="center")
        self.tree.column("policy", width=80, anchor="center")
        self.tree.column("sync", width=100, anchor="center")
        self.tree.column("confidence", width=80, anchor="center")
        self.tree.column("last_seen", width=90, anchor="w")

        scrollbar_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        self.tree.pack(side="top", fill="both", expand=True)
        scrollbar_y.pack(side="right", fill="y")
        scrollbar_x.pack(side="bottom", fill="x")

        self.tree.bind("<Double-1>", self._on_double_click)

        # Bottom Quick Action Bar
        action_bar = ttk.Frame(self)
        action_bar.pack(fill="x", pady=(12, 0))

        ttk.Button(
            action_bar, text="Open Device Details", style="Primary.TButton", command=self._action_open
        ).pack(side="left", padx=4)

        ttk.Button(
            action_bar, text="Block Selected", style="Danger.TButton", command=self._action_block
        ).pack(side="left", padx=4)

        ttk.Button(
            action_bar, text="Unblock Selected", style="Secondary.TButton", command=self._action_unblock
        ).pack(side="left", padx=4)

        ttk.Button(
            action_bar, text="Set Bandwidth", style="Secondary.TButton", command=self._action_bandwidth
        ).pack(side="left", padx=4)

    def set_devices(self, devices: List[Device]):
        self._devices = devices
        self._apply_filter()

    def _on_search(self, query: str):
        self._search_query = query.lower().strip()
        self._apply_filter()

    def _on_filter_changed(self):
        self._filter_type = self.filter_var.get()
        self._apply_filter()

    def _apply_filter(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        for dev in self._devices:
            # Check filter dropdown
            if self._filter_type == "ONLINE" and not dev.is_online:
                continue
            if self._filter_type == "BLOCKED" and not dev.desired_policy.is_blocked:
                continue
            if self._filter_type == "SHAPED" and not (dev.desired_policy.has_download_limit or dev.desired_policy.has_upload_limit):
                continue
            if self._filter_type == "RANDOM_MAC" and not dev.is_randomized_mac:
                continue
            if self._filter_type == "DRIFTED" and dev.policy_status != PolicyStatus.DRIFTED:
                continue

            # Check search query
            if self._search_query:
                haystack = f"{dev.display_name} {dev.primary_mac} {' '.join(dev.ipv4_addresses)} {' '.join(dev.ipv6_addresses)} {dev.hostname or ''} {dev.vendor or ''}".lower()
                if self._search_query not in haystack:
                    continue

            dl_str = f"{dev.desired_policy.download_limit_kbps}k" if dev.desired_policy.download_limit_kbps else "Unlim"
            ul_str = f"{dev.desired_policy.upload_limit_kbps}k" if dev.desired_policy.upload_limit_kbps else "Unlim"
            status_str = "ONLINE" if dev.is_online else "OFFLINE"
            policy_str = "BLOCKED" if dev.desired_policy.is_blocked else "ALLOWED"

            self.tree.insert(
                "",
                "end",
                iid=dev.device_guid,
                values=(
                    dev.display_name,
                    status_str,
                    dev.primary_mac,
                    dev.primary_ipv4,
                    dev.primary_ipv6,
                    dev.vendor or "Unknown",
                    dl_str,
                    ul_str,
                    policy_str,
                    dev.policy_status.value,
                    dev.confidence_level.value,
                    dev.last_seen.strftime("%H:%M:%S"),
                ),
            )

    def _get_selected_device(self) -> Optional[Device]:
        selected = self.tree.selection()
        if not selected:
            return None
        guid = selected[0]
        return next((d for d in self._devices if d.device_guid == guid), None)

    def _on_double_click(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.on_open_device(item)

    def _action_open(self):
        dev = self._get_selected_device()
        if dev:
            self.on_open_device(dev.device_guid)
        else:
            messagebox.showinfo("Select Device", "Please select a device from the table first.")

    def _action_block(self):
        dev = self._get_selected_device()
        if dev:
            self.on_block_device(dev)
        else:
            messagebox.showinfo("Select Device", "Please select a device from the table first.")

    def _action_unblock(self):
        dev = self._get_selected_device()
        if dev:
            self.on_unblock_device(dev.device_guid)
        else:
            messagebox.showinfo("Select Device", "Please select a device from the table first.")

    def _action_bandwidth(self):
        dev = self._get_selected_device()
        if dev:
            self.on_set_bandwidth(dev)
        else:
            messagebox.showinfo("Select Device", "Please select a device from the table first.")
