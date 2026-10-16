"""
Gateways Management Page View for NetCutter.
Add, configure, test, and activate router backends with live capability checklists.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable, Dict, List, Optional
from netcutter.backends.capabilities import format_capabilities_report
from netcutter.domain.models import GatewayConfig
from netcutter.ui.components import StatusBadge
from netcutter.ui.theme import Theme


class GatewaysPage(ttk.Frame):
    def __init__(
        self,
        parent,
        on_add_gw: Callable[[], None],
        on_edit_gw: Callable[[GatewayConfig], None],
        on_delete_gw: Callable[[str], None],
        on_activate_gw: Callable[[str], None],
        on_test_gw: Callable[[GatewayConfig], None],
        **kwargs,
    ):
        super().__init__(parent, padding=20, **kwargs)
        self.on_add_gw = on_add_gw
        self.on_edit_gw = on_edit_gw
        self.on_delete_gw = on_delete_gw
        self.on_activate_gw = on_activate_gw
        self.on_test_gw = on_test_gw
        self._gateways: List[GatewayConfig] = []

        # Top Bar
        top_bar = ttk.Frame(self)
        top_bar.pack(fill="x", pady=(0, 16))

        ttk.Label(top_bar, text="Gateway Routers & Backends", style="Header.TLabel").pack(side="left")

        btn_box = ttk.Frame(top_bar)
        btn_box.pack(side="right")
        ttk.Button(btn_box, text="+ Add Gateway Router", style="Primary.TButton", command=self.on_add_gw).pack(side="left", padx=4)

        # Gateways Table Card
        table_frame = ttk.Frame(self, style="Card.TFrame", padding=12)
        table_frame.pack(fill="x", pady=(0, 16))

        columns = ("active", "name", "host", "port", "backend", "username", "lan", "wan", "status")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=5)

        self.tree.heading("active", text="Active")
        self.tree.heading("name", text="Gateway Name")
        self.tree.heading("host", text="Host / IP")
        self.tree.heading("port", text="Port")
        self.tree.heading("backend", text="Backend Type")
        self.tree.heading("username", text="Username")
        self.tree.heading("lan", text="LAN Bridge")
        self.tree.heading("wan", text="WAN Interface")
        self.tree.heading("status", text="Status")

        self.tree.column("active", width=60, anchor="center")
        self.tree.column("name", width=140, anchor="w")
        self.tree.column("host", width=120, anchor="w")
        self.tree.column("port", width=60, anchor="center")
        self.tree.column("backend", width=110, anchor="center")
        self.tree.column("username", width=90, anchor="w")
        self.tree.column("lan", width=90, anchor="w")
        self.tree.column("wan", width=90, anchor="w")
        self.tree.column("status", width=90, anchor="center")

        self.tree.pack(fill="x")

        # Action Buttons
        gw_btn_bar = ttk.Frame(self)
        gw_btn_bar.pack(fill="x", pady=(0, 20))

        ttk.Button(gw_btn_bar, text="Connect / Set Active", style="Primary.TButton", command=self._action_activate).pack(side="left", padx=4)
        ttk.Button(gw_btn_bar, text="Edit Gateway", style="Secondary.TButton", command=self._action_edit).pack(side="left", padx=4)
        ttk.Button(gw_btn_bar, text="Test Connection", style="Secondary.TButton", command=self._action_test).pack(side="left", padx=4)
        ttk.Button(gw_btn_bar, text="Delete Gateway", style="Danger.TButton", command=self._action_delete).pack(side="right", padx=4)

        # Capabilities Card
        self.cap_card = ttk.Frame(self, style="Card.TFrame", padding=16)
        self.cap_card.pack(fill="both", expand=True)

        ttk.Label(self.cap_card, text="Active Backend Capability Matrix", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 10))

        self.caps_container = ttk.Frame(self.cap_card, style="Card.TFrame")
        self.caps_container.pack(fill="both", expand=True)

    def set_gateways(self, gateways: List[GatewayConfig], active_caps: Dict[str, str]):
        self._gateways = gateways
        for item in self.tree.get_children():
            self.tree.delete(item)

        for gw in gateways:
            active_mark = "★ YES" if gw.is_active else "NO"
            self.tree.insert(
                "",
                "end",
                iid=gw.gateway_id,
                values=(
                    active_mark,
                    gw.name,
                    gw.host,
                    gw.port,
                    gw.backend_type.value,
                    gw.username,
                    gw.lan_interface,
                    gw.wan_interface,
                    gw.status.value,
                ),
            )

        # Render capability checklist
        for widget in self.caps_container.winfo_children():
            widget.destroy()

        self.caps_container.columnconfigure(0, weight=1)
        self.caps_container.columnconfigure(1, weight=1)

        row = 0
        col = 0
        for cap_name, status in active_caps.items():
            cell = ttk.Frame(self.caps_container, style="Card.TFrame", padding=(8, 4))
            cell.grid(row=row, column=col, sticky="w", padx=10, pady=4)
            badge = StatusBadge(cell, status, "ONLINE" if status == "SUPPORTED" else "OFFLINE")
            badge.pack(side="left", padx=(0, 8))
            ttk.Label(cell, text=cap_name, style="Card.TLabel").pack(side="left")
            col += 1
            if col > 1:
                col = 0
                row += 1

    def _get_selected_gw(self) -> Optional[GatewayConfig]:
        sel = self.tree.selection()
        if not sel:
            return None
        gw_id = sel[0]
        return next((g for g in self._gateways if g.gateway_id == gw_id), None)

    def _action_activate(self):
        gw = self._get_selected_gw()
        if gw:
            self.on_activate_gw(gw.gateway_id)
        else:
            messagebox.showinfo("Select Gateway", "Please select a gateway from the list.")

    def _action_edit(self):
        gw = self._get_selected_gw()
        if gw:
            self.on_edit_gw(gw)
        else:
            messagebox.showinfo("Select Gateway", "Please select a gateway from the list.")

    def _action_test(self):
        gw = self._get_selected_gw()
        if gw:
            self.on_test_gw(gw)
        else:
            messagebox.showinfo("Select Gateway", "Please select a gateway from the list.")

    def _action_delete(self):
        gw = self._get_selected_gw()
        if gw:
            if messagebox.askyesno("Confirm Delete", f"Delete gateway '{gw.name}'?"):
                self.on_delete_gw(gw.gateway_id)
        else:
            messagebox.showinfo("Select Gateway", "Please select a gateway from the list.")
