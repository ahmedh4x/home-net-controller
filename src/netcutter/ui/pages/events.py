"""
Audit & Event History Page View for NetCutter.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, List
from netcutter.domain.events import AuditEvent
from netcutter.ui.components import SearchBar
from netcutter.ui.theme import Theme


class EventsPage(ttk.Frame):
    def __init__(self, parent, on_refresh: Callable[[], None], **kwargs):
        super().__init__(parent, padding=20, **kwargs)
        self.on_refresh = on_refresh
        self._events: List[AuditEvent] = []
        self._search_query: str = ""

        # Top Bar
        top_bar = ttk.Frame(self)
        top_bar.pack(fill="x", pady=(0, 16))

        ttk.Label(top_bar, text="Audit Trail & Enforcement History", style="Header.TLabel").pack(side="left")

        ttk.Button(top_bar, text="Refresh Logs", style="Secondary.TButton", command=self.on_refresh).pack(side="right")

        # Search Bar
        self.search_bar = SearchBar(self, on_search=self._on_search, placeholder="Search audit logs...")
        self.search_bar.pack(fill="x", pady=(0, 12))

        # Events Table Card
        table_frame = ttk.Frame(self, style="Card.TFrame", padding=12)
        table_frame.pack(fill="both", expand=True)

        columns = ("timestamp", "action", "target", "details", "status", "error")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        self.tree.heading("timestamp", text="Timestamp (UTC)")
        self.tree.heading("action", text="Action")
        self.tree.heading("target", text="Target Device")
        self.tree.heading("details", text="Operation Details")
        self.tree.heading("status", text="Status")
        self.tree.heading("error", text="Error Diagnostic")

        self.tree.column("timestamp", width=140, anchor="w")
        self.tree.column("action", width=160, anchor="w")
        self.tree.column("target", width=150, anchor="w")
        self.tree.column("details", width=380, anchor="w")
        self.tree.column("status", width=90, anchor="center")
        self.tree.column("error", width=180, anchor="w")

        scrollbar_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar_y.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar_y.pack(side="right", fill="y")

    def set_events(self, events: List[AuditEvent]):
        self._events = events
        self._render()

    def _on_search(self, query: str):
        self._search_query = query.lower().strip()
        self._render()

    def _render(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        for ev in self._events:
            if self._search_query:
                haystack = f"{ev.action.value} {ev.device_name or ''} {ev.details} {ev.status} {ev.error or ''}".lower()
                if self._search_query not in haystack:
                    continue

            self.tree.insert(
                "",
                "end",
                values=(
                    ev.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    ev.action.value,
                    ev.device_name or "Gateway",
                    ev.details,
                    ev.status,
                    ev.error or "-",
                ),
            )
