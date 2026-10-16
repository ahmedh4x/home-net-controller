"""
Reusable Modern UI Components for NetCutter.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, List, Optional
from netcutter.ui.theme import Theme


class MetricCard(ttk.Frame):
    """Modern dashboard KPI metric card."""
    def __init__(
        self,
        parent,
        title: str,
        value: str,
        subtitle: str = "",
        accent_color: str = Theme.ACCENT_BLUE,
        **kwargs,
    ):
        super().__init__(parent, style="Card.TFrame", padding=(16, 16), **kwargs)
        self.accent_color = accent_color

        # Accent color strip on top
        strip = tk.Frame(self, bg=accent_color, height=3)
        strip.pack(fill="x", side="top", pady=(0, 8))

        self.lbl_title = ttk.Label(self, text=title, style="CardTitle.TLabel")
        self.lbl_title.pack(anchor="w")

        self.lbl_val = ttk.Label(self, text=value, style="CardValue.TLabel")
        self.lbl_val.pack(anchor="w", pady=(4, 2))

        if subtitle:
            self.lbl_sub = ttk.Label(
                self, text=subtitle, font=Theme.FONT_SMALL, background=Theme.BG_CARD, foreground=Theme.TEXT_MUTED
            )
            self.lbl_sub.pack(anchor="w")

    def set_value(self, value: str, subtitle: Optional[str] = None):
        self.lbl_val.configure(text=value)
        if subtitle is not None and hasattr(self, "lbl_sub"):
            self.lbl_sub.configure(text=subtitle)


class StatusBadge(tk.Label):
    """Pill-shaped colored status badge."""
    def __init__(self, parent, text: str, badge_type: str = "default", **kwargs):
        bg, fg = self._get_colors(badge_type)
        super().__init__(
            parent,
            text=f" {text} ",
            bg=bg,
            fg=fg,
            font=Theme.FONT_SMALL,
            padx=6,
            pady=2,
            relief="flat",
            **kwargs,
        )

    @staticmethod
    def _get_colors(badge_type: str):
        bt = badge_type.upper()
        if bt in ("ONLINE", "ALLOWED", "SYNCHRONIZED", "HIGH", "SUCCESS"):
            return ("#064e3b", "#34d399")  # Dark emerald bg, mint text
        elif bt in ("OFFLINE", "BLOCKED", "FAILED", "DANGER"):
            return ("#7f1d1d", "#f87171")  # Dark red bg, red text
        elif bt in ("DRIFTED", "WARNING", "MEDIUM", "AMBIGUOUS"):
            return ("#78350f", "#fbbf24")  # Dark amber bg, yellow text
        elif bt in ("APPLYING", "AUTHENTICATING", "INFO"):
            return ("#1e3a8a", "#60a5fa")  # Dark blue bg, sky text
        return (Theme.BG_CARD_HOVER, Theme.TEXT_SECONDARY)

    def update_status(self, text: str, badge_type: str):
        bg, fg = self._get_colors(badge_type)
        self.configure(text=f" {text} ", bg=bg, fg=fg)


class SearchBar(ttk.Frame):
    """Search input field with clear button and change callback."""
    def __init__(self, parent, on_search: Callable[[str], None], placeholder: str = "Search devices...", **kwargs):
        super().__init__(parent, style="Card.TFrame", padding=(8, 4), **kwargs)
        self.on_search = on_search
        
        self.var = tk.StringVar()
        self.var.trace_add("write", lambda *_: self.on_search(self.var.get()))

        lbl_icon = ttk.Label(self, text="Search:", style="Card.TLabel", font=Theme.FONT_BODY_BOLD)
        lbl_icon.pack(side="left", padx=(4, 8))

        self.entry = ttk.Entry(self, textvariable=self.var, font=Theme.FONT_BODY, width=35)
        self.entry.pack(side="left", fill="x", expand=True, padx=4)

        btn_clear = ttk.Button(
            self, text="Clear", style="Secondary.TButton", command=lambda: self.var.set("")
        )
        btn_clear.pack(side="right", padx=4)
