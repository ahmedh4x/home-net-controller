"""
Modern Dark Theme Styling for NetCutter Desktop Application.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class Theme:
    # Color Palette (Modern Slate Dark)
    BG_DARK = "#0f172a"        # Deep slate background
    BG_CARD = "#1e293b"        # Card / panel background
    BG_CARD_HOVER = "#334155"  # Card hover / selection
    BG_SIDEBAR = "#090d16"     # Left navigation bar
    
    TEXT_PRIMARY = "#f8fafc"   # High contrast text
    TEXT_SECONDARY = "#94a3b8" # Muted text
    TEXT_MUTED = "#64748b"     # Very muted text
    
    ACCENT_BLUE = "#3b82f6"    # Primary action
    ACCENT_BLUE_HOVER = "#2563eb"
    ACCENT_GREEN = "#10b981"   # Success / Online / Allowed
    ACCENT_RED = "#ef4444"     # Danger / Blocked / Error
    ACCENT_RED_HOVER = "#dc2626"
    ACCENT_AMBER = "#f59e0b"   # Warning / Drifted / Medium
    ACCENT_PURPLE = "#8b5cf6"  # Bandwidth / QoS
    
    BORDER_COLOR = "#334155"
    INPUT_BG = "#0f172a"

    # Fonts
    FONT_FAMILY = "Segoe UI" if tk.TkVersion >= 8.5 else "Helvetica"
    FONT_TITLE = (FONT_FAMILY, 16, "bold")
    FONT_SUBTITLE = (FONT_FAMILY, 12, "bold")
    FONT_BODY = (FONT_FAMILY, 10)
    FONT_BODY_BOLD = (FONT_FAMILY, 10, "bold")
    FONT_SMALL = (FONT_FAMILY, 9)
    FONT_MONO = ("Consolas", 9)
    FONT_HERO = (FONT_FAMILY, 24, "bold")

    @classmethod
    def apply(cls, root: tk.Tk) -> None:
        """Configures ttk style database for the dark theme."""
        style = ttk.Style(root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Global backgrounds
        root.configure(bg=cls.BG_DARK)
        
        # Frames
        style.configure("TFrame", background=cls.BG_DARK)
        style.configure("Card.TFrame", background=cls.BG_CARD, relief="flat")
        style.configure("Sidebar.TFrame", background=cls.BG_SIDEBAR)

        # Labels
        style.configure("TLabel", background=cls.BG_DARK, foreground=cls.TEXT_PRIMARY, font=cls.FONT_BODY)
        style.configure("Card.TLabel", background=cls.BG_CARD, foreground=cls.TEXT_PRIMARY, font=cls.FONT_BODY)
        style.configure("CardTitle.TLabel", background=cls.BG_CARD, foreground=cls.TEXT_SECONDARY, font=cls.FONT_BODY_BOLD)
        style.configure("CardValue.TLabel", background=cls.BG_CARD, foreground=cls.TEXT_PRIMARY, font=cls.FONT_HERO)
        style.configure("Header.TLabel", background=cls.BG_DARK, foreground=cls.TEXT_PRIMARY, font=cls.FONT_TITLE)
        style.configure("Subheader.TLabel", background=cls.BG_DARK, foreground=cls.TEXT_SECONDARY, font=cls.FONT_SMALL)

        # Buttons
        style.configure(
            "Primary.TButton",
            background=cls.ACCENT_BLUE,
            foreground="#ffffff",
            font=cls.FONT_BODY_BOLD,
            borderwidth=0,
            padding=(12, 6),
        )
        style.map("Primary.TButton", background=[("active", cls.ACCENT_BLUE_HOVER)])

        style.configure(
            "Danger.TButton",
            background=cls.ACCENT_RED,
            foreground="#ffffff",
            font=cls.FONT_BODY_BOLD,
            borderwidth=0,
            padding=(12, 6),
        )
        style.map("Danger.TButton", background=[("active", cls.ACCENT_RED_HOVER)])

        style.configure(
            "Secondary.TButton",
            background=cls.BG_CARD,
            foreground=cls.TEXT_PRIMARY,
            font=cls.FONT_BODY,
            borderwidth=1,
            relief="solid",
            padding=(10, 5),
        )
        style.map("Secondary.TButton", background=[("active", cls.BG_CARD_HOVER)])

        style.configure(
            "Sidebar.TButton",
            background=cls.BG_SIDEBAR,
            foreground=cls.TEXT_SECONDARY,
            font=cls.FONT_BODY_BOLD,
            borderwidth=0,
            anchor="w",
            padding=(16, 10),
        )
        style.map(
            "Sidebar.TButton",
            background=[("active", cls.BG_CARD), ("selected", cls.BG_CARD)],
            foreground=[("active", cls.TEXT_PRIMARY), ("selected", cls.ACCENT_BLUE)],
        )

        # Treeview (Data Tables)
        style.configure(
            "Treeview",
            background=cls.BG_CARD,
            foreground=cls.TEXT_PRIMARY,
            fieldbackground=cls.BG_CARD,
            font=cls.FONT_BODY,
            rowheight=32,
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background=cls.BG_SIDEBAR,
            foreground=cls.TEXT_PRIMARY,
            font=cls.FONT_BODY_BOLD,
            borderwidth=1,
            relief="flat",
            padding=(8, 8),
        )
        style.map("Treeview", background=[("selected", cls.ACCENT_BLUE)])

        # Entry fields
        style.configure(
            "TEntry",
            fieldbackground=cls.INPUT_BG,
            foreground=cls.TEXT_PRIMARY,
            insertcolor=cls.TEXT_PRIMARY,
            font=cls.FONT_BODY,
            borderwidth=1,
        )

        # Combobox
        style.configure(
            "TCombobox",
            fieldbackground=cls.INPUT_BG,
            background=cls.BG_CARD,
            foreground=cls.TEXT_PRIMARY,
            arrowcolor=cls.TEXT_PRIMARY,
            font=cls.FONT_BODY,
        )

        # Notebook (Tabs)
        style.configure("TNotebook", background=cls.BG_DARK, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=cls.BG_CARD,
            foreground=cls.TEXT_SECONDARY,
            padding=(14, 8),
            font=cls.FONT_BODY_BOLD,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", cls.BG_DARK)],
            foreground=[("selected", cls.ACCENT_BLUE)],
        )
