"""
Application Settings Page View for NetCutter.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable, Dict
from netcutter.ui.theme import Theme


class SettingsPage(ttk.Frame):
    def __init__(self, parent, on_save: Callable[[Dict[str, str]], None], **kwargs):
        super().__init__(parent, padding=20, **kwargs)
        self.on_save = on_save

        # Top Bar
        top_bar = ttk.Frame(self)
        top_bar.pack(fill="x", pady=(0, 16))

        ttk.Label(top_bar, text="Application & Engine Settings", style="Header.TLabel").pack(side="left")

        # Form Card
        form_card = ttk.Frame(self, style="Card.TFrame", padding=16)
        form_card.pack(fill="x", pady=(0, 16))

        ttk.Label(form_card, text="Discovery & Reconciliation Timers", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 12))

        # Discovery Interval
        row1 = ttk.Frame(form_card, style="Card.TFrame")
        row1.pack(fill="x", pady=6)
        ttk.Label(row1, text="Discovery Polling Interval (seconds):", style="Card.TLabel", width=32).pack(side="left")
        self.poll_var = tk.StringVar(value="15")
        ttk.Entry(row1, textvariable=self.poll_var, width=10).pack(side="left")

        # Reconcile Interval
        row2 = ttk.Frame(form_card, style="Card.TFrame")
        row2.pack(fill="x", pady=6)
        ttk.Label(row2, text="Reconciliation Interval (seconds):", style="Card.TLabel", width=32).pack(side="left")
        self.reconcile_var = tk.StringVar(value="30")
        ttk.Entry(row2, textvariable=self.reconcile_var, width=10).pack(side="left")

        # Auto reconcile
        row3 = ttk.Frame(form_card, style="Card.TFrame")
        row3.pack(fill="x", pady=8)
        self.auto_rec_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            row3, text="Automatically re-enforce desired policies when drift is detected", variable=self.auto_rec_var
        ).pack(side="left")

        # Logging level
        row4 = ttk.Frame(form_card, style="Card.TFrame")
        row4.pack(fill="x", pady=6)
        ttk.Label(row4, text="Application Logging Level:", style="Card.TLabel", width=32).pack(side="left")
        self.log_var = tk.StringVar(value="INFO")
        ttk.Combobox(
            row4,
            textvariable=self.log_var,
            values=["DEBUG", "INFO", "WARNING", "ERROR"],
            state="readonly",
            width=12,
        ).pack(side="left")

        # Save Button
        ttk.Button(
            self, text="Save Settings", style="Primary.TButton", command=self._do_save
        ).pack(anchor="w", pady=10)

    def _do_save(self):
        settings = {
            "poll_interval": self.poll_var.get().strip(),
            "reconcile_interval": self.reconcile_var.get().strip(),
            "auto_reconcile": str(self.auto_rec_var.get()),
            "log_level": self.log_var.get().strip(),
        }
        self.on_save(settings)
        messagebox.showinfo("Settings Saved", "Application engine settings updated successfully.")
