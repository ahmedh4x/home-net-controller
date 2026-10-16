"""
Modal Dialogs for NetCutter Desktop Application.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable, Optional
from netcutter.domain.models import BackendType, Device, GatewayConfig
from netcutter.ui.theme import Theme


class BlockDeviceDialog(tk.Toplevel):
    """Explicit confirmation dialog before blocking Internet access."""
    def __init__(self, parent, device: Device, on_confirm: Callable[[], None]):
        super().__init__(parent)
        self.device = device
        self.on_confirm = on_confirm
        self.title("Confirm Internet Block")
        self.geometry("480x360")
        self.resizable(False, False)
        self.configure(bg=Theme.BG_DARK)
        self.transient(parent)
        self.grab_set()

        # Header warning banner
        banner = tk.Frame(self, bg=Theme.ACCENT_RED, height=8)
        banner.pack(fill="x")

        pad = ttk.Frame(self, padding=20)
        pad.pack(fill="both", expand=True)

        lbl_title = ttk.Label(pad, text="Block Internet Access?", style="Header.TLabel")
        lbl_title.pack(anchor="w", pady=(0, 10))

        lbl_desc = ttk.Label(
            pad,
            text=(
                f"You are about to block Internet traffic for:\n"
                f"• Device: {device.display_name}\n"
                f"• MAC Address: {device.primary_mac}\n"
                f"• IPv4: {device.primary_ipv4}\n"
                f"• IPv6: {device.primary_ipv6}\n\n"
                f"This will drop all forwarded WAN traffic on the gateway router\n"
                f"while preserving local network / router access."
            ),
            style="Subheader.TLabel",
            justify="left",
        )
        lbl_desc.pack(anchor="w", pady=(0, 20))

        btn_box = ttk.Frame(pad)
        btn_box.pack(fill="x", side="bottom")

        btn_cancel = ttk.Button(btn_box, text="Cancel", style="Secondary.TButton", command=self.destroy)
        btn_cancel.pack(side="left", padx=(0, 10))

        btn_block = ttk.Button(
            btn_box, text="Confirm Block", style="Danger.TButton", command=self._do_confirm
        )
        btn_block.pack(side="right")

    def _do_confirm(self):
        self.destroy()
        self.on_confirm()


class BandwidthDialog(tk.Toplevel):
    """Configures independent download and upload traffic rate limits."""
    PRESETS = [
        ("Unlimited", 0),
        ("512 Kbps", 512),
        ("1 Mbps", 1024),
        ("2 Mbps", 2048),
        ("5 Mbps", 5120),
        ("10 Mbps", 10240),
        ("20 Mbps", 20480),
        ("50 Mbps", 51200),
        ("100 Mbps", 102400),
    ]

    def __init__(
        self,
        parent,
        device: Device,
        on_save: Callable[[int, int], None],
    ):
        super().__init__(parent)
        self.device = device
        self.on_save = on_save
        self.title("Configure Bandwidth Shaping")
        self.geometry("520x440")
        self.resizable(False, False)
        self.configure(bg=Theme.BG_DARK)
        self.transient(parent)
        self.grab_set()

        pad = ttk.Frame(self, padding=20)
        pad.pack(fill="both", expand=True)

        ttk.Label(
            pad, text=f"Bandwidth Limits: {device.display_name}", style="Header.TLabel"
        ).pack(anchor="w", pady=(0, 15))

        # Download Limit Section
        card_dl = ttk.Frame(pad, style="Card.TFrame", padding=12)
        card_dl.pack(fill="x", pady=(0, 12))
        ttk.Label(card_dl, text="Download Limit (Internet -> Device)", style="CardTitle.TLabel").pack(anchor="w")

        self.dl_var = tk.StringVar(value=str(device.desired_policy.download_limit_kbps))
        row_dl = ttk.Frame(card_dl, style="Card.TFrame")
        row_dl.pack(fill="x", pady=6)
        ttk.Entry(row_dl, textvariable=self.dl_var, width=12).pack(side="left", padx=(0, 6))
        ttk.Label(row_dl, text="Kbps (0 = Unlimited)", style="Card.TLabel").pack(side="left")

        # Preset chips for DL
        chips_dl = ttk.Frame(card_dl, style="Card.TFrame")
        chips_dl.pack(fill="x", pady=4)
        for label, val in [("Unlimited", 0), ("2 Mbps", 2048), ("5 Mbps", 5120), ("10 Mbps", 10240), ("20 Mbps", 20480)]:
            ttk.Button(
                chips_dl,
                text=label,
                style="Secondary.TButton",
                command=lambda v=val: self.dl_var.set(str(v)),
            ).pack(side="left", padx=2)

        # Upload Limit Section
        card_ul = ttk.Frame(pad, style="Card.TFrame", padding=12)
        card_ul.pack(fill="x", pady=(0, 15))
        ttk.Label(card_ul, text="Upload Limit (Device -> Internet)", style="CardTitle.TLabel").pack(anchor="w")

        self.ul_var = tk.StringVar(value=str(device.desired_policy.upload_limit_kbps))
        row_ul = ttk.Frame(card_ul, style="Card.TFrame")
        row_ul.pack(fill="x", pady=6)
        ttk.Entry(row_ul, textvariable=self.ul_var, width=12).pack(side="left", padx=(0, 6))
        ttk.Label(row_ul, text="Kbps (0 = Unlimited)", style="Card.TLabel").pack(side="left")

        # Preset chips for UL
        chips_ul = ttk.Frame(card_ul, style="Card.TFrame")
        chips_ul.pack(fill="x", pady=4)
        for label, val in [("Unlimited", 0), ("1 Mbps", 1024), ("2 Mbps", 2048), ("5 Mbps", 5120), ("10 Mbps", 10240)]:
            ttk.Button(
                chips_ul,
                text=label,
                style="Secondary.TButton",
                command=lambda v=val: self.ul_var.set(str(v)),
            ).pack(side="left", padx=2)

        # Button row
        btn_box = ttk.Frame(pad)
        btn_box.pack(fill="x", side="bottom")

        ttk.Button(btn_box, text="Cancel", style="Secondary.TButton", command=self.destroy).pack(side="left")
        ttk.Button(
            btn_box,
            text="Remove All Limits",
            style="Secondary.TButton",
            command=self._do_remove,
        ).pack(side="left", padx=10)
        ttk.Button(
            btn_box, text="Apply Limits", style="Primary.TButton", command=self._do_apply
        ).pack(side="right")

    def _do_remove(self):
        self.destroy()
        self.on_save(0, 0)

    def _do_apply(self):
        try:
            dl = int(self.dl_var.get().strip())
            ul = int(self.ul_var.get().strip())
            if dl < 0 or ul < 0:
                raise ValueError("Rate values cannot be negative")
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter valid non-negative integer rates in Kbps.")
            return
        self.destroy()
        self.on_save(dl, ul)


class GatewayConfigDialog(tk.Toplevel):
    """Dialog to create or edit a router gateway configuration."""
    def __init__(
        self,
        parent,
        config: Optional[GatewayConfig],
        on_save: Callable[[GatewayConfig, str], None],
        on_test: Callable[[GatewayConfig, str], None],
    ):
        super().__init__(parent)
        self.config = config or GatewayConfig()
        self.on_save = on_save
        self.on_test = on_test
        self.title("Configure Gateway Router")
        self.geometry("540x540")
        self.resizable(False, False)
        self.configure(bg=Theme.BG_DARK)
        self.transient(parent)
        self.grab_set()

        pad = ttk.Frame(self, padding=20)
        pad.pack(fill="both", expand=True)

        ttk.Label(
            pad,
            text="Add / Edit Gateway Router",
            style="Header.TLabel",
        ).pack(anchor="w", pady=(0, 15))

        # Form fields
        form = ttk.Frame(pad, style="Card.TFrame", padding=14)
        form.pack(fill="both", expand=True, pady=(0, 15))

        # Name
        ttk.Label(form, text="Gateway Name:", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w", pady=4)
        self.name_var = tk.StringVar(value=self.config.name)
        ttk.Entry(form, textvariable=self.name_var, width=30).grid(row=0, column=1, sticky="w", pady=4)

        # Host
        ttk.Label(form, text="Host / IP Address:", style="CardTitle.TLabel").grid(row=1, column=0, sticky="w", pady=4)
        self.host_var = tk.StringVar(value=self.config.host)
        ttk.Entry(form, textvariable=self.host_var, width=30).grid(row=1, column=1, sticky="w", pady=4)

        # Port
        ttk.Label(form, text="Port:", style="CardTitle.TLabel").grid(row=2, column=0, sticky="w", pady=4)
        self.port_var = tk.StringVar(value=str(self.config.port))
        ttk.Entry(form, textvariable=self.port_var, width=10).grid(row=2, column=1, sticky="w", pady=4)

        # Backend Type
        ttk.Label(form, text="Backend Type:", style="CardTitle.TLabel").grid(row=3, column=0, sticky="w", pady=4)
        self.type_var = tk.StringVar(value=self.config.backend_type.value)
        types_combo = ttk.Combobox(
            form,
            textvariable=self.type_var,
            values=[b.value for b in BackendType],
            state="readonly",
            width=20,
        )
        types_combo.grid(row=3, column=1, sticky="w", pady=4)

        # Username
        ttk.Label(form, text="Admin Username:", style="CardTitle.TLabel").grid(row=4, column=0, sticky="w", pady=4)
        self.user_var = tk.StringVar(value=self.config.username)
        ttk.Entry(form, textvariable=self.user_var, width=20).grid(row=4, column=1, sticky="w", pady=4)

        # Password
        ttk.Label(form, text="Password / Secret:", style="CardTitle.TLabel").grid(row=5, column=0, sticky="w", pady=4)
        self.pass_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.pass_var, show="•", width=25).grid(row=5, column=1, sticky="w", pady=4)

        # Interfaces
        ttk.Label(form, text="LAN Bridge Interface:", style="CardTitle.TLabel").grid(row=6, column=0, sticky="w", pady=4)
        self.lan_var = tk.StringVar(value=self.config.lan_interface)
        ttk.Entry(form, textvariable=self.lan_var, width=15).grid(row=6, column=1, sticky="w", pady=4)

        ttk.Label(form, text="WAN Interface:", style="CardTitle.TLabel").grid(row=7, column=0, sticky="w", pady=4)
        self.wan_var = tk.StringVar(value=self.config.wan_interface)
        ttk.Entry(form, textvariable=self.wan_var, width=15).grid(row=7, column=1, sticky="w", pady=4)

        # Buttons
        btn_box = ttk.Frame(pad)
        btn_box.pack(fill="x", side="bottom")

        ttk.Button(btn_box, text="Cancel", style="Secondary.TButton", command=self.destroy).pack(side="left")
        ttk.Button(
            btn_box, text="Test Connection", style="Secondary.TButton", command=self._do_test
        ).pack(side="left", padx=10)
        ttk.Button(
            btn_box, text="Save Gateway", style="Primary.TButton", command=self._do_save
        ).pack(side="right")

    def _collect_config(self) -> GatewayConfig:
        port = int(self.port_var.get().strip()) if self.port_var.get().strip().isdigit() else 22
        return GatewayConfig(
            gateway_id=self.config.gateway_id,
            name=self.name_var.get().strip() or "Gateway",
            host=self.host_var.get().strip() or "192.168.1.1",
            port=port,
            backend_type=BackendType(self.type_var.get()),
            username=self.user_var.get().strip() or "root",
            lan_interface=self.lan_var.get().strip() or "br-lan",
            wan_interface=self.wan_var.get().strip() or "eth1",
        )

    def _do_test(self):
        cfg = self._collect_config()
        self.on_test(cfg, self.pass_var.get())

    def _do_save(self):
        cfg = self._collect_config()
        self.destroy()
        self.on_save(cfg, self.pass_var.get())
