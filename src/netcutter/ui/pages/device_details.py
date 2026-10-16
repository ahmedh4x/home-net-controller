"""
Device Details Page View for NetCutter.
Provides granular inspection and policy controls for a single device.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import simpledialog, ttk
from typing import Callable, Optional
from netcutter.domain.models import Device, InternetAccessState
from netcutter.ui.components import StatusBadge
from netcutter.ui.theme import Theme


class DeviceDetailsPage(ttk.Frame):
    def __init__(
        self,
        parent,
        on_back: Callable[[], None],
        on_block: Callable[[Device], None],
        on_unblock: Callable[[str], None],
        on_set_bandwidth: Callable[[Device], None],
        on_rename: Callable[[str, str], None],
        **kwargs,
    ):
        super().__init__(parent, padding=20, **kwargs)
        self.on_back = on_back
        self.on_block = on_block
        self.on_unblock = on_unblock
        self.on_set_bandwidth = on_set_bandwidth
        self.on_rename = on_rename
        self.device: Optional[Device] = None

        # Top Navigation & Header
        top_bar = ttk.Frame(self)
        top_bar.pack(fill="x", pady=(0, 16))

        ttk.Button(top_bar, text="← Back to Devices", style="Secondary.TButton", command=self.on_back).pack(side="left")

        self.btn_rename = ttk.Button(top_bar, text="Rename Device", style="Secondary.TButton", command=self._do_rename)
        self.btn_rename.pack(side="right")

        # Header Title Card
        header_card = ttk.Frame(self, style="Card.TFrame", padding=16)
        header_card.pack(fill="x", pady=(0, 16))

        self.lbl_name = ttk.Label(header_card, text="Device Name", style="Header.TLabel")
        self.lbl_name.pack(anchor="w")

        self.lbl_vendor = ttk.Label(header_card, text="Vendor", style="Subheader.TLabel")
        self.lbl_vendor.pack(anchor="w", pady=(2, 8))

        badges_row = ttk.Frame(header_card, style="Card.TFrame")
        badges_row.pack(anchor="w")

        self.badge_online = StatusBadge(badges_row, "ONLINE", "ONLINE")
        self.badge_online.pack(side="left", padx=(0, 8))

        self.badge_policy = StatusBadge(badges_row, "ALLOWED", "ALLOWED")
        self.badge_policy.pack(side="left", padx=(0, 8))

        self.badge_sync = StatusBadge(badges_row, "SYNCHRONIZED", "SYNCHRONIZED")
        self.badge_sync.pack(side="left", padx=(0, 8))

        self.badge_random = StatusBadge(badges_row, "HARDWARE OUI", "DEFAULT")
        self.badge_random.pack(side="left")

        # Two-column layout for Details
        cols = ttk.Frame(self)
        cols.pack(fill="both", expand=True)
        cols.columnconfigure(0, weight=1)
        cols.columnconfigure(1, weight=1)

        # Left Column: Identity & Network
        col_left = ttk.Frame(cols)
        col_left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        # Identity Card
        card_id = ttk.Frame(col_left, style="Card.TFrame", padding=14)
        card_id.pack(fill="x", pady=(0, 12))
        ttk.Label(card_id, text="Identity & Hardware", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 6))

        self.lbl_guid = ttk.Label(card_id, text="GUID: -", font=Theme.FONT_MONO, style="Card.TLabel")
        self.lbl_guid.pack(anchor="w", pady=2)
        self.lbl_mac = ttk.Label(card_id, text="Primary MAC: -", font=Theme.FONT_MONO, style="Card.TLabel")
        self.lbl_mac.pack(anchor="w", pady=2)
        self.lbl_hist_mac = ttk.Label(card_id, text="Historical MACs: -", font=Theme.FONT_MONO, style="Card.TLabel")
        self.lbl_hist_mac.pack(anchor="w", pady=2)
        self.lbl_duid = ttk.Label(card_id, text="DHCP DUID: None", font=Theme.FONT_MONO, style="Card.TLabel")
        self.lbl_duid.pack(anchor="w", pady=2)
        self.lbl_host = ttk.Label(card_id, text="Hostname: -", style="Card.TLabel")
        self.lbl_host.pack(anchor="w", pady=2)
        self.lbl_conf = ttk.Label(card_id, text="Identity Confidence: HIGH", style="Card.TLabel")
        self.lbl_conf.pack(anchor="w", pady=2)

        # Network Card
        card_net = ttk.Frame(col_left, style="Card.TFrame", padding=14)
        card_net.pack(fill="x")
        ttk.Label(card_net, text="IP Addressing & Routing", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 6))

        self.lbl_ipv4 = ttk.Label(card_net, text="IPv4: -", font=Theme.FONT_MONO, style="Card.TLabel")
        self.lbl_ipv4.pack(anchor="w", pady=2)
        self.lbl_ipv6 = ttk.Label(card_net, text="IPv6: -", font=Theme.FONT_MONO, style="Card.TLabel")
        self.lbl_ipv6.pack(anchor="w", pady=2)
        self.lbl_seen = ttk.Label(card_net, text="First / Last Seen: -", style="Card.TLabel")
        self.lbl_seen.pack(anchor="w", pady=2)

        # Right Column: Policy & Enforcement
        col_right = ttk.Frame(cols)
        col_right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        # Internet Control Card
        card_policy = ttk.Frame(col_right, style="Card.TFrame", padding=14)
        card_policy.pack(fill="x", pady=(0, 12))
        ttk.Label(card_policy, text="Internet Access Policy", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 6))

        self.lbl_policy_desc = ttk.Label(card_policy, text="Forwarded Internet Traffic: ALLOWED", style="Card.TLabel")
        self.lbl_policy_desc.pack(anchor="w", pady=4)

        btn_row_pol = ttk.Frame(card_policy, style="Card.TFrame")
        btn_row_pol.pack(anchor="w", pady=6)

        self.btn_block = ttk.Button(
            btn_row_pol, text="Block Internet Access", style="Danger.TButton", command=self._do_block
        )
        self.btn_block.pack(side="left", padx=(0, 8))

        self.btn_unblock = ttk.Button(
            btn_row_pol, text="Unblock Access", style="Primary.TButton", command=self._do_unblock
        )
        self.btn_unblock.pack(side="left")

        # Bandwidth Limits Card
        card_qos = ttk.Frame(col_right, style="Card.TFrame", padding=14)
        card_qos.pack(fill="x", pady=(0, 12))
        ttk.Label(card_qos, text="Bandwidth & Traffic Shaping (QoS)", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 6))

        self.lbl_dl = ttk.Label(card_qos, text="Download Limit: Unlimited", style="Card.TLabel")
        self.lbl_dl.pack(anchor="w", pady=2)
        self.lbl_ul = ttk.Label(card_qos, text="Upload Limit: Unlimited", style="Card.TLabel")
        self.lbl_ul.pack(anchor="w", pady=2)

        ttk.Button(
            card_qos, text="Configure Bandwidth Limits", style="Secondary.TButton", command=self._do_bandwidth
        ).pack(anchor="w", pady=6)

        # Live Kernel Enforcement Card
        card_enf = ttk.Frame(col_right, style="Card.TFrame", padding=14)
        card_enf.pack(fill="x")
        ttk.Label(card_enf, text="Gateway Kernel Enforcement State", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 6))

        self.lbl_enf_set = ttk.Label(card_enf, text="Firewall Set: Not Present", font=Theme.FONT_MONO, style="Card.TLabel")
        self.lbl_enf_set.pack(anchor="w", pady=2)
        self.lbl_enf_tc = ttk.Label(card_enf, text="QoS Classes: None", font=Theme.FONT_MONO, style="Card.TLabel")
        self.lbl_enf_tc.pack(anchor="w", pady=2)
        self.lbl_enf_drops = ttk.Label(card_enf, text="Kernel Drops: 0 packets", style="Card.TLabel")
        self.lbl_enf_drops.pack(anchor="w", pady=2)
        self.lbl_enf_err = ttk.Label(card_enf, text="Last Error: None", font=Theme.FONT_SMALL, foreground=Theme.ACCENT_RED, style="Card.TLabel")
        self.lbl_enf_err.pack(anchor="w", pady=2)

    def load_device(self, device: Device):
        self.device = device
        self.lbl_name.configure(text=device.display_name)
        self.lbl_vendor.configure(text=f"Vendor: {device.vendor or 'Unknown Hardware Vendor'}")

        self.badge_online.update_status(
            "ONLINE" if device.is_online else "OFFLINE",
            "ONLINE" if device.is_online else "OFFLINE",
        )
        self.badge_policy.update_status(
            device.desired_policy.internet_access.value,
            device.desired_policy.internet_access.value,
        )
        self.badge_sync.update_status(
            device.policy_status.value,
            device.policy_status.value,
        )
        self.badge_random.update_status(
            "RANDOMIZED MAC" if device.is_randomized_mac else "HARDWARE OUI",
            "WARNING" if device.is_randomized_mac else "DEFAULT",
        )

        self.lbl_guid.configure(text=f"Device GUID: {device.device_guid}")
        self.lbl_mac.configure(text=f"Primary MAC: {device.primary_mac}")
        self.lbl_hist_mac.configure(text=f"Historical MACs: {', '.join(device.historical_macs)}")
        self.lbl_duid.configure(text=f"DHCP DUID: {device.duid or 'None'}")
        self.lbl_host.configure(text=f"Hostname: {device.hostname or 'Unassigned'}")
        self.lbl_conf.configure(text=f"Identity Confidence: {device.confidence_level.value}")

        self.lbl_ipv4.configure(text=f"IPv4 Addresses: {', '.join(device.ipv4_addresses) or 'None'}")
        self.lbl_ipv6.configure(text=f"IPv6 Addresses: {', '.join(device.ipv6_addresses) or 'None'}")
        self.lbl_seen.configure(
            text=f"First Seen: {device.first_seen.strftime('%Y-%m-%d %H:%M')} | Last: {device.last_seen.strftime('%H:%M:%S')}"
        )

        # Policy & QoS
        is_blocked = device.desired_policy.is_blocked
        self.lbl_policy_desc.configure(
            text=f"Forwarded Internet Traffic: {'BLOCKED (Drops Enforced)' if is_blocked else 'ALLOWED'}"
        )
        self.lbl_dl.configure(
            text=f"Download Limit: {device.desired_policy.download_limit_kbps} Kbps"
            if device.desired_policy.download_limit_kbps
            else "Download Limit: Unlimited"
        )
        self.lbl_ul.configure(
            text=f"Upload Limit: {device.desired_policy.upload_limit_kbps} Kbps"
            if device.desired_policy.upload_limit_kbps
            else "Upload Limit: Unlimited"
        )

        # Enforcement
        obs_blocked = device.observed_policy.is_blocked
        self.lbl_enf_set.configure(
            text=f"nftables Set: @blocked_macs contains {device.primary_mac}"
            if obs_blocked
            else "nftables Set: Unrestricted (Not in @blocked_macs)"
        )
        self.lbl_enf_tc.configure(
            text=f"tc HTB Leaf: DL={device.observed_policy.download_limit_kbps}k UL={device.observed_policy.upload_limit_kbps}k"
            if (device.observed_policy.has_download_limit or device.observed_policy.has_upload_limit)
            else "tc HTB Leaf: Default Unthrottled Class"
        )
        self.lbl_enf_err.configure(text=f"Last Error: {device.last_policy_error or 'None'}")

    def _do_rename(self):
        if not self.device:
            return
        new_name = simpledialog.askstring("Rename Device", "Enter new display name:", initialvalue=self.device.display_name)
        if new_name and new_name.strip():
            self.on_rename(self.device.device_guid, new_name.strip())

    def _do_block(self):
        if self.device:
            self.on_block(self.device)

    def _do_unblock(self):
        if self.device:
            self.on_unblock(self.device.device_guid)

    def _do_bandwidth(self):
        if self.device:
            self.on_set_bandwidth(self.device)
