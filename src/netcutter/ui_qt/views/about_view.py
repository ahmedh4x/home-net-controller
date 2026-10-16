"""
About and Architecture Summary View for NetCutter.
Displays version v2.0.0, author credits, Apache 2.0 licensing, and core technical pillars.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional
from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from netcutter.common.paths import get_asset_path
from netcutter.ui_qt.components import PageHeader, StatusBadge
from netcutter.ui_qt.theme import Theme


class AboutView(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(24, 20, 24, 20)
        outer_layout.setSpacing(16)

        header = PageHeader(
            title="About Home Net Controller",
            subtitle="Your Home Network. Under Your Control.",
        )
        outer_layout.addWidget(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background: transparent;")

        scroll_widget = QWidget()
        layout = QVBoxLayout(scroll_widget)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(16)

        # 1. Hero Brand & Creator Card
        hero_card = QFrame()
        hero_card.setObjectName("SurfaceCard")
        hero_layout = QHBoxLayout(hero_card)
        hero_layout.setContentsMargins(24, 24, 24, 24)
        hero_layout.setSpacing(20)

        # Logo Mark
        mark_path = get_asset_path("hnc-mark.png")
        if not mark_path.exists():
            mark_path = get_asset_path("netcutter-mark.png")
        lbl_logo = QLabel()
        if mark_path.exists():
            pix = QPixmap(str(mark_path)).scaled(80, 80, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            lbl_logo.setPixmap(pix)
        lbl_logo.setFixedSize(80, 80)
        hero_layout.addWidget(lbl_logo)

        # Title & Author Credit
        hero_text = QVBoxLayout()
        hero_text.setSpacing(6)

        title_row = QHBoxLayout()
        title = QLabel("Home Net Controller")
        title.setStyleSheet(f"font-size: 24px; font-weight: 800; color: #ffffff; letter-spacing: 1px;")
        title_row.addWidget(title)

        badge_ver = StatusBadge("v0.0.1", variant="info")
        title_row.addWidget(badge_ver)
        badge_lic = StatusBadge("APACHE 2.0", variant="success")
        title_row.addWidget(badge_lic)
        title_row.addStretch()
        hero_text.addLayout(title_row)

        creator_lbl = QLabel("Author & Maintainer: Ahmed Ibrahim")
        creator_lbl.setStyleSheet(f"font-size: 15px; font-weight: 700; color: {Theme.ACCENT_PRIMARY}; margin-top: 2px;")
        hero_text.addWidget(creator_lbl)

        links_lbl = QLabel("<a href='https://github.com/ahmedh4x' style='color:#00e5ff; text-decoration:none;'>GitHub: @ahmedh4x</a> &nbsp;|&nbsp; <a href='https://www.linkedin.com/in/ahmed-ibrahim-h4x/' style='color:#00e5ff; text-decoration:none;'>LinkedIn</a>")
        links_lbl.setOpenExternalLinks(True)
        links_lbl.setStyleSheet("font-size: 13px; margin-top: 2px;")
        hero_text.addWidget(links_lbl)

        desc = QLabel(
            "Home Net Controller (HNC) is an authoritative, high-assurance desktop controller for modern network environments. "
            "It orchestrates native router forwarding-path filters directly inside router operating systems (OpenWrt, generic Linux nftables, "
            "MikroTik RouterOS 7), delivering IPv6 parity, token-bucket QoS, and state reconciliation, alongside an off-path Windows LAN fallback."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 13px; line-height: 1.5; margin-top: 4px;")
        hero_text.addWidget(desc)

        hero_layout.addLayout(hero_text, stretch=1)
        layout.addWidget(hero_card)

        # 2. Key Technical Pillars Card
        pillars_card = QFrame()
        pillars_card.setObjectName("SurfaceCard")
        p_layout = QVBoxLayout(pillars_card)
        p_layout.setContentsMargins(20, 18, 20, 18)
        p_layout.setSpacing(12)

        pillars_title = QLabel("Core Technical Pillars")
        pillars_title.setStyleSheet("font-size: 15px; font-weight: 700; color: #ffffff;")
        p_layout.addWidget(pillars_title)

        bullets = [
            ("Gateway-Native Forwarding Drops", "Enforcement drops occur at forward hook priority -10, strictly pre-routing before conntrack acceptance or hardware flowtable offloading."),
            ("Dual-Stack IPv4 / IPv6 Parity", "Strict Layer-2 Ethernet source matching in the inet family prevents IPv6 SLAAC address evasion and bypass attacks."),
            ("Token-Bucket Hierarchical QoS", "HTB hierarchies paired with fq_codel leaf queues systematically eliminate bufferbloat and enforce fair bandwidth limits."),
            ("Self-Healing State Reconciliation", "Background engine periodically audits live router kernel tables, instantly detecting external reboots or rule drifts and recovering state idempotently."),
            ("Windows LAN Off-Path Interceptor", "High-safety local subnet controller with automated atexit ARP table restoration, gateway preservation invariants, and per-target lockouts."),
            ("Zero-Trust Security Vault", "Host-bound AES-GCM-256 authenticated encryption for router credentials with zero cleartext credentials stored on disk."),
        ]

        for heading, body in bullets:
            b_layout = QVBoxLayout()
            b_layout.setSpacing(2)
            h = QLabel(f"• <b>{heading}</b>")
            h.setStyleSheet("color: #ffffff; font-size: 13px;")
            b = QLabel(f"   {body}")
            b.setWordWrap(True)
            b.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 12px; margin-left: 12px;")
            b_layout.addWidget(h)
            b_layout.addWidget(b)
            p_layout.addLayout(b_layout)

        layout.addWidget(pillars_card)

        # 3. Licensing & Compliance Card
        license_card = QFrame()
        license_card.setObjectName("SurfaceCard")
        l_layout = QVBoxLayout(license_card)
        l_layout.setContentsMargins(20, 18, 20, 18)
        l_layout.setSpacing(8)

        lic_title = QLabel("Open Source Licensing & Warranty Notice")
        lic_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff;")
        l_layout.addWidget(lic_title)

        lic_desc = QLabel(
            "Licensed under the Apache License, Version 2.0 (the 'License'). You may not use this file except in "
            "compliance with the License. You may obtain a copy of the License at:\n"
            "http://www.apache.org/licenses/LICENSE-2.0\n\n"
            "Unless required by applicable law or agreed to in writing, software distributed under the License is "
            "distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied."
        )
        lic_desc.setWordWrap(True)
        lic_desc.setStyleSheet(f"color: {Theme.TEXT_MUTED}; font-size: 12px;")
        l_layout.addWidget(lic_desc)

        layout.addWidget(license_card)
        layout.addStretch()

        scroll.setWidget(scroll_widget)
        outer_layout.addWidget(scroll)
