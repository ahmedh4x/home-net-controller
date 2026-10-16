"""
Modal Dialogs for Policy Preview, Bandwidth QoS Configuration, and Gateway Management.
"""
from __future__ import annotations

from typing import Callable, Optional
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from netcutter.domain.models import Device, GatewayConfig
from netcutter.services.policy_preview import (
    ImpactSeverity,
    PolicyPreviewEngine,
    PolicyPreviewReport,
    ProposedAction,
)
from netcutter.ui_qt.theme import Theme


class PolicyPreviewDialog(QDialog):
    """
    Mandatory pre-enforcement modal displaying dry-run validation,
    conflict detection, capability matrix, and verification strategies.
    """

    def __init__(self, report: PolicyPreviewReport, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.report = report
        self.confirmed = False

        self.setWindowTitle("NetCutter — Policy Enforcement Preview")
        self.setFixedWidth(560)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header Title
        title_lbl = QLabel("Pre-Execution Policy Preview & Risk Audit")
        title_lbl.setStyleSheet("font-size: 16px; font-weight: 700; color: #ffffff;")
        layout.addWidget(title_lbl)

        # Target Device Details Card
        card = QFrame()
        card.setObjectName("SurfaceCard")
        c_layout = QFormLayout(card)
        c_layout.setContentsMargins(14, 12, 14, 12)
        c_layout.setSpacing(8)

        c_layout.addRow(QLabel("Target Device:"), QLabel(f"<b>{report.device_name}</b> ({report.primary_mac})"))
        ips_str = ", ".join(report.target_ips) if report.target_ips else "None Discovered"
        c_layout.addRow(QLabel("Network IPs:"), QLabel(ips_str))
        c_layout.addRow(QLabel("Responsible Gateway:"), QLabel(f"<b>{report.responsible_backend}</b>"))
        c_layout.addRow(QLabel("Proposed Action:"), QLabel(f"<span style='color:{Theme.ACCENT_HOVER};font-weight:600;'>{report.proposed_action.value}</span>"))

        layout.addWidget(card)

        # Impact and Summary Notice
        impact_frame = QFrame()
        impact_bg = "#2a1515" if report.impact_level == ImpactSeverity.DISRUPTIVE else Theme.BG_SURFACE
        impact_border = Theme.DANGER if report.impact_level == ImpactSeverity.DISRUPTIVE else Theme.BORDER_DEFAULT
        impact_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {impact_bg};
                border: 1px solid {impact_border};
                border-radius: 6px;
                padding: 10px;
            }}
        """)
        imp_layout = QVBoxLayout(impact_frame)
        imp_layout.setContentsMargins(10, 8, 10, 8)
        imp_layout.setSpacing(4)

        lbl_imp_title = QLabel(f"Impact Level: {report.impact_level.value}")
        lbl_imp_title.setStyleSheet(f"font-weight: 700; color: {Theme.DANGER_TEXT if report.impact_level == ImpactSeverity.DISRUPTIVE else Theme.INFO};")
        imp_layout.addWidget(lbl_imp_title)

        lbl_imp_text = QLabel(report.impact_summary)
        lbl_imp_text.setWordWrap(True)
        lbl_imp_text.setStyleSheet(f"font-size: 12px; color: {Theme.TEXT_SECONDARY};")
        imp_layout.addWidget(lbl_imp_text)

        layout.addWidget(impact_frame)

        # Conflicts / Warnings List
        if report.conflicts:
            warn_lbl = QLabel(f"Safety Warnings & Conflicts ({len(report.conflicts)}):")
            warn_lbl.setStyleSheet(f"font-weight: 600; color: {Theme.WARNING_TEXT};")
            layout.addWidget(warn_lbl)

            for conf in report.conflicts:
                cf = QFrame()
                cf.setStyleSheet(f"background-color: {Theme.BG_CARD}; border-left: 3px solid {Theme.WARNING_TEXT}; padding: 6px;")
                cf_l = QVBoxLayout(cf)
                cf_l.setContentsMargins(6, 4, 6, 4)
                cf_l.setSpacing(2)

                t = QLabel(f"• {conf.title}")
                t.setStyleSheet(f"font-weight: 600; color: {Theme.TEXT_PRIMARY}; font-size: 12px;")
                cf_l.addWidget(t)

                d = QLabel(conf.description)
                d.setWordWrap(True)
                d.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 11px;")
                cf_l.addWidget(d)
                layout.addWidget(cf)

        # Verification Strategy Box
        strat_lbl = QLabel("Gateway Verification Strategy:")
        strat_lbl.setStyleSheet(f"font-size: 11px; font-weight: 600; color: {Theme.TEXT_MUTED}; text-transform: uppercase;")
        layout.addWidget(strat_lbl)

        strat_val = QLabel(report.verification_strategy)
        strat_val.setWordWrap(True)
        strat_val.setStyleSheet(f"font-size: 12px; color: {Theme.TEXT_SECONDARY}; background-color: {Theme.BG_CARD}; padding: 8px; border-radius: 4px;")
        layout.addWidget(strat_val)

        # Blocking Reason (if execution is disallowed)
        if not report.can_execute:
            block_box = QLabel(f"Execution Prohibited: {report.block_reason}")
            block_box.setWordWrap(True)
            block_box.setStyleSheet(f"background-color: #3b1111; color: {Theme.DANGER_TEXT}; padding: 10px; border-radius: 6px; font-weight: 600;")
            layout.addWidget(block_box)

        # Action Buttons Layout
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)
        btn_layout.addStretch()

        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(btn_cancel)

        self.btn_confirm = QPushButton("Confirm & Enforce")
        if report.impact_level == ImpactSeverity.DISRUPTIVE:
            self.btn_confirm.setObjectName("DangerBtn")
        else:
            self.btn_confirm.setObjectName("PrimaryBtn")

        self.btn_confirm.setEnabled(report.can_execute)
        self.btn_confirm.clicked.connect(self._on_confirm)
        btn_layout.addWidget(self.btn_confirm)

        layout.addLayout(btn_layout)

    def _on_confirm(self):
        self.confirmed = True
        self.accept()


class BandwidthDialog(QDialog):
    """QoS Bandwidth rate configuration dialog with presets and custom limits."""

    def __init__(self, device: Device, on_save: Callable[[int, int], None], parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.device = device
        self.on_save = on_save

        self.setWindowTitle(f"QoS Bandwidth Limits — {device.display_name}")
        self.setFixedWidth(460)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        title = QLabel("Configure Bandwidth Shaping (QoS)")
        title.setStyleSheet("font-size: 15px; font-weight: 700; color: #ffffff;")
        layout.addWidget(title)

        sub = QLabel(f"Target: {device.display_name} ({device.primary_mac})")
        sub.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 12px;")
        layout.addWidget(sub)

        # Form Inputs
        form = QFormLayout()
        form.setSpacing(10)

        self.spin_dl = QSpinBox()
        self.spin_dl.setRange(0, 1000000)
        self.spin_dl.setSingleStep(512)
        self.spin_dl.setSuffix(" Kbps")
        self.spin_dl.setValue(device.desired_policy.download_limit_kbps)
        form.addRow("Download Limit:", self.spin_dl)

        self.spin_ul = QSpinBox()
        self.spin_ul.setRange(0, 1000000)
        self.spin_ul.setSingleStep(512)
        self.spin_ul.setSuffix(" Kbps")
        self.spin_ul.setValue(device.desired_policy.upload_limit_kbps)
        form.addRow("Upload Limit:", self.spin_ul)

        layout.addLayout(form)

        # Quick Presets Buttons
        presets_lbl = QLabel("Quick Presets:")
        presets_lbl.setStyleSheet(f"font-size: 11px; font-weight: 600; color: {Theme.TEXT_MUTED};")
        layout.addWidget(presets_lbl)

        preset_layout = QHBoxLayout()
        presets = [
            ("1 Mbps", 1024, 512),
            ("5 Mbps", 5120, 2048),
            ("10 Mbps", 10240, 5120),
            ("25 Mbps", 25600, 10240),
            ("Remove Limits", 0, 0),
        ]
        for label, dl, ul in presets:
            btn = QPushButton(label)
            btn.setStyleSheet(f"font-size: 11px; padding: 4px 8px; background-color: {Theme.BG_CARD};")
            btn.clicked.connect(lambda _, d=dl, u=ul: self._apply_preset(d, u))
            preset_layout.addWidget(btn)
        layout.addLayout(preset_layout)

        # Action Buttons
        btn_box = QHBoxLayout()
        btn_box.addStretch()

        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        btn_box.addWidget(btn_cancel)

        btn_apply = QPushButton("Preview & Apply")
        btn_apply.setObjectName("PrimaryBtn")
        btn_apply.clicked.connect(self._on_apply)
        btn_box.addWidget(btn_apply)

        layout.addLayout(btn_box)

    def _apply_preset(self, dl: int, ul: int):
        self.spin_dl.setValue(dl)
        self.spin_ul.setValue(ul)

    def _on_apply(self):
        dl = self.spin_dl.value()
        ul = self.spin_ul.value()
        self.on_save(dl, ul)
        self.accept()


class GatewayConfigDialog(QDialog):
    """Add or edit router configuration record."""

    def __init__(
        self,
        config: Optional[GatewayConfig] = None,
        on_save: Optional[Callable[[GatewayConfig, str], None]] = None,
        on_test: Optional[Callable[[GatewayConfig, str], None]] = None,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.config = config or GatewayConfig()
        self.on_save = on_save
        self.on_test = on_test
        self.is_new = config is None

        self.setWindowTitle("Configure Gateway Router" if self.is_new else f"Edit Gateway — {self.config.name}")
        self.setFixedWidth(460)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        title = QLabel("Gateway Router Connection" if self.is_new else "Edit Gateway Configuration")
        title.setStyleSheet("font-size: 15px; font-weight: 700; color: #ffffff;")
        layout.addWidget(title)

        form = QFormLayout()
        form.setSpacing(10)

        self.txt_name = QLineEdit(self.config.name)
        form.addRow("Gateway Name:", self.txt_name)

        self.combo_type = QComboBox()
        from netcutter.domain.models import BackendType
        for b in [BackendType.OPENWRT, BackendType.LINUX, BackendType.MIKROTIK, BackendType.WINDOWS_LAN, BackendType.MOCK]:
            self.combo_type.addItem(b.value, b)
        index = self.combo_type.findData(self.config.backend_type)
        if index >= 0:
            self.combo_type.setCurrentIndex(index)
        form.addRow("Backend Mode:", self.combo_type)

        self.txt_host = QLineEdit(self.config.host)
        form.addRow("IP Host / URL:", self.txt_host)

        self.spin_port = QSpinBox()
        self.spin_port.setRange(1, 65535)
        self.spin_port.setValue(self.config.port)
        form.addRow("Port (SSH/REST):", self.spin_port)

        self.txt_user = QLineEdit(self.config.username)
        form.addRow("Username:", self.txt_user)

        self.txt_password = QLineEdit()
        self.txt_password.setEchoMode(QLineEdit.Password)
        self.txt_password.setPlaceholderText("(Leave empty to keep existing password)")
        form.addRow("Password / Token:", self.txt_password)

        # SSH & TLS Security Settings
        sec_header = QLabel("Security & Verification")
        sec_header.setStyleSheet(f"font-size: 12px; font-weight: 600; color: {Theme.TEXT_MUTED}; margin-top: 6px;")
        form.addRow(sec_header)

        self.txt_ssh_fp = QLineEdit(self.config.ssh_host_key_fingerprint or "")
        self.txt_ssh_fp.setPlaceholderText("e.g. SHA256:abc... (Auto-pins on first connect)")
        form.addRow("SSH Fingerprint:", self.txt_ssh_fp)

        self.chk_tls_verify = QCheckBox("Enforce Strict TLS CA Validation")
        self.chk_tls_verify.setChecked(self.config.tls_verify)
        form.addRow("TLS Verification:", self.chk_tls_verify)

        self.txt_tls_ca = QLineEdit(self.config.tls_ca_path or "")
        self.txt_tls_ca.setPlaceholderText("(Optional) Path to custom CA bundle (.pem / .crt)")
        form.addRow("Custom CA Bundle:", self.txt_tls_ca)

        self.txt_tls_fp = QLineEdit(self.config.tls_fingerprint or "")
        self.txt_tls_fp.setPlaceholderText("(Optional) Pin SHA256 cert fingerprint for self-signed certs")
        form.addRow("TLS Fingerprint Pin:", self.txt_tls_fp)

        layout.addLayout(form)

        # Buttons
        btn_box = QHBoxLayout()

        if self.on_test:
            btn_test = QPushButton("Test Connection")
            btn_test.clicked.connect(self._on_test_clicked)
            btn_box.addWidget(btn_test)

        btn_box.addStretch()

        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        btn_box.addWidget(btn_cancel)

        btn_save = QPushButton("Save Gateway")
        btn_save.setObjectName("PrimaryBtn")
        btn_save.clicked.connect(self._on_save_clicked)
        btn_box.addWidget(btn_save)

        layout.addLayout(btn_box)

    def _build_config_from_form(self) -> GatewayConfig:
        cfg = self.config
        cfg.name = self.txt_name.text().strip() or "Gateway"
        cfg.backend_type = self.combo_type.currentData()
        cfg.host = self.txt_host.text().strip() or "192.168.1.1"
        cfg.port = self.spin_port.value()
        cfg.username = self.txt_user.text().strip() or "root"
        cfg.ssh_host_key_fingerprint = self.txt_ssh_fp.text().strip() or None
        cfg.tls_verify = self.chk_tls_verify.isChecked()
        cfg.tls_ca_path = self.txt_tls_ca.text().strip() or None
        cfg.tls_fingerprint = self.txt_tls_fp.text().strip() or None
        return cfg

    def _on_test_clicked(self):
        cfg = self._build_config_from_form()
        pwd = self.txt_password.text()
        if self.on_test:
            self.on_test(cfg, pwd)

    def _on_save_clicked(self):
        cfg = self._build_config_from_form()
        pwd = self.txt_password.text()
        if self.on_save:
            self.on_save(cfg, pwd)
        self.accept()
