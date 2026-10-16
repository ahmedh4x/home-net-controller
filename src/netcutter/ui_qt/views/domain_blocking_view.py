"""
Website & Domain Blocking View for NetCutter.
Provides persistent domain rule configuration, scope assignment (per-device or global),
live enforcement status badges, and real-time audit logging for intercepted domain requests.
"""
from __future__ import annotations

from typing import List, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QPixmap
from netcutter.common.paths import get_asset_path
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from netcutter.domain.domain_validator import normalize_domain, validate_domain
from netcutter.domain.models import (
    BlockedDomainEvent,
    Device,
    DomainBlockingRule,
    DomainEnforcementStatus,
    DomainMatchType,
    DomainScope,
)
from netcutter.ui_qt.components import PageHeader
from netcutter.ui_qt.models import BlockedEventsTableModel, DomainRulesTableModel
from netcutter.ui_qt.theme import Theme


class AddDomainRuleDialog(QDialog):
    """Modal dialog for creating or configuring domain blocking rules."""

    def __init__(self, devices: List[Device], parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Add Website & Domain Blocking Rule")
        self.resize(520, 460)
        self._devices = devices

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # Title
        lbl_title = QLabel("Block Website or Domain")
        lbl_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #ffffff;")
        layout.addWidget(lbl_title)

        # Domain input
        layout.addWidget(QLabel("Domain Name or Hostname:"))
        self.txt_domain = QLineEdit()
        self.txt_domain.setPlaceholderText("e.g. example.com, tiktok.com, ads.network.com")
        self.txt_domain.textChanged.connect(self._on_domain_changed)
        layout.addWidget(self.txt_domain)

        # Real-time preview & normalization label
        self.lbl_preview = QLabel("Enter a domain name to inspect validation.")
        self.lbl_preview.setStyleSheet(f"font-size: 11px; color: {Theme.TEXT_MUTED};")
        self.lbl_preview.setWordWrap(True)
        layout.addWidget(self.lbl_preview)

        # Match Type
        grp_match = QGroupBox("Match Type")
        grp_match.setStyleSheet("QGroupBox { font-weight: bold; }")
        vbox_match = QVBoxLayout(grp_match)
        self.rb_subdomain = QRadioButton("Domain and all subdomains (*.example.com and example.com)")
        self.rb_subdomain.setChecked(True)
        self.rb_exact = QRadioButton("Exact domain only (example.com only, subdomains allowed)")
        vbox_match.addWidget(self.rb_subdomain)
        vbox_match.addWidget(self.rb_exact)
        layout.addWidget(grp_match)

        # Target Scope
        grp_scope = QGroupBox("Enforcement Scope")
        grp_scope.setStyleSheet("QGroupBox { font-weight: bold; }")
        vbox_scope = QVBoxLayout(grp_scope)
        self.rb_global = QRadioButton("All Managed Devices (Global network rule)")
        self.rb_global.setChecked(True)
        self.rb_device = QRadioButton("Specific Target Device")
        self.rb_global.toggled.connect(self._on_scope_toggled)
        vbox_scope.addWidget(self.rb_global)
        vbox_scope.addWidget(self.rb_device)

        # Device selector dropdown
        self.combo_device = QComboBox()
        self.combo_device.setEnabled(False)
        for dev in self._devices:
            ip_str = dev.primary_ipv4 if dev.ipv4_addresses else "No IP"
            self.combo_device.addItem(
                f"{dev.display_name} ({ip_str} — {dev.primary_mac})",
                userData=dev.device_guid,
            )
        vbox_scope.addWidget(self.combo_device)
        layout.addWidget(grp_scope)

        # Optional notes
        layout.addWidget(QLabel("Notes (Optional):"))
        self.txt_notes = QLineEdit()
        self.txt_notes.setPlaceholderText("e.g. Parental control, bandwidth saving")
        layout.addWidget(self.txt_notes)

        # Buttons
        btn_box = QHBoxLayout()
        btn_box.addStretch()
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self.reject)
        self.btn_submit = QPushButton("Add Blocking Rule")
        self.btn_submit.setStyleSheet(f"""
            QPushButton {{
                background-color: {Theme.DANGER};
                color: #ffffff;
                font-weight: bold;
                padding: 7px 18px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #d32f2f;
            }}
        """)
        self.btn_submit.clicked.connect(self._on_submit)
        btn_box.addWidget(self.btn_cancel)
        btn_box.addWidget(self.btn_submit)
        layout.addLayout(btn_box)

    def _on_scope_toggled(self, checked: bool):
        self.combo_device.setEnabled(not self.rb_global.isChecked())

    def _on_domain_changed(self, text: str):
        if not text.strip():
            self.lbl_preview.setText("Enter a domain name to inspect validation.")
            self.lbl_preview.setStyleSheet(f"font-size: 11px; color: {Theme.TEXT_MUTED};")
            return

        valid, err, norm = validate_domain(text)
        if valid:
            self.lbl_preview.setText(f"✓ Valid: Will block '{norm}'")
            self.lbl_preview.setStyleSheet(f"font-size: 11px; color: {Theme.SUCCESS_TEXT}; font-weight: bold;")
        else:
            self.lbl_preview.setText(f"⚠ {err}")
            self.lbl_preview.setStyleSheet(f"font-size: 11px; color: {Theme.DANGER_TEXT}; font-weight: bold;")

    def _on_submit(self):
        raw = self.txt_domain.text().strip()
        valid, err, norm = validate_domain(raw)
        if not valid:
            QMessageBox.warning(self, "Invalid Domain", err)
            return

        if self.rb_device.isChecked() and self.combo_device.currentIndex() < 0:
            QMessageBox.warning(self, "No Device Selected", "Please select a target device.")
            return

        self.accept()

    def get_data(self):
        match_type = (
            DomainMatchType.SUBDOMAIN if self.rb_subdomain.isChecked() else DomainMatchType.EXACT
        )
        target_scope = (
            DomainScope.GLOBAL if self.rb_global.isChecked() else DomainScope.DEVICE
        )
        device_guid = (
            self.combo_device.currentData() if target_scope == DomainScope.DEVICE else None
        )
        return {
            "domain": self.txt_domain.text().strip(),
            "match_type": match_type,
            "target_scope": target_scope,
            "target_device_guid": device_guid,
            "notes": self.txt_notes.text().strip() or None,
        }


class DomainBlockingView(QWidget):
    add_rule_requested = Signal(dict)
    toggle_rule_requested = Signal(str)    # rule_id
    delete_rule_requested = Signal(str)    # rule_id
    verify_rules_requested = Signal()
    clear_events_requested = Signal()
    refresh_requested = Signal()

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._rules: List[DomainBlockingRule] = []
        self._events: List[BlockedDomainEvent] = []
        self._devices: List[Device] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # 1. Page Header
        header = PageHeader(
            title="Website & Domain Blocking",
            subtitle="Enforce persistent DNS sinkholes and Layer-2 SNI domain filters across local devices or router-wide.",
        )
        layout.addWidget(header)

        # 2. Metric Summary Cards
        metrics_box = QHBoxLayout()
        metrics_box.setSpacing(12)

        self.card_active = self._create_metric_card("Active Rules", "0", Theme.CYAN)
        self.card_devices = self._create_metric_card("Devices Targeted", "0", "#ffffff")
        self.card_hits = self._create_metric_card("Blocked Queries", "0", Theme.ACCENT_HOVER)
        self.card_engine = self._create_metric_card("Enforcement Engine", "Ready", Theme.SUCCESS_TEXT)

        metrics_box.addWidget(self.card_active)
        metrics_box.addWidget(self.card_devices)
        metrics_box.addWidget(self.card_hits)
        metrics_box.addWidget(self.card_engine)
        layout.addLayout(metrics_box)

        # 3. Limitations & Modern Encryption Notice Card
        notice_card = QFrame()
        notice_card.setObjectName("NoticeCard")
        notice_card.setStyleSheet(f"""
            QFrame#NoticeCard {{
                background-color: #0f172a;
                border: 1px solid #1e293b;
                border-left: 4px solid {Theme.CYAN_ACCENT};
                border-radius: 8px;
            }}
        """)
        n_layout = QHBoxLayout(notice_card)
        n_layout.setContentsMargins(16, 12, 16, 12)
        n_layout.setSpacing(14)

        shield_path = get_asset_path("shield_lock.svg")
        lbl_shield = QLabel()
        if shield_path.exists():
            pix = QPixmap(str(shield_path)).scaled(26, 26, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            lbl_shield.setPixmap(pix)
        else:
            lbl_shield.setText("🛡️")
            lbl_shield.setStyleSheet("font-size: 20px;")
        n_layout.addWidget(lbl_shield)

        lbl_notice_text = QLabel(
            "<b>DNS & SNI Filter Architecture:</b> Domain rules sinkhole DNS queries to <code>0.0.0.0</code> and reject unencrypted TLS ClientHello handshakes. "
            "Encrypted DNS (DoH/DoT) or VPNs on client devices bypass local DNS filtering. Specific URL paths inside HTTPS connections cannot be inspected without TLS decryption certificates."
        )
        lbl_notice_text.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 11px;")
        lbl_notice_text.setWordWrap(True)
        n_layout.addWidget(lbl_notice_text)
        layout.addWidget(notice_card)

        # 4. Search and Action Controls Bar
        ctrl_bar = QHBoxLayout()
        ctrl_bar.setSpacing(10)

        self.btn_add_rule = QPushButton("+ Add Domain Rule")
        self.btn_add_rule.setObjectName("PrimaryBtn")
        self.btn_add_rule.setStyleSheet(f"background-color: {Theme.CYAN}; color: #000000; font-weight: 700; padding: 7px 16px; border-radius: 6px;")
        self.btn_add_rule.clicked.connect(self._open_add_dialog)
        ctrl_bar.addWidget(self.btn_add_rule)

        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Search domain rules...")
        self.txt_search.textChanged.connect(self._apply_filters)
        ctrl_bar.addWidget(self.txt_search)

        self.combo_scope_filter = QComboBox()
        self.combo_scope_filter.addItems(["All Scopes", "Global Only", "Device-Specific Only"])
        self.combo_scope_filter.currentIndexChanged.connect(self._apply_filters)
        ctrl_bar.addWidget(self.combo_scope_filter)

        self.combo_status_filter = QComboBox()
        self.combo_status_filter.addItems(["All Statuses", "Active", "Pending", "Failed"])
        self.combo_status_filter.currentIndexChanged.connect(self._apply_filters)
        ctrl_bar.addWidget(self.combo_status_filter)

        self.btn_verify = QPushButton("Verify Rules")
        self.btn_verify.clicked.connect(self.verify_rules_requested.emit)
        ctrl_bar.addWidget(self.btn_verify)

        self.btn_toggle = QPushButton("Enable / Disable")
        self.btn_toggle.clicked.connect(self._toggle_selected_rule)
        ctrl_bar.addWidget(self.btn_toggle)

        self.btn_delete = QPushButton("Delete")
        self.btn_delete.setObjectName("DangerBtn")
        self.btn_delete.clicked.connect(self._delete_selected_rule)
        ctrl_bar.addWidget(self.btn_delete)

        layout.addLayout(ctrl_bar)

        # 5. Dual Table Splitter (Rules Table + Blocked Events Stream)
        splitter = QSplitter(Qt.Vertical)

        # --- Top: Domain Rules Table ---
        rules_container = QWidget()
        v_rules = QVBoxLayout(rules_container)
        v_rules.setContentsMargins(0, 0, 0, 0)
        v_rules.setSpacing(6)

        lbl_rules_title = QLabel("Configured Domain Rules")
        lbl_rules_title.setStyleSheet("font-weight: bold; font-size: 13px; color: #ffffff;")
        v_rules.addWidget(lbl_rules_title)

        self.rules_model = DomainRulesTableModel(self._rules, self)
        self.rules_table = QTableView()
        self.rules_table.setModel(self.rules_model)
        self.rules_table.verticalHeader().setDefaultSectionSize(34)
        self.rules_table.setSelectionBehavior(QTableView.SelectRows)
        self.rules_table.setSelectionMode(QTableView.SingleSelection)
        self.rules_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.rules_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeToContents)
        v_rules.addWidget(self.rules_table)

        self.empty_rules_card = QFrame()
        self.empty_rules_card.setObjectName("SurfaceCard")
        self.empty_rules_card.setStyleSheet(f"""
            QFrame#SurfaceCard {{
                background-color: {Theme.BG_CARD};
                border: 1px dashed {Theme.BORDER_DEFAULT};
                border-radius: 8px;
            }}
        """)
        er_layout = QVBoxLayout(self.empty_rules_card)
        er_layout.setContentsMargins(20, 24, 20, 24)
        er_layout.setAlignment(Qt.AlignCenter)
        er_layout.setSpacing(6)

        lbl_r_title = QLabel("No Domain Blocking Rules Configured")
        lbl_r_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff;")
        lbl_r_title.setAlignment(Qt.AlignCenter)
        er_layout.addWidget(lbl_r_title)

        lbl_r_sub = QLabel("Click '+ Add Domain Rule' above to sinkhole DNS queries and reject TLS handshakes.")
        lbl_r_sub.setStyleSheet(f"font-size: 12px; color: {Theme.TEXT_SECONDARY};")
        lbl_r_sub.setAlignment(Qt.AlignCenter)
        er_layout.addWidget(lbl_r_sub)

        v_rules.addWidget(self.empty_rules_card)
        splitter.addWidget(rules_container)

        # --- Bottom: Blocked Events Stream ---
        events_container = QWidget()
        v_events = QVBoxLayout(events_container)
        v_events.setContentsMargins(0, 0, 0, 0)
        v_events.setSpacing(6)

        events_header = QHBoxLayout()
        lbl_events_title = QLabel("Live Blocked Query Audit Stream")
        lbl_events_title.setStyleSheet("font-weight: bold; font-size: 13px; color: #ffffff;")
        events_header.addWidget(lbl_events_title)
        events_header.addStretch()

        self.btn_clear_events = QPushButton("Clear Stream")
        self.btn_clear_events.setStyleSheet("padding: 3px 10px; font-size: 11px;")
        self.btn_clear_events.clicked.connect(self.clear_events_requested.emit)
        events_header.addWidget(self.btn_clear_events)
        v_events.addLayout(events_header)

        self.events_model = BlockedEventsTableModel(self._events, self)
        self.events_table = QTableView()
        self.events_table.setModel(self.events_model)
        self.events_table.verticalHeader().setDefaultSectionSize(32)
        self.events_table.setSelectionBehavior(QTableView.SelectRows)
        self.events_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.events_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.events_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.events_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.events_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.events_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        v_events.addWidget(self.events_table)

        self.empty_events_card = QFrame()
        self.empty_events_card.setObjectName("SurfaceCard")
        self.empty_events_card.setStyleSheet(f"""
            QFrame#SurfaceCard {{
                background-color: {Theme.BG_CARD};
                border: 1px dashed {Theme.BORDER_DEFAULT};
                border-radius: 8px;
            }}
        """)
        ee_layout = QVBoxLayout(self.empty_events_card)
        ee_layout.setContentsMargins(20, 20, 20, 20)
        ee_layout.setAlignment(Qt.AlignCenter)
        ee_layout.setSpacing(6)

        lbl_e_title = QLabel("No Blocked Queries in Active Session")
        lbl_e_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #ffffff;")
        lbl_e_title.setAlignment(Qt.AlignCenter)
        ee_layout.addWidget(lbl_e_title)

        lbl_e_sub = QLabel("When client devices request restricted domains, live intercepted queries will stream here.")
        lbl_e_sub.setStyleSheet(f"font-size: 11px; color: {Theme.TEXT_SECONDARY};")
        lbl_e_sub.setAlignment(Qt.AlignCenter)
        ee_layout.addWidget(lbl_e_sub)

        v_events.addWidget(self.empty_events_card)
        splitter.addWidget(events_container)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter)

    def _create_metric_card(self, title: str, initial_val: str, color_hex: str) -> QFrame:
        card = QFrame()
        card.setObjectName("MetricCard")
        card.setStyleSheet(f"""
            QFrame#MetricCard {{
                background-color: {Theme.BG_CARD};
                border: 1px solid {Theme.BORDER_DEFAULT};
                border-top: 3px solid {color_hex};
                border-radius: 8px;
            }}
            QFrame#MetricCard:hover {{
                border-color: {color_hex};
                background-color: {Theme.BG_SURFACE};
            }}
        """)
        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(16, 12, 16, 12)
        vbox.setSpacing(4)

        lbl_t = QLabel(title.upper())
        lbl_t.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {Theme.TEXT_SECONDARY}; letter-spacing: 0.6px;")
        vbox.addWidget(lbl_t)

        lbl_v = QLabel(initial_val)
        lbl_v.setObjectName("MetricValue")
        lbl_v.setStyleSheet(f"font-size: 24px; font-weight: 800; color: {color_hex};")
        vbox.addWidget(lbl_v)

        return card

    def set_devices(self, devices: List[Device]):
        self._devices = list(devices)

    def update_rules(self, rules: List[DomainBlockingRule]):
        self._rules = list(rules)
        self._apply_filters()
        self._update_metric_cards()

    def update_events(self, events: List[BlockedDomainEvent]):
        self._events = list(events)
        self.events_model.set_events(self._events)
        has_events = bool(self._events)
        self.events_table.setVisible(has_events)
        self.empty_events_card.setVisible(not has_events)

    def set_engine_status(self, engine_name: str, is_active: bool = True):
        lbl = self.card_engine.findChild(QLabel, "MetricValue")
        if lbl:
            lbl.setText(engine_name)
            lbl.setStyleSheet(f"font-size: 15px; font-weight: bold; color: {Theme.SUCCESS_TEXT if is_active else Theme.WARNING_TEXT};")

    def _update_metric_cards(self):
        active_count = sum(1 for r in self._rules if r.is_enabled and r.enforcement_status == DomainEnforcementStatus.ACTIVE)
        devices_targeted = len(set(r.target_device_guid for r in self._rules if r.target_scope == DomainScope.DEVICE and r.target_device_guid))
        total_hits = sum(r.hits_count for r in self._rules)

        lbl_act = self.card_active.findChild(QLabel, "MetricValue")
        if lbl_act:
            lbl_act.setText(f"{active_count} Active")

        lbl_dev = self.card_devices.findChild(QLabel, "MetricValue")
        if lbl_dev:
            lbl_dev.setText(f"{devices_targeted} Devices" if devices_targeted else "Global Only")

        lbl_hit = self.card_hits.findChild(QLabel, "MetricValue")
        if lbl_hit:
            lbl_hit.setText(str(total_hits))

    def _apply_filters(self):
        filtered = self._rules
        query = self.txt_search.text().strip().lower()
        if query:
            filtered = [
                r for r in filtered
                if query in r.domain.lower()
                or (r.target_device_name and query in r.target_device_name.lower())
                or (r.notes and query in r.notes.lower())
            ]

        scope_idx = self.combo_scope_filter.currentIndex()
        if scope_idx == 1:
            filtered = [r for r in filtered if r.target_scope == DomainScope.GLOBAL]
        elif scope_idx == 2:
            filtered = [r for r in filtered if r.target_scope == DomainScope.DEVICE]

        status_idx = self.combo_status_filter.currentIndex()
        if status_idx == 1:
            filtered = [r for r in filtered if r.enforcement_status == DomainEnforcementStatus.ACTIVE]
        elif status_idx == 2:
            filtered = [r for r in filtered if r.enforcement_status == DomainEnforcementStatus.PENDING]
        elif status_idx == 3:
            filtered = [r for r in filtered if r.enforcement_status == DomainEnforcementStatus.FAILED]

        self.rules_model.set_rules(filtered)
        has_rules = bool(filtered)
        self.rules_table.setVisible(has_rules)
        self.empty_rules_card.setVisible(not has_rules)

    def _open_add_dialog(self):
        dlg = AddDomainRuleDialog(self._devices, self)
        if dlg.exec() == QDialog.Accepted:
            data = dlg.get_data()
            self.add_rule_requested.emit(data)

    def _get_selected_rule(self) -> Optional[DomainBlockingRule]:
        indexes = self.rules_table.selectionModel().selectedRows()
        if indexes:
            row = indexes[0].row()
            return self.rules_model.get_rule(row)
        return None

    def _toggle_selected_rule(self):
        rule = self._get_selected_rule()
        if not rule:
            QMessageBox.information(self, "No Selection", "Please select a rule from the table.")
            return
        self.toggle_rule_requested.emit(rule.rule_id)

    def _delete_selected_rule(self):
        rule = self._get_selected_rule()
        if not rule:
            QMessageBox.information(self, "No Selection", "Please select a rule to delete.")
            return

        confirm = QMessageBox.question(
            self,
            "Confirm Delete Rule",
            f"Are you sure you want to remove the domain blocking rule for '{rule.domain}'?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm == QMessageBox.Yes:
            self.delete_rule_requested.emit(rule.rule_id)
