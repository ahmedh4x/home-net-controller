from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor, QFont, QIcon
import PySide6.QtSvg  # noqa: F401 - registers SVG format plugin with QImageReader

from netcutter.common.logging import LogEntry
from netcutter.common.paths import get_asset_path
from netcutter.domain.events import AuditEvent
from netcutter.domain.models import (
    BlockedDomainEvent,
    Device,
    DeviceCategory,
    DomainBlockingRule,
    DomainEnforcementStatus,
    DomainMatchType,
    DomainScope,
    GatewayConfig,
    InternetAccessState,
    PolicyStatus,
)
from netcutter.persistence.repository import NotificationItem
from netcutter.ui_qt.theme import Theme

_CATEGORY_ICONS: Dict[str, QIcon] = {}


def get_category_icon(category: Any) -> Optional[QIcon]:
    key = category.value if hasattr(category, "value") else str(category)
    if key in _CATEGORY_ICONS:
        return _CATEGORY_ICONS[key]

    mapping = {
        DeviceCategory.SMARTPHONE: "smartphone.svg",
        DeviceCategory.LAPTOP_PC: "laptop.svg",
        DeviceCategory.MAC: "mac.svg",
        DeviceCategory.TABLET: "tablet.svg",
        DeviceCategory.SMART_TV: "smart_tv.svg",
        DeviceCategory.PRINTER: "printer.svg",
        DeviceCategory.GAMING_CONSOLE: "gaming.svg",
        DeviceCategory.ROUTER_AP: "router.svg",
        DeviceCategory.IOT_DEVICE: "iot.svg",
        DeviceCategory.UNKNOWN: "unknown.svg",
    }
    fname = mapping.get(category, "unknown.svg")
    icon_path = get_asset_path(f"icons/{fname}")
    if icon_path.exists():
        icon = QIcon(str(icon_path))
        _CATEGORY_ICONS[key] = icon
        return icon
    return None


class DeviceTableModel(QAbstractTableModel):
    COLUMNS = [
        "Device Name",
        "Category",
        "MAC Address",
        "IP Address",
        "Vendor",
        "Access",
        "Bandwidth",
        "Sync State",
    ]

    def __init__(self, devices: Optional[List[Device]] = None, parent=None):
        super().__init__(parent)
        self._devices: List[Device] = devices or []

    def set_devices(self, devices: List[Device]):
        self.beginResetModel()
        self._devices = list(devices)
        self.endResetModel()

    def get_device(self, row: int) -> Optional[Device]:
        if 0 <= row < len(self._devices):
            return self._devices[row]
        return None

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._devices)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> Any:
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self._devices)):
            return None

        dev = self._devices[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:
                name = dev.display_name
                if dev.is_randomized_mac and name in ("Unknown Device", "Generic Device", ""):
                    name = "Private MAC Device"
                return name
            elif col == 1:
                return dev.category.value if hasattr(dev.category, "value") else str(dev.category)
            elif col == 2:
                return dev.primary_mac
            elif col == 3:
                return dev.primary_ipv4
            elif col == 4:
                return dev.vendor or "Generic"
            elif col == 5:
                if dev.desired_policy.is_blocked:
                    return "● BLOCKED"
                return "● ALLOWED"
            elif col == 6:
                dl = dev.desired_policy.download_limit_kbps
                ul = dev.desired_policy.upload_limit_kbps
                if dl <= 0 and ul <= 0:
                    return "Unlimited"
                parts = []
                if dl > 0:
                    parts.append(f"↓ {dl} Kbps")
                if ul > 0:
                    parts.append(f"↑ {ul} Kbps")
                return " / ".join(parts)
            elif col == 7:
                st = dev.policy_status
                if st == PolicyStatus.SYNCHRONIZED:
                    return "● SYNCHRONIZED"
                elif st == PolicyStatus.DRIFTED:
                    return "▲ DRIFTED"
                return "✕ " + st.value

        elif role == Qt.ToolTipRole:
            if col == 0:
                return f"Device: {dev.display_name}\nHostname: {dev.hostname or 'None'}\nVendor: {dev.vendor or 'Unknown'}"
            elif col == 1:
                return f"Category: {dev.category.value}\nBasis: {dev.classification_basis or 'Heuristic'}\nConfidence: {dev.confidence_level.value}"
            elif col == 2:
                hist = ", ".join(dev.historical_macs) if dev.historical_macs else dev.primary_mac
                return f"Primary MAC: {dev.primary_mac}\nRandomized / Private: {dev.is_randomized_mac}\nHistory: {hist}"
            elif col == 3:
                return f"IPv4: {dev.primary_ipv4}\nIPv6: {dev.primary_ipv6}"
            elif col == 4:
                return f"Hardware Vendor: {dev.vendor or 'Unknown / Generic'}"
            elif col == 6:
                return f"Download Limit: {dev.desired_policy.download_limit_kbps} Kbps\nUpload Limit: {dev.desired_policy.upload_limit_kbps} Kbps"

        elif role == Qt.ForegroundRole:
            if col == 5:
                if dev.desired_policy.is_blocked:
                    return QColor(Theme.DANGER_TEXT)
                return QColor(Theme.SUCCESS_TEXT)
            elif col == 7:
                if dev.policy_status == PolicyStatus.SYNCHRONIZED:
                    return QColor(Theme.SUCCESS_TEXT)
                elif dev.policy_status == PolicyStatus.DRIFTED:
                    return QColor(Theme.WARNING_TEXT)
                elif dev.policy_status in (PolicyStatus.FAILED, PolicyStatus.BACKEND_UNAVAILABLE):
                    return QColor(Theme.DANGER_TEXT)
                return QColor(Theme.TEXT_SECONDARY)

        elif role == Qt.DecorationRole:
            if col == 1:
                return get_category_icon(dev.category)

        elif role == Qt.FontRole:
            if col in (0, 5, 7):
                f = QFont()
                f.setBold(True)
                return f

        elif role == Qt.TextAlignmentRole:
            if col in (5, 6, 7):
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        return None


class PoliciesTableModel(QAbstractTableModel):
    COLUMNS = [
        "Device",
        "MAC Address",
        "Desired Access",
        "Observed Access",
        "Enforcement State",
        "Download Limit",
        "Upload Limit",
        "Last Sync",
    ]

    def __init__(self, devices: Optional[List[Device]] = None, parent=None):
        super().__init__(parent)
        self._devices: List[Device] = devices or []

    def set_devices(self, devices: List[Device]):
        self.beginResetModel()
        self._devices = list(devices)
        self.endResetModel()

    def get_device(self, row: int) -> Optional[Device]:
        if 0 <= row < len(self._devices):
            return self._devices[row]
        return None

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._devices)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> Any:
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self._devices)):
            return None

        dev = self._devices[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:
                return dev.display_name
            elif col == 1:
                return dev.primary_mac
            elif col == 2:
                return dev.desired_policy.internet_access.value
            elif col == 3:
                return dev.observed_policy.internet_access.value
            elif col == 4:
                return dev.policy_status.value
            elif col == 5:
                dl = dev.desired_policy.download_limit_kbps
                return f"{dl} Kbps" if dl > 0 else "Unlimited"
            elif col == 6:
                ul = dev.desired_policy.upload_limit_kbps
                return f"{ul} Kbps" if ul > 0 else "Unlimited"
            elif col == 7:
                return dev.last_sync.strftime("%H:%M:%S") if dev.last_sync else "Never"

        elif role == Qt.ForegroundRole:
            if col in (2, 3):
                acc = dev.desired_policy.internet_access if col == 2 else dev.observed_policy.internet_access
                return QColor(Theme.DANGER_TEXT if acc == InternetAccessState.BLOCKED else Theme.SUCCESS_TEXT)
            elif col == 4:
                if dev.policy_status == PolicyStatus.SYNCHRONIZED:
                    return QColor(Theme.SUCCESS_TEXT)
                elif dev.policy_status == PolicyStatus.DRIFTED:
                    return QColor(Theme.WARNING_TEXT)
                return QColor(Theme.DANGER_TEXT)

        elif role == Qt.TextAlignmentRole:
            if col in (2, 3, 4, 5, 6, 7):
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        return None


class BandwidthTableModel(QAbstractTableModel):
    COLUMNS = [
        "Device Name",
        "IP Address",
        "MAC Address",
        "↓ Rate",
        "↑ Rate",
        "Total ↓",
        "Total ↑",
        "Combined",
        "Mode",
        "Access",
    ]

    def __init__(self, devices: Optional[List[Device]] = None, parent=None):
        super().__init__(parent)
        self._devices: List[Device] = devices or []

    def set_devices(self, devices: List[Device]):
        self.beginResetModel()
        self._devices = list(devices)
        self.endResetModel()

    def get_device(self, row: int) -> Optional[Device]:
        if 0 <= row < len(self._devices):
            return self._devices[row]
        return None

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._devices)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> Any:
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self._devices)):
            return None

        dev = self._devices[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:
                name = dev.display_name
                if dev.is_randomized_mac and name in ("Unknown Device", "Generic Device", ""):
                    name = "Private MAC Device"
                return name
            elif col == 1:
                return dev.primary_ipv4
            elif col == 2:
                return dev.primary_mac
            elif col == 3:
                return dev.download_rate_display
            elif col == 4:
                return dev.upload_rate_display
            elif col == 5:
                return dev.total_download_display
            elif col == 6:
                return dev.total_upload_display
            elif col == 7:
                from netcutter.domain.models import format_bytes
                return format_bytes(dev.total_download_bytes + dev.total_upload_bytes)
            elif col == 8:
                mode = dev.traffic_monitoring_mode
                if mode == "ACTIVE_METERING":
                    return "ACTIVE METERING"
                elif mode == "GATEWAY_NATIVE":
                    return "GATEWAY NATIVE"
                return "PASSIVE (Broadcast Only)"
            elif col == 9:
                return "BLOCKED" if dev.desired_policy.is_blocked else "ALLOWED"

        elif role == Qt.ToolTipRole:
            if col == 8:
                if dev.traffic_monitoring_mode == "ACTIVE_METERING":
                    return "Full unicast throughput is being metered via Layer-2 transparent forwarding bridge."
                elif dev.traffic_monitoring_mode == "GATEWAY_NATIVE":
                    return "Accruing directly from router kernel nftables/tc counters."
                else:
                    return (
                        "Passive observation on switched network. Only broadcasts and host-directed packets are visible. "
                        "Click 'Enable Active Metering' to measure full-duplex internet throughput."
                    )
            elif col in (3, 4):
                return f"Instantaneous speed: Download: {dev.download_rate_display}, Upload: {dev.upload_rate_display}"

        elif role == Qt.ForegroundRole:
            if col in (3, 4):
                rate = dev.download_rate_bps if col == 3 else dev.upload_rate_bps
                if rate > 0:
                    return QColor(Theme.CYAN if col == 3 else Theme.ACCENT_HOVER)
                return QColor(Theme.TEXT_MUTED)
            elif col == 8:
                if dev.traffic_monitoring_mode == "ACTIVE_METERING":
                    return QColor(Theme.CYAN)
                elif dev.traffic_monitoring_mode == "GATEWAY_NATIVE":
                    return QColor(Theme.PURPLE)
                return QColor(Theme.TEXT_SECONDARY)
            elif col == 9:
                if dev.desired_policy.is_blocked:
                    return QColor(Theme.DANGER_TEXT)
                return QColor(Theme.SUCCESS_TEXT)

        elif role == Qt.TextAlignmentRole:
            if col in (1, 2, 3, 4, 5, 6, 7, 8, 9):
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        return None


class LogsTableModel(QAbstractTableModel):
    COLUMNS = ["Timestamp", "Severity", "Component", "Message"]

    def __init__(self, entries: Optional[List[LogEntry]] = None, parent=None):
        super().__init__(parent)
        self._entries: List[LogEntry] = entries or []

    def set_entries(self, entries: List[LogEntry]):
        self.beginResetModel()
        self._entries = list(entries)
        self.endResetModel()

    def get_entry(self, row: int) -> Optional[LogEntry]:
        if 0 <= row < len(self._entries):
            return self._entries[row]
        return None

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._entries)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> Any:
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self._entries)):
            return None

        entry = self._entries[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:
                return entry.timestamp[11:19]  # Just HH:MM:SS for clean layout
            elif col == 1:
                return entry.level
            elif col == 2:
                return entry.logger_name.split(".")[-1]
            elif col == 3:
                return entry.message

        elif role == Qt.ForegroundRole:
            if col == 1:
                lvl = entry.level
                if lvl == "ERROR" or lvl == "CRITICAL":
                    return QColor(Theme.DANGER_TEXT)
                elif lvl == "WARNING":
                    return QColor(Theme.WARNING_TEXT)
                elif lvl == "INFO":
                    return QColor(Theme.INFO)
                return QColor(Theme.TEXT_MUTED)

        elif role == Qt.TextAlignmentRole:
            if col in (0, 1):
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        return None


class NotificationsTableModel(QAbstractTableModel):
    COLUMNS = ["Time", "Category", "Title", "Message", "Status"]

    def __init__(self, items: Optional[List[NotificationItem]] = None, parent=None):
        super().__init__(parent)
        self._items: List[NotificationItem] = items or []

    def set_items(self, items: List[NotificationItem]):
        self.beginResetModel()
        self._items = list(items)
        self.endResetModel()

    def get_item(self, row: int) -> Optional[NotificationItem]:
        if 0 <= row < len(self._items):
            return self._items[row]
        return None

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._items)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> Any:
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self._items)):
            return None

        notif = self._items[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:
                return notif.timestamp.strftime("%H:%M:%S")
            elif col == 1:
                return notif.category
            elif col == 2:
                return notif.title
            elif col == 3:
                return notif.message
            elif col == 4:
                return "Read" if notif.is_read else "Unread"

        elif role == Qt.ForegroundRole:
            if col == 1:
                cat = notif.category
                if cat in ("ERROR", "CRITICAL"):
                    return QColor(Theme.DANGER_TEXT)
                elif cat == "WARNING":
                    return QColor(Theme.WARNING_TEXT)
                elif cat == "SUCCESS":
                    return QColor(Theme.SUCCESS_TEXT)
                return QColor(Theme.INFO)
            elif col == 4:
                return QColor(Theme.TEXT_MUTED if notif.is_read else Theme.ACCENT_HOVER)

        elif role == Qt.TextAlignmentRole:
            if col in (0, 1, 4):
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        return None


class DomainRulesTableModel(QAbstractTableModel):
    COLUMNS = [
        "Domain",
        "Match Type",
        "Scope",
        "Status",
        "Hits",
        "Enabled",
        "Created At",
        "Last Verified",
    ]

    def __init__(self, rules: Optional[List[DomainBlockingRule]] = None, parent=None):
        super().__init__(parent)
        self._rules: List[DomainBlockingRule] = rules or []

    def set_rules(self, rules: List[DomainBlockingRule]):
        self.beginResetModel()
        self._rules = list(rules)
        self.endResetModel()

    def get_rule(self, row: int) -> Optional[DomainBlockingRule]:
        if 0 <= row < len(self._rules):
            return self._rules[row]
        return None

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._rules)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> Any:
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self._rules)):
            return None

        rule = self._rules[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:
                return rule.domain
            elif col == 1:
                return rule.display_match_type
            elif col == 2:
                return rule.display_scope
            elif col == 3:
                return rule.enforcement_status.value
            elif col == 4:
                return str(rule.hits_count)
            elif col == 5:
                return "Active" if rule.is_enabled else "Disabled"
            elif col == 6:
                return rule.created_at.strftime("%Y-%m-%d %H:%M")
            elif col == 7:
                return (
                    rule.last_verified_at.strftime("%H:%M:%S")
                    if rule.last_verified_at
                    else "Never"
                )

        elif role == Qt.ForegroundRole:
            if col == 0:
                return QColor("#ffffff" if rule.is_enabled else Theme.TEXT_MUTED)
            elif col == 3:
                if rule.enforcement_status == DomainEnforcementStatus.ACTIVE:
                    return QColor(Theme.SUCCESS_TEXT)
                elif rule.enforcement_status == DomainEnforcementStatus.PENDING:
                    return QColor(Theme.WARNING_TEXT)
                elif rule.enforcement_status == DomainEnforcementStatus.FAILED:
                    return QColor(Theme.DANGER_TEXT)
                return QColor(Theme.TEXT_MUTED)
            elif col == 4:
                return QColor(Theme.CYAN_ACCENT if rule.hits_count > 0 else Theme.TEXT_MUTED)
            elif col == 5:
                return QColor(Theme.SUCCESS_TEXT if rule.is_enabled else Theme.TEXT_MUTED)

        elif role == Qt.TextAlignmentRole:
            if col in (1, 3, 4, 5, 6, 7):
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        return None


class BlockedEventsTableModel(QAbstractTableModel):
    COLUMNS = [
        "Time",
        "Target Device",
        "Client IP",
        "Requested Domain",
        "Action Taken",
        "Mechanism",
    ]

    def __init__(self, events: Optional[List[BlockedDomainEvent]] = None, parent=None):
        super().__init__(parent)
        self._events: List[BlockedDomainEvent] = events or []

    def set_events(self, events: List[BlockedDomainEvent]):
        self.beginResetModel()
        self._events = list(events)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._events)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> Any:
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self._events)):
            return None

        event = self._events[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:
                return event.timestamp.strftime("%H:%M:%S")
            elif col == 1:
                return event.device_name or (event.client_mac or "Unknown")
            elif col == 2:
                return event.client_ip or "-"
            elif col == 3:
                return event.domain
            elif col == 4:
                return event.action
            elif col == 5:
                return event.mechanism

        elif role == Qt.ForegroundRole:
            if col == 3:
                return QColor(Theme.DANGER_TEXT)
            elif col == 4:
                return QColor(Theme.WARNING_TEXT)
            elif col == 5:
                return QColor(Theme.INFO)

        elif role == Qt.TextAlignmentRole:
            if col in (0, 2, 4):
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        return None


class AuditTableModel(QAbstractTableModel):
    COLUMNS = ["Timestamp", "Action", "Target / Scope", "Status", "Details"]

    def __init__(self, events: Optional[List[AuditEvent]] = None, parent=None):
        super().__init__(parent)
        self._events: List[AuditEvent] = events or []

    def set_events(self, events: List[AuditEvent]):
        self.beginResetModel()
        self._events = list(events)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._events)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> Any:
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self._events)):
            return None

        event = self._events[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:
                return event.timestamp.strftime("%H:%M:%S") if hasattr(event.timestamp, "strftime") else str(event.timestamp)[:8]
            elif col == 1:
                return event.action.value.replace("_", " ").title() if hasattr(event.action, "value") else str(event.action)
            elif col == 2:
                return event.device_name or "Gateway Subnet"
            elif col == 3:
                st = str(event.status).upper()
                if st == "SUCCESS":
                    return "● " + st
                elif st in ("FAILED", "ERROR"):
                    return "✕ " + st
                return "▲ " + st
            elif col == 4:
                return event.details or event.error or "Normal operation"

        elif role == Qt.ForegroundRole:
            if col == 3:
                st = str(event.status).upper()
                if st == "SUCCESS":
                    return QColor(Theme.SUCCESS_TEXT)
                elif st in ("FAILED", "ERROR"):
                    return QColor(Theme.DANGER_TEXT)
                return QColor(Theme.WARNING_TEXT)

        elif role == Qt.FontRole:
            if col in (1, 3):
                f = QFont()
                f.setBold(True)
                return f

        elif role == Qt.TextAlignmentRole:
            if col in (0, 3):
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        return None


