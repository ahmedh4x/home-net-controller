"""
Reusable UI Components and Widgets for NetCutter Qt Interface.
"""
from __future__ import annotations

from typing import Optional
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
    QWidget,
)
from netcutter.services.notification_service import NotificationCategory, ToastNotification
from netcutter.ui_qt.theme import Theme


class StatusBadge(QLabel):
    """Visual status pill badge with distinctive background, border, and text colors."""

    VARIANTS = {
        "success": ("#064e3b", "#34d399", "#059669"),
        "warning": ("#451a03", "#fbbf24", "#d97706"),
        "danger": ("#450a0a", "#f87171", "#dc2626"),
        "info": ("#0c4a6e", "#38bdf8", "#0284c7"),
        "purple": ("#3b0764", "#c084fc", "#9333ea"),
        "neutral": ("#1e293b", "#94a3b8", "#334155"),
    }

    def __init__(self, text: str, variant: str = "neutral", parent: Optional[QWidget] = None):
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignCenter)
        self.set_variant(variant)

    def set_variant(self, variant: str):
        bg, fg, border = self.VARIANTS.get(variant.lower(), self.VARIANTS["neutral"])
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {bg};
                color: {fg};
                border: 1px solid {border};
                border-radius: 9px;
                padding: 3px 10px;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 0.3px;
            }}
        """)


class MetricCard(QFrame):
    """Operational KPI summary card with top accent border, large display, and subtitle."""

    def __init__(
        self,
        title: str,
        value: str = "0",
        subtitle: str = "",
        accent_color: str = Theme.TEXT_PRIMARY,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.setObjectName("MetricCard")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.accent_color = accent_color

        border_top = f"border-top: 3px solid {accent_color};" if accent_color != Theme.TEXT_PRIMARY else f"border-top: 3px solid {Theme.CYAN_ACCENT};"
        self.setStyleSheet(f"""
            QFrame#MetricCard {{
                background-color: {Theme.BG_CARD};
                border: 1px solid {Theme.BORDER_DEFAULT};
                {border_top}
                border-radius: 8px;
            }}
            QFrame#MetricCard:hover {{
                border-color: {Theme.CYAN_ACCENT};
                background-color: {Theme.BG_SURFACE};
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)

        self.lbl_title = QLabel(title.upper())
        self.lbl_title.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {Theme.TEXT_SECONDARY}; letter-spacing: 0.6px;")
        layout.addWidget(self.lbl_title)

        self.lbl_value = QLabel(value)
        val_color = accent_color if accent_color != Theme.TEXT_PRIMARY else "#ffffff"
        self.lbl_value.setStyleSheet(f"color: {val_color}; font-size: 26px; font-weight: 800;")
        layout.addWidget(self.lbl_value)

        self.lbl_sub = QLabel(subtitle)
        self.lbl_sub.setStyleSheet(f"font-size: 11px; color: {Theme.TEXT_MUTED};")
        layout.addWidget(self.lbl_sub)

    def set_value(self, value: str, subtitle: Optional[str] = None):
        self.lbl_value.setText(value)
        if subtitle is not None:
            self.lbl_sub.setText(subtitle)


class PageHeader(QWidget):
    """Standardized page header displaying title, subtitle, and contextual action buttons."""

    def __init__(self, title: str, subtitle: str = "", parent: Optional[QWidget] = None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 16)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(4)

        self.lbl_title = QLabel(title)
        self.lbl_title.setObjectName("PageHeaderTitle")
        text_layout.addWidget(self.lbl_title)

        if subtitle:
            self.lbl_sub = QLabel(subtitle)
            self.lbl_sub.setObjectName("PageHeaderSubtitle")
            text_layout.addWidget(self.lbl_sub)

        layout.addLayout(text_layout)
        layout.addStretch()

        self.actions_layout = QHBoxLayout()
        self.actions_layout.setSpacing(8)
        layout.addLayout(self.actions_layout)

    def add_action(self, widget: QWidget):
        self.actions_layout.addWidget(widget)


class ToastWidget(QFrame):
    """Individual animated floating notification toast."""

    dismissed = Signal(str)  # toast_id

    def __init__(self, toast: ToastNotification, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.toast = toast
        self.setObjectName("ToastWidget")

        # Color scheme based on severity
        cat_colors = {
            NotificationCategory.SUCCESS: (Theme.SUCCESS, "#2ea043", "✓"),
            NotificationCategory.INFO: (Theme.ACCENT_PRIMARY, "#388bfd", "ℹ"),
            NotificationCategory.WARNING: (Theme.WARNING, "#d29922", "⚠"),
            NotificationCategory.ERROR: (Theme.DANGER, "#f85149", "✕"),
            NotificationCategory.CRITICAL: ("#6e0000", "#ff7b72", "⚡"),
        }
        bg, border, symbol = cat_colors.get(toast.category, (Theme.BG_CARD, Theme.BORDER_DEFAULT, "•"))

        self.setStyleSheet(f"""
            QFrame#ToastWidget {{
                background-color: {Theme.BG_CARD};
                border: 1px solid {border};
                border-left: 5px solid {border};
                border-radius: 6px;
                padding: 10px 14px;
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(12)

        # Icon symbol
        lbl_icon = QLabel(symbol)
        lbl_icon.setStyleSheet(f"color: {border}; font-size: 16px; font-weight: 700;")
        layout.addWidget(lbl_icon)

        # Text block
        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)

        lbl_title = QLabel(toast.title)
        lbl_title.setStyleSheet("font-size: 13px; font-weight: 600; color: #ffffff;")
        text_layout.addWidget(lbl_title)

        lbl_msg = QLabel(toast.message)
        lbl_msg.setWordWrap(True)
        lbl_msg.setStyleSheet(f"font-size: 12px; color: {Theme.TEXT_SECONDARY};")
        text_layout.addWidget(lbl_msg)

        layout.addLayout(text_layout)

        # Optional action button
        if toast.action_label:
            btn_action = QPushButton(toast.action_label)
            btn_action.setStyleSheet(f"""
                QPushButton {{
                    background-color: {Theme.BG_HOVER};
                    color: {border};
                    border: 1px solid {border};
                    padding: 4px 10px;
                    font-size: 11px;
                }}
            """)
            layout.addWidget(btn_action)

        # Dismiss 'X' button
        btn_close = QPushButton("×")
        btn_close.setFixedSize(22, 22)
        btn_close.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: none;
                color: {Theme.TEXT_MUTED};
                font-size: 16px;
                font-weight: 700;
            }}
            QPushButton:hover {{
                color: #ffffff;
            }}
        """)
        btn_close.clicked.connect(self.dismiss)
        layout.addWidget(btn_close)

        # Auto-dismiss timer
        if toast.duration_ms > 0:
            QTimer.singleShot(toast.duration_ms, self.dismiss)

    def dismiss(self):
        self.dismissed.emit(self.toast.toast_id)


class ToastContainer(QWidget):
    """Overlay container managing active toasts in the top-right corner of the window."""

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, False)
        self.setFixedWidth(380)

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(8)
        self.layout.setAlignment(Qt.AlignTop)

        self.active_toasts = {}

    def add_toast(self, toast: ToastNotification):
        # Limit visible toasts to 4
        if len(self.active_toasts) >= 4:
            oldest_id = next(iter(self.active_toasts))
            self.remove_toast(oldest_id)

        widget = ToastWidget(toast, self)
        widget.dismissed.connect(self.remove_toast)
        self.layout.addWidget(widget)
        self.active_toasts[toast.toast_id] = widget
        self.adjustSize()
        self.reposition()

    def remove_toast(self, toast_id: str):
        if toast_id in self.active_toasts:
            widget = self.active_toasts.pop(toast_id)
            self.layout.removeWidget(widget)
            widget.deleteLater()
            self.adjustSize()
            self.reposition()

    def reposition(self):
        if self.parent():
            parent_rect = self.parent().rect()
            x = parent_rect.width() - self.width() - 20
            y = 20
            self.move(x, y)
            self.raise_()
