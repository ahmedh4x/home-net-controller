"""
Design System, Color Tokens, and Modern Dark Qt Style Sheet (QSS) for NetCutter.
Theme: Midnight Obsidian with Electric Cyan, Neon Violet, and Emerald accents.
"""
from __future__ import annotations

from PySide6.QtGui import QColor, QFont


class Theme:
    """Design tokens and visual language constants."""

    # Surfaces & Canvas
    BG_CANVAS = "#0a0e17"       # Deep Obsidian Midnight Canvas
    BG_SIDEBAR = "#0d1322"      # Elevated Dark Slate Sidebar
    BG_CARD = "#131b2e"         # Midnight Container Card
    BG_SURFACE = "#18223a"      # Raised Surface Panel
    BG_HOVER = "#1e2b48"        # Interactive Element Hover
    BG_INPUT = "#070a12"        # Sunken High-Contrast Input Well

    # Borders & Dividers
    BORDER_DEFAULT = "#1e2a42"  # Subtle Technical Border
    BORDER_MUTED = "#141c2e"    # Low-Contrast Divider
    BORDER_FOCUS = "#00f0ff"    # Electric Cyan Focus Ring
    BORDER_GLOW_VIOLET = "#a855f7"

    # Text Colors
    TEXT_PRIMARY = "#f0f6fc"    # High-Contrast White/Silver
    TEXT_SECONDARY = "#94a3b8"  # Slate Gray Supporting Text
    TEXT_MUTED = "#64748b"      # Muted Labels and Placeholders
    TEXT_INVERT = "#0a0e17"     # Dark Text on Bright Chips

    # Semantic Status Accents
    CYAN_ACCENT = "#00f0ff"     # Primary Electric Brand Cyan
    CYAN = CYAN_ACCENT          # Alias
    ACCENT = CYAN_ACCENT        # Alias
    CYAN_HOVER = "#38f9d7"      # High-Luminance Cyan Hover
    VIOLET_ACCENT = "#a855f7"   # Neon Violet Accent for AI & Special Actions
    VIOLET = VIOLET_ACCENT      # Alias
    ACCENT_PRIMARY = "#2563eb"  # Deep Royal Blue CTA
    ACCENT_HOVER = "#3b82f6"    # Royal Blue Hover
    SUCCESS = "#10b981"         # Vibrant Emerald Green
    SUCCESS_TEXT = "#34d399"    # High-Legibility Success Text
    WARNING = "#f59e0b"         # Amber Warning
    WARNING_TEXT = "#fbbf24"    # High-Legibility Amber
    DANGER = "#ef4444"          # Crimson Alert/Block
    DANGER_TEXT = "#f87171"     # High-Legibility Red Alert
    INFO = "#0ea5e9"            # Informational Cyan-Blue
    PURPLE = "#a855f7"          # Supporting Purple

    # Radii & Metrics
    RADIUS_CARD = "8px"
    RADIUS_BUTTON = "6px"
    RADIUS_INPUT = "6px"
    RADIUS_TAG = "12px"

    @classmethod
    def get_stylesheet(cls) -> str:
        return f"""
        /* Global Window and Base Widget */
        QMainWindow, QWidget#CentralWidget {{
            background-color: {cls.BG_CANVAS};
            color: {cls.TEXT_PRIMARY};
            font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, "Inter", Arial, sans-serif;
            font-size: 13px;
        }}

        QWidget {{
            color: {cls.TEXT_PRIMARY};
            selection-background-color: {cls.ACCENT_PRIMARY};
            selection-color: #ffffff;
        }}

        /* Sidebar Styling */
        QFrame#SidebarFrame {{
            background-color: {cls.BG_SIDEBAR};
            border-right: 1px solid {cls.BORDER_DEFAULT};
        }}

        /* Top Header Bar */
        QFrame#HeaderBar {{
            background-color: {cls.BG_SIDEBAR};
            border-bottom: 1px solid {cls.BORDER_DEFAULT};
            padding: 8px 16px;
        }}

        /* Cards & Content Surfaces */
        QFrame#MetricCard, QFrame#SurfaceCard {{
            background-color: {cls.BG_CARD};
            border: 1px solid {cls.BORDER_DEFAULT};
            border-radius: {cls.RADIUS_CARD};
            padding: 14px;
        }}
        QFrame#MetricCard:hover {{
            border-color: {cls.CYAN_ACCENT};
            background-color: {cls.BG_SURFACE};
        }}

        /* Safe Mode Banner */
        QFrame#SafeModeBanner {{
            background-color: #2b1b06;
            border: 1px solid {cls.WARNING_TEXT};
            border-radius: {cls.RADIUS_CARD};
            padding: 10px 16px;
        }}

        /* Typography */
        QLabel#BrandTitle {{
            font-size: 13px;
            font-weight: 700;
            color: #ffffff;
            letter-spacing: 0.4px;
        }}

        QLabel#BrandSubtitle {{
            font-size: 11px;
            font-weight: 600;
            color: {cls.CYAN_ACCENT};
            letter-spacing: 0.4px;
        }}

        QLabel#PageHeaderTitle {{
            font-size: 20px;
            font-weight: 700;
            color: #ffffff;
        }}

        QLabel#PageHeaderSubtitle {{
            font-size: 13px;
            color: {cls.TEXT_SECONDARY};
        }}

        QLabel#CardHeader {{
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            color: {cls.TEXT_SECONDARY};
            letter-spacing: 0.6px;
        }}

        QLabel#CardBigValue {{
            font-size: 26px;
            font-weight: 700;
            color: #ffffff;
        }}

        /* Sidebar Navigation Buttons */
        QPushButton[class="NavButton"] {{
            background-color: transparent;
            color: #94a3b8;
            border: none;
            border-left: 3px solid transparent;
            border-radius: 6px;
            padding: 10px 14px;
            text-align: left;
            font-size: 13px;
            font-weight: 500;
        }}
        QPushButton[class="NavButton"]:hover {{
            background-color: #162035;
            color: #f0f6fc;
            border-left: 3px solid #38bdf8;
        }}
        QPushButton[class="NavButton"][active="true"] {{
            background-color: #101e38;
            color: #00f0ff;
            border-left: 3px solid #00f0ff;
            font-weight: 600;
        }}

        /* Standard Buttons */
        QPushButton {{
            background-color: #131b2e;
            color: #f0f6fc;
            border: 1px solid #1e2a42;
            border-radius: 6px;
            padding: 7px 16px;
            font-size: 13px;
            font-weight: 500;
        }}
        QPushButton:hover {{
            background-color: #1e2b48;
            border-color: #38bdf8;
        }}
        QPushButton:pressed {{
            background-color: #162238;
        }}
        QPushButton:disabled {{
            background-color: #101726;
            color: #64748b;
            border-color: #182236;
        }}

        /* Primary Call-to-Action Button */
        QPushButton#PrimaryBtn, QPushButton[variant="primary"], QPushButton[class="PrimaryBtn"] {{
            background-color: #0284c7;
            color: #ffffff;
            border: 1px solid #38bdf8;
            border-radius: 6px;
            font-weight: 600;
            padding: 7px 16px;
        }}
        QPushButton#PrimaryBtn:hover, QPushButton[variant="primary"]:hover, QPushButton[class="PrimaryBtn"]:hover {{
            background-color: #0369a1;
            border-color: #00f0ff;
        }}

        /* Secondary Button */
        QPushButton.SecondaryButton, QPushButton[variant="secondary"] {{
            background-color: #131b2e;
            color: #f0f6fc;
            border: 1px solid #1e2a42;
        }}
        QPushButton.SecondaryButton:hover, QPushButton[variant="secondary"]:hover {{
            background-color: #1e2b48;
            border-color: #94a3b8;
        }}

        /* Danger / Block Button */
        QPushButton#DangerBtn, QPushButton[variant="danger"], QPushButton[class="DangerBtn"] {{
            background-color: #dc2626;
            color: #ffffff;
            border: 1px solid #ef4444;
            border-radius: 6px;
            font-weight: 600;
            padding: 7px 16px;
        }}
        QPushButton#DangerBtn:hover, QPushButton[variant="danger"]:hover, QPushButton[class="DangerBtn"]:hover {{
            background-color: #b91c1c;
            border-color: #f87171;
        }}

        /* Success / Unblock Button */
        QPushButton#SuccessBtn, QPushButton[variant="success"], QPushButton[class="SuccessBtn"] {{
            background-color: #059669;
            color: #ffffff;
            border: 1px solid #10b981;
            border-radius: 6px;
            font-weight: 600;
            padding: 7px 16px;
        }}
        QPushButton#SuccessBtn:hover, QPushButton[variant="success"]:hover, QPushButton[class="SuccessBtn"]:hover {{
            background-color: #047857;
            border-color: #34d399;
        }}

        /* Inputs and Text Fields */
        QLineEdit, QComboBox, QSpinBox {{
            background-color: #070a12;
            color: #f0f6fc;
            border: 1px solid #1e2a42;
            border-radius: 6px;
            padding: 7px 12px;
            font-size: 13px;
        }}
        QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{
            border: 1px solid #00f0ff;
            background-color: #090e1c;
        }}

        QComboBox::drop-down {{
            subcontrol-origin: padding;
            subcontrol-position: top right;
            width: 24px;
            border-left: 1px solid {cls.BORDER_DEFAULT};
        }}
        QComboBox QAbstractItemView {{
            background-color: {cls.BG_CARD};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER_DEFAULT};
            selection-background-color: {cls.ACCENT_PRIMARY};
        }}

        /* Tables & Grids */
        QTableView {{
            background-color: {cls.BG_CARD};
            alternate-background-color: #0e1626;
            border: 1px solid {cls.BORDER_DEFAULT};
            border-radius: {cls.RADIUS_CARD};
            gridline-color: #172236;
            selection-background-color: #1a365d;
            selection-color: #ffffff;
            outline: none;
        }}
        QTableView::item {{
            padding: 8px 10px;
            border-bottom: 1px solid #141d2e;
        }}
        QTableView::item:selected {{
            background-color: #1a365d;
            color: #ffffff;
        }}
        QTableView::item:hover {{
            background-color: #142036;
        }}

        QHeaderView::section {{
            background-color: #0b101c;
            color: #94a3b8;
            font-weight: 700;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 9px 12px;
            border: none;
            border-bottom: 2px solid {cls.BORDER_DEFAULT};
            border-right: 1px solid #141c2c;
        }}

        /* Scrollbars */
        QScrollBar:vertical {{
            background: transparent;
            width: 7px;
            margin: 2px;
        }}
        QScrollBar::handle:vertical {{
            background: #1e2a42;
            min-height: 24px;
            border-radius: 3px;
        }}
        QScrollBar::handle:vertical:hover {{
            background: #38bdf8;
        }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}
        QScrollBar:horizontal {{
            background: transparent;
            height: 7px;
            margin: 2px;
        }}
        QScrollBar::handle:horizontal {{
            background: #1e2a42;
            min-width: 24px;
            border-radius: 3px;
        }}
        QScrollBar::handle:horizontal:hover {{
            background: #38bdf8;
        }}
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
            width: 0px;
        }}

        /* Splitter */
        QSplitter::handle {{
            background-color: #141d2e;
            height: 2px;
        }}
        QSplitter::handle:hover {{
            background-color: #00f0ff;
        }}

        /* Dialogs */
        QDialog {{
            background-color: {cls.BG_CANVAS};
            color: {cls.TEXT_PRIMARY};
        }}

        /* Badges / Chips */
        QLabel.Badge {{
            font-size: 11px;
            font-weight: 600;
            padding: 3px 8px;
            border-radius: {cls.RADIUS_TAG};
        }}

        /* Tooltips */
        QToolTip {{
            background-color: {cls.BG_CARD};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER_DEFAULT};
            border-radius: 4px;
            padding: 6px 10px;
            font-size: 12px;
        }}
        """
