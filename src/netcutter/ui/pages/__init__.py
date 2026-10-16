"""
NetCutter UI Pages Package.
"""
from netcutter.ui.pages.dashboard import DashboardPage
from netcutter.ui.pages.devices import DevicesPage
from netcutter.ui.pages.device_details import DeviceDetailsPage
from netcutter.ui.pages.policies import PoliciesPage
from netcutter.ui.pages.gateways import GatewaysPage
from netcutter.ui.pages.bandwidth import BandwidthPage
from netcutter.ui.pages.events import EventsPage
from netcutter.ui.pages.diagnostics import DiagnosticsPage
from netcutter.ui.pages.settings import SettingsPage
from netcutter.ui.pages.about import AboutPage

__all__ = [
    "DashboardPage",
    "DevicesPage",
    "DeviceDetailsPage",
    "PoliciesPage",
    "GatewaysPage",
    "BandwidthPage",
    "EventsPage",
    "DiagnosticsPage",
    "SettingsPage",
    "AboutPage",
]
