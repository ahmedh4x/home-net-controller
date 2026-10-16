"""
Main Desktop Application Window for NetCutter.
Provides sidebar navigation, threaded service orchestration, and live UI updates.
"""
from __future__ import annotations

import logging
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Dict, Optional
from netcutter.backends.capabilities import format_capabilities_report
from netcutter.diagnostics.health import DiagnosticsService
from netcutter.domain.models import Device, GatewayConfig
from netcutter.persistence.database import Database
from netcutter.persistence.repository import (
    AuditRepository,
    DeviceRepository,
    GatewayRepository,
)
from netcutter.persistence.secret_store import SecretStore
from netcutter.services.audit_service import AuditService
from netcutter.services.device_service import DeviceService
from netcutter.services.gateway_manager import GatewayManager
from netcutter.services.identity_engine import IdentityEngine
from netcutter.services.policy_service import PolicyService
from netcutter.services.reconciliation import ReconciliationEngine
from netcutter.ui.dialogs import (
    BandwidthDialog,
    BlockDeviceDialog,
    GatewayConfigDialog,
)
from netcutter.ui.pages import (
    AboutPage,
    BandwidthPage,
    DashboardPage,
    DeviceDetailsPage,
    DevicesPage,
    DiagnosticsPage,
    EventsPage,
    GatewaysPage,
    PoliciesPage,
    SettingsPage,
)
from netcutter.ui.theme import Theme

logger = logging.getLogger("netcutter.ui")


class NetCutterApp:
    def __init__(self, root: tk.Tk, db_path: Optional[str] = None):
        self.root = root
        self.root.title("NetCutter — Gateway Network Management & Policy Control")
        self.root.geometry("1280x800")
        self.root.minsize(1050, 680)

        Theme.apply(self.root)

        # Initialize persistence & services
        self.db = Database(db_path)
        self.secret_store = SecretStore()
        self.device_repo = DeviceRepository(self.db)
        self.gw_repo = GatewayRepository(self.db)
        self.audit_repo = AuditRepository(self.db)

        self.identity_engine = IdentityEngine(self.db, self.device_repo)
        self.gw_manager = GatewayManager(self.db, self.gw_repo, self.secret_store)
        self.device_service = DeviceService(self.device_repo, self.identity_engine, self.gw_manager)
        self.policy_service = PolicyService(self.device_repo, self.audit_repo, self.gw_manager)
        self.audit_service = AuditService(self.audit_repo)
        self.diag_service = DiagnosticsService(self.gw_manager)

        self.reconcile_engine = ReconciliationEngine(
            self.device_repo,
            self.audit_repo,
            self.gw_manager,
            self.policy_service,
            reconcile_interval_seconds=30,
        )

        # Ensure at least one default mock gateway exists if empty
        self._ensure_initial_gateway()

        # Connect active gateway
        active_gw = self.gw_repo.get_active()
        if active_gw:
            self.gw_manager.set_active_gateway(active_gw.gateway_id)

        # Build UI layout
        self._build_layout()

        # Intercept window close for clean ARP restoration and shutdown
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Start background reconciliation
        self.reconcile_engine.start()

        # Initial data refresh
        self._async_refresh_discovery()
        self._schedule_periodic_refresh()

    def on_close(self):
        try:
            self.reconcile_engine.stop()
            self.gw_manager.disconnect_active()
        except Exception as ex:
            logger.warning(f"Error during app shutdown: {ex}")
        finally:
            self.root.destroy()

    def _ensure_initial_gateway(self):
        from netcutter.domain.models import BackendType
        gws = self.gw_repo.get_all()
        has_win_lan = any(g.backend_type == BackendType.WINDOWS_LAN for g in gws)
        if not has_win_lan:
            win_lan_gw = GatewayConfig(
                gateway_id="gw-windows-lan",
                name="Windows LAN Off-Path (Local Subnet)",
                host="192.168.1.1",
                port=0,
                backend_type=BackendType.WINDOWS_LAN,
                username="",
                is_active=True,
            )
            for g in gws:
                g.is_active = False
                self.gw_repo.upsert(g)
            self.gw_repo.upsert(win_lan_gw)
            gws = self.gw_repo.get_all()

        if not gws:
            default_gw = GatewayConfig(
                name="Simulator Gateway (Mock)",
                host="127.0.0.1",
                port=22,
                backend_type=BackendType.MOCK,
                username="admin",
                is_active=True,
            )
            self.gw_repo.upsert(default_gw)

    def _build_layout(self):
        # Master container
        self.panes = tk.PanedWindow(self.root, orient="horizontal", bg=Theme.BG_DARK, bd=0, sashwidth=0)
        self.panes.pack(fill="both", expand=True)

        # 1. Left Sidebar
        self.sidebar = ttk.Frame(self.panes, style="Sidebar.TFrame", width=220)
        self.panes.add(self.sidebar, minsize=200)

        # App branding
        brand = ttk.Frame(self.sidebar, style="Sidebar.TFrame", padding=(16, 20))
        brand.pack(fill="x")
        ttk.Label(brand, text="NET CUTTER", font=Theme.FONT_TITLE, foreground=Theme.ACCENT_BLUE, background=Theme.BG_SIDEBAR).pack(anchor="w")
        ttk.Label(brand, text="Gateway Controller v2.0", font=Theme.FONT_SMALL, foreground=Theme.TEXT_MUTED, background=Theme.BG_SIDEBAR).pack(anchor="w")

        # Nav Buttons Container
        self.nav_box = ttk.Frame(self.sidebar, style="Sidebar.TFrame")
        self.nav_box.pack(fill="x", pady=10)

        self.nav_btns = {}
        pages_nav = [
            ("dashboard", "Dashboard"),
            ("devices", "Devices"),
            ("policies", "Policies"),
            ("bandwidth", "Bandwidth (QoS)"),
            ("gateways", "Gateways"),
            ("events", "Audit Events"),
            ("diagnostics", "Diagnostics"),
            ("settings", "Settings"),
            ("about", "About"),
        ]

        for page_id, label in pages_nav:
            btn = ttk.Button(
                self.nav_box,
                text=label,
                style="Sidebar.TButton",
                command=lambda p=page_id: self.show_page(p),
            )
            btn.pack(fill="x", pady=1)
            self.nav_btns[page_id] = btn

        # Sidebar footer
        footer = ttk.Frame(self.sidebar, style="Sidebar.TFrame", padding=14)
        footer.pack(side="bottom", fill="x")
        self.lbl_sidebar_gw = ttk.Label(footer, text="GW: Initializing...", font=Theme.FONT_SMALL, background=Theme.BG_SIDEBAR, foreground=Theme.TEXT_SECONDARY)
        self.lbl_sidebar_gw.pack(anchor="w")

        # 2. Main Content Frame
        self.content_area = ttk.Frame(self.panes, style="TFrame")
        self.panes.add(self.content_area, sticky="nsew")

        # Initialize Page Views
        self.pages = {}
        self.pages["dashboard"] = DashboardPage(
            self.content_area,
            on_refresh=self._async_refresh_discovery,
            on_reconcile=self._async_reconcile,
            on_open_device=self.open_device_details,
        )
        self.pages["devices"] = DevicesPage(
            self.content_area,
            on_open_device=self.open_device_details,
            on_block_device=self.confirm_block_device,
            on_unblock_device=self.unblock_device,
            on_set_bandwidth=self.open_bandwidth_dialog,
            on_refresh=self._async_refresh_discovery,
        )
        self.pages["device_details"] = DeviceDetailsPage(
            self.content_area,
            on_back=lambda: self.show_page("devices"),
            on_block=self.confirm_block_device,
            on_unblock=self.unblock_device,
            on_set_bandwidth=self.open_bandwidth_dialog,
            on_rename=self.rename_device,
        )
        self.pages["policies"] = PoliciesPage(
            self.content_area,
            on_reconcile_all=self._async_reconcile,
            on_open_device=self.open_device_details,
        )
        self.pages["bandwidth"] = BandwidthPage(
            self.content_area,
            on_set_bandwidth=self.open_bandwidth_dialog,
            on_open_device=self.open_device_details,
        )
        self.pages["gateways"] = GatewaysPage(
            self.content_area,
            on_add_gw=self.open_add_gateway_dialog,
            on_edit_gw=self.open_edit_gateway_dialog,
            on_delete_gw=self.delete_gateway,
            on_activate_gw=self.activate_gateway,
            on_test_gw=self.test_gateway,
        )
        self.pages["events"] = EventsPage(
            self.content_area,
            on_refresh=self._refresh_events_page,
        )
        self.pages["diagnostics"] = DiagnosticsPage(
            self.content_area,
            on_run_diagnostics=self._async_run_diagnostics,
        )
        self.pages["settings"] = SettingsPage(
            self.content_area,
            on_save=self.save_settings,
        )
        self.pages["about"] = AboutPage(self.content_area)

        # Show Dashboard initially
        self.show_page("dashboard")

    def show_page(self, page_id: str):
        for pid, page in self.pages.items():
            if pid == page_id:
                page.pack(fill="both", expand=True)
            else:
                page.pack_forget()

        # Update sidebar button styling highlight
        for pid, btn in self.nav_btns.items():
            if pid == page_id:
                btn.configure(style="Primary.TButton")
            else:
                btn.configure(style="Sidebar.TButton")

        # Refresh page content
        self._refresh_current_view()

    def open_device_details(self, device_guid: str):
        dev = self.device_service.get_device_by_guid(device_guid)
        if dev:
            self.pages["device_details"].load_device(dev)
            self.show_page("device_details")

    def confirm_block_device(self, device: Device):
        BlockDeviceDialog(self.root, device, on_confirm=lambda: self._async_block(device.device_guid))

    def unblock_device(self, device_guid: str):
        self._async_unblock(device_guid)

    def open_bandwidth_dialog(self, device: Device):
        backend = self.gw_manager.get_active_backend()
        from netcutter.backends.capabilities import BackendCapabilities
        if backend and (
            BackendCapabilities.UPLOAD_SHAPING not in backend.capabilities
            and BackendCapabilities.DOWNLOAD_SHAPING not in backend.capabilities
        ):
            messagebox.showwarning(
                "Bandwidth Shaping Unsupported",
                "Bandwidth QoS shaping is NOT supported in Windows LAN Off-Path mode.\n\n"
                "Real token-bucket queueing requires in-path Gateway-Native enforcement (OpenWrt/Linux with CAKE or HTB).",
            )
            return

        BandwidthDialog(
            self.root,
            device,
            on_save=lambda dl, ul: self._async_set_bandwidth(device.device_guid, dl, ul),
        )

    def rename_device(self, guid: str, new_name: str):
        self.device_service.update_display_name(guid, new_name)
        self.open_device_details(guid)
        self._refresh_all_views()

    def open_add_gateway_dialog(self):
        GatewayConfigDialog(
            self.root,
            None,
            on_save=self._save_gateway,
            on_test=self._test_gateway_from_dialog,
        )

    def open_edit_gateway_dialog(self, gw: GatewayConfig):
        GatewayConfigDialog(
            self.root,
            gw,
            on_save=self._save_gateway,
            on_test=self._test_gateway_from_dialog,
        )

    def _save_gateway(self, gw: GatewayConfig, password: str):
        if password:
            import uuid
            secret_id = gw.auth_secret_id or str(uuid.uuid4())
            gw.auth_secret_id = secret_id
            self.gw_manager.save_credential(secret_id, password)
        self.gw_repo.upsert(gw)
        self._refresh_all_views()

    def _test_gateway_from_dialog(self, gw: GatewayConfig, password: str):
        threading.Thread(
            target=lambda: self._run_test_gw_bg(gw, password), daemon=True
        ).start()

    def _run_test_gw_bg(self, gw: GatewayConfig, password: str):
        ok, msg = self.gw_manager.test_connection(gw, password)
        self.root.after(0, lambda: messagebox.showinfo(
            "Gateway Test Result", f"{'Connection Successful!' if ok else 'Connection Failed!'}\n\n{msg}"
        ))

    def delete_gateway(self, gw_id: str):
        with self.db.get_connection() as conn:
            conn.execute("DELETE FROM gateways WHERE gateway_id = ?", (gw_id,))
            conn.commit()
        self._refresh_all_views()

    def activate_gateway(self, gw_id: str):
        threading.Thread(
            target=lambda: self._run_activate_gw_bg(gw_id), daemon=True
        ).start()

    def _run_activate_gw_bg(self, gw_id: str):
        ok, msg = self.gw_manager.set_active_gateway(gw_id)
        self.root.after(0, lambda: self._after_gw_activate(ok, msg))

    def _after_gw_activate(self, ok: bool, msg: str):
        if ok:
            messagebox.showinfo("Gateway Activated", msg)
            self._async_refresh_discovery()
        else:
            messagebox.showerror("Gateway Activation Failed", msg)
        self._refresh_all_views()

    def test_gateway(self, gw: GatewayConfig):
        threading.Thread(
            target=lambda: self._run_test_gw_bg(gw, None), daemon=True
        ).start()

    def save_settings(self, settings: Dict[str, str]):
        with self.db.get_connection() as conn:
            for k, v in settings.items():
                conn.execute(
                    "INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (k, v),
                )
            conn.commit()
        if "reconcile_interval" in settings and settings["reconcile_interval"].isdigit():
            self.reconcile_engine.interval = int(settings["reconcile_interval"])

    # Asynchronous Network Workers
    def _async_block(self, guid: str):
        threading.Thread(target=lambda: self._do_block_bg(guid), daemon=True).start()

    def _do_block_bg(self, guid: str):
        res = self.policy_service.block_device(guid)
        self.root.after(0, lambda: self._after_policy_change(res))

    def _async_unblock(self, guid: str):
        threading.Thread(target=lambda: self._do_unblock_bg(guid), daemon=True).start()

    def _do_unblock_bg(self, guid: str):
        res = self.policy_service.unblock_device(guid)
        self.root.after(0, lambda: self._after_policy_change(res))

    def _async_set_bandwidth(self, guid: str, dl: int, ul: int):
        threading.Thread(target=lambda: self._do_bandwidth_bg(guid, dl, ul), daemon=True).start()

    def _do_bandwidth_bg(self, guid: str, dl: int, ul: int):
        if dl == 0 and ul == 0:
            res = self.policy_service.remove_bandwidth_limits(guid)
        else:
            res = self.policy_service.set_bandwidth_limits(guid, dl, ul)
        self.root.after(0, lambda: self._after_policy_change(res))

    def _after_policy_change(self, res):
        if not res.success:
            messagebox.showerror("Policy Enforcement Failed", f"Gateway Error:\n{res.error}")
        self._refresh_all_views()

    def _async_refresh_discovery(self):
        threading.Thread(target=self._do_discovery_bg, daemon=True).start()

    def _do_discovery_bg(self):
        self.device_service.refresh_discovery()
        self.root.after(0, self._refresh_all_views)

    def _async_reconcile(self):
        threading.Thread(target=self._do_reconcile_bg, daemon=True).start()

    def _do_reconcile_bg(self):
        results = self.reconcile_engine.reconcile_once()
        self.root.after(0, lambda: self._after_reconcile(results))

    def _after_reconcile(self, results):
        messagebox.showinfo(
            "Reconciliation Completed",
            f"Evaluated {len(results)} device rules against live router state.\n"
            f"All observed drift has been reconciled."
        )
        self._refresh_all_views()

    def _async_run_diagnostics(self):
        threading.Thread(target=self._do_diagnostics_bg, daemon=True).start()

    def _do_diagnostics_bg(self):
        report = self.diag_service.run_full_diagnostics()
        self.root.after(0, lambda: self.pages["diagnostics"].set_report(report))

    def _schedule_periodic_refresh(self):
        self.root.after(15000, self._periodic_timer_tick)

    def _periodic_timer_tick(self):
        self._async_refresh_discovery()
        self._schedule_periodic_refresh()

    def _refresh_events_page(self):
        evs = self.audit_service.get_recent_events(100)
        self.pages["events"].set_events(evs)

    def _refresh_current_view(self):
        self._refresh_all_views()

    def _refresh_all_views(self):
        devices = self.device_service.get_all_devices()
        active_gw = self.gw_manager.get_active_config()
        recent_events = self.audit_service.get_recent_events(20)

        # Update sidebar
        if active_gw:
            self.lbl_sidebar_gw.configure(text=f"GW: {active_gw.name} ({active_gw.status.value})")
        else:
            self.lbl_sidebar_gw.configure(text="GW: None")

        # Update Dashboard
        self.pages["dashboard"].update_view(devices, active_gw, recent_events)
        # Update Devices
        self.pages["devices"].set_devices(devices)
        # Update Policies
        self.pages["policies"].set_devices(devices)
        # Update Bandwidth
        self.pages["bandwidth"].set_devices(devices)
        # Update Gateways
        all_gws = self.gw_repo.get_all()
        backend = self.gw_manager.get_active_backend()
        caps = format_capabilities_report(backend.capabilities) if backend else {}
        self.pages["gateways"].set_gateways(all_gws, caps)
        # Update Events
        self.pages["events"].set_events(recent_events)
