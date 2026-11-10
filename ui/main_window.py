"""Main window — sidebar + stacked pages + live refresh + tray + notifications."""
from __future__ import annotations
try:
    from PySide6.QtWidgets import (QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QStackedWidget, QLabel,
        QSystemTrayIcon, QMenu, QMessageBox, QPushButton)
    from PySide6.QtCore import Qt, QTimer, Signal
    from PySide6.QtGui import QAction, QIcon
    _HAS = True
except Exception: _HAS = False
if _HAS:
    from ui.theme import apply_theme
    from ui.widgets.sidebar import Sidebar
    from ui.pages.dashboard_page import DashboardPage
    from ui.pages.firewall_page import FirewallPage
    from ui.pages.connections_page import ConnectionsPage
    from ui.pages.ports_page import PortsPage
    from ui.pages.applications_page import ApplicationsPage
    from ui.pages.rules_page import RulesPage
    from ui.pages.notifications_page import NotificationsPage
    from ui.pages.logs_page import LogsPage
    from ui.pages.settings_page import SettingsPage
    from notifications.notification_window import NotificationWindow
    from notifications.notification_manager import is_system_exe
    from utils.security import is_admin
    class MainWindow(QMainWindow):
        def __init__(self, app):
            super().__init__(); self.app = app
            self.setWindowTitle("Spider Web Firewall — v2.0"); self.resize(1240, 780); self.setMinimumSize(980, 620)
            root = QWidget(); root.setObjectName("Root"); self.setCentralWidget(root)
            lay = QHBoxLayout(root); lay.setContentsMargins(0, 0, 0, 0); lay.setSpacing(0)
            self.sidebar = Sidebar(); lay.addWidget(self.sidebar)
            col = QWidget(); coll = QVBoxLayout(col); coll.setContentsMargins(0, 0, 0, 0); coll.setSpacing(0)
            top = QHBoxLayout(); top.setContentsMargins(20, 12, 20, 8)
            self.top_status = QLabel("Protected"); self.top_status.setStyleSheet("font-weight:700; color:#22C55E;"); top.addWidget(self.top_status)
            top.addStretch()
            self.admin_label = QLabel("Admin: yes" if is_admin() else "Admin: no — run as admin for firewall changes")
            self.admin_label.setStyleSheet("font-size:11px; color:#9A9AA3;"); top.addWidget(self.admin_label)
            shield = QPushButton("Emergency Shield"); shield.setObjectName("Danger"); shield.clicked.connect(lambda: self._toggle_shield()); top.addWidget(shield)
            coll.addLayout(top)
            self.stack = QStackedWidget(); coll.addWidget(self.stack, 1); lay.addWidget(col, 1)
            self.pages = {}
            for key, cls in [("Dashboard", DashboardPage), ("Firewall", FirewallPage), ("Connections", ConnectionsPage),
                             ("Ports", PortsPage), ("Applications", ApplicationsPage), ("Rules", RulesPage),
                             ("Notifications", NotificationsPage), ("Logs", LogsPage), ("Settings", SettingsPage)]:
                p = cls(app, self); self.pages[key] = p; self.stack.addWidget(p)
            self.sidebar.navigate.connect(self._nav)
            self.pages["Dashboard"].on_firewall_toggle = self._confirm_toggle
            self.pages["Dashboard"].on_refresh = self.refresh_all
            # Fix #4: keys already seen. Seeded with the baseline snapshot taken
            # in Application.start_monitoring() — those connections are OLD and
            # must never notify. _tick only evaluates keys it sees for the first time.
            self._seen_conn_keys: set = set(getattr(app, "baseline_conn_keys", set()))
            self._toasts = []  # must exist BEFORE _tick() (it can show a toast)
            self.timer = QTimer(self); self.timer.timeout.connect(self._tick); self.timer.start(int(app.config.get("auto_refresh_sec", 3)) * 1000)
            self._tick(initial=True)
            self._setup_tray()
        def _nav(self, key):
            idx = list(self.pages.keys()).index(key) if key in self.pages else 0
            self.stack.setCurrentIndex(idx)
            try: self.pages[key].refresh()
            except Exception: pass
        def _confirm_toggle(self, profile, on, page):
            if not on:
                r = QMessageBox.question(self, "Disable firewall?", f"Turn OFF the {profile.title()} firewall?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if r != QMessageBox.StandardButton.Yes:
                    page.refresh(fw_state=self.app.firewall.get_state()); return
            ok, msg = self.app.firewall.set_profile(profile, on)
            if ok: self.app.logger.firewall_change(profile, "ON" if not on else "OFF", "ON" if on else "OFF")
            self.refresh_all()
        def _toggle_shield(self):
            st = self.app.firewall.get_state()
            ok, msg = self.app.firewall.set_emergency_shield(not st.emergency_shield)
            if ok: self.app.logger.log("EMERGENCY_SHIELD", "HIGH" if not st.emergency_shield else "LOW", decision="ON" if not st.emergency_shield else "OFF", details=msg)
            self.refresh_all()
        def open_rules_with(self, prefill):
            self._nav("Rules")
            from ui.pages.rules_page import RuleDialog
            dlg = RuleDialog(self.app, prefill=prefill, parent=self)
            if dlg.exec():
                from storage.models import FirewallRule
                rule = FirewallRule(**dlg._data); self.app.rules.create(rule); self.app.logger.rule_change("CREATE", rule.name); self.pages["Rules"].refresh()
        # --- notifications (fix #3: stacking + real placement) ---
        def show_notification(self, group):
            def _allow(g):
                self.app.notifications.resolve_group(g.group_id, "ALLOWED")
                self.app.logger.connection_decision(g.origin_application, "ALLOWED", details=f"Allowed via notification. {g.connection_count} connections.")
                self.pages["Notifications"].refresh()
            def _block(g):
                self.app.notifications.resolve_group(g.group_id, "BLOCKED")
                from core.rules_engine import RulesEngine
                rule = RulesEngine.rule_for_app_block(g.origin_application, None)
                try: self.app.rules.create(rule)
                except Exception: pass
                self.app.logger.connection_decision(g.origin_application, "BLOCKED", details=f"Blocked via notification. Rule created.")
                self.pages["Notifications"].refresh(); self.pages["Rules"].refresh()
            def _details(g): self._nav("Notifications")
            try:
                toast = NotificationWindow(group, on_allow=_allow, on_block=_block, on_details=_details)
                toast.show(); toast.raise_()
                self._toasts.append(toast)
                self._restack_toasts()
                # drop dead toasts so the list does not grow forever
                toast.destroyed.connect(lambda *_: self._restack_toasts())
            except Exception:
                # Fallback: tray bubble, so the decision is never silently lost.
                try:
                    if getattr(self, "tray", None):
                        self.tray.showMessage("Spider Web — Security alert",
                            f"{group.origin_application} wants to connect to {group.destination}", QSystemTrayIcon.MessageIcon.Warning, 10000)
                except Exception: pass
        def _restack_toasts(self):
            try:
                from PySide6.QtWidgets import QApplication
                self._toasts = [t for t in self._toasts if t is not None]
                # keep only visible ones
                self._toasts = [t for t in self._toasts if t.isVisible()]
                geo = QApplication.primaryScreen().availableGeometry()
                y = geo.bottom() - 16
                for toast in reversed(self._toasts):
                    y -= toast.height()
                    toast.move(geo.right() - toast.width() - 16, y)
                    y -= 12
            except Exception: pass
        # --- live tick (fixes #4 + #5 + threat spam) ---
        def _tick(self, initial=False):
            try:
                snap = self.app.monitor.snapshot()
            except Exception:
                return
            mgr = self.app.notifications
            for c in snap.get("connections", []):
                if not c.remote_ip:
                    continue
                key = (c.pid, c.remote_ip, c.remote_port, c.proto)
                if key in self._seen_conn_keys:
                    continue  # Fix #4: seen before (incl. baseline) — not a fresh request
                self._seen_conn_keys.add(key)
                if c.status not in ("ESTABLISHED", "SYN_SENT"):
                    continue
                # Fix #5: system traffic is never evaluated for notifications.
                if is_system_exe(c.process_name, c.exe):
                    continue
                # Threats: only NEW connections are attempts. Feeding the same
                # socket every tick is what produced 5 identical BRUTE_FORCE
                # alerts in one second on the dashboard.
                if c.status in ("ESTABLISHED", "SYN_SENT"):
                    alerts = self.app.threats.observe(remote_ip=c.remote_ip, local_port=c.local_port,
                        remote_port=c.remote_port, direction="INBOUND", process_name=c.process_name)
                    for a in alerts:
                        self.app.logger.log(a["type"], a["severity"], remote_ip=a["remote_ip"], details=a["details"])
                        g = mgr.create_group(origin_application=c.process_name or "Unknown", origin_pid=c.pid,
                            connections=[c.to_dict()], direction="INBOUND", risk=a["severity"])
                        if a["severity"] == "HIGH": self.show_notification(g)
                # Fresh outbound request from a real user app — the actual
                # "app wants to connect" notification (was missing entirely:
                # _tick only notified on threat alerts before).
                is_unknown = not (c.process_name and c.process_name.lower() in mgr.trusted_apps)
                risk = mgr.assess_risk(app_name=c.process_name or "Unknown", exe_name=c.process_name,
                    remote_ip=c.remote_ip, remote_port=c.remote_port, is_unknown=is_unknown)
                ok, _why = mgr.should_notify(app_name=c.process_name or "Unknown", exe_name=c.process_name,
                    exe_path=c.exe, remote_ip=c.remote_ip, remote_port=c.remote_port,
                    direction="OUTBOUND", risk=risk, pid=c.pid, proto=c.proto)
                if ok and not mgr.is_duplicate(c.process_name or "Unknown", f"{c.remote_ip}:{c.remote_port}"):
                    g = mgr.create_group(origin_application=c.process_name or "Unknown", origin_pid=c.pid,
                        related_processes=[{"pid": c.pid, "name": c.process_name}],
                        connections=[c.to_dict()], direction="OUTBOUND", risk=risk)
                    self.show_notification(g)
            self.refresh_all(snapshot=snap)
        def refresh_all(self, snapshot=None):
            st = self.app.firewall.get_state()
            ok = st.public and st.private
            self.top_status.setText("Protected" if ok else "At risk — firewall OFF")
            self.top_status.setStyleSheet(f"font-weight:700; color:{'#22C55E' if ok else '#E10600'};")
            try: self.pages["Dashboard"].refresh(snapshot=snapshot, fw_state=st, events=self.app.events.list(limit=5))
            except Exception: pass
            cur = self.stack.currentWidget()
            for key, page in self.pages.items():
                if page is cur and key not in ("Dashboard",):
                    try: page.refresh(snapshot) if key in ("Connections", "Ports", "Applications") else page.refresh()
                    except Exception: pass
        def _setup_tray(self):
            try:
                self.tray = QSystemTrayIcon(self); self.tray.setToolTip("Spider Web Firewall")
                menu = QMenu()
                for label, fn in (("Open", self.show), ("Emergency Shield", self._toggle_shield), ("Quit", self.close)):
                    a = QAction(label, self); a.triggered.connect(fn); menu.addAction(a)
                self.tray.setContextMenu(menu); self.tray.show()
                self.tray.activated.connect(lambda r: self.show() if r == QSystemTrayIcon.ActivationReason.DoubleClick else None)
            except Exception: self.tray = None
        def closeEvent(self, ev):
            if getattr(self, "tray", None) and self.tray.isVisible():
                self.hide(); ev.ignore(); return
            super().closeEvent(ev)
else:
    class MainWindow: pass
