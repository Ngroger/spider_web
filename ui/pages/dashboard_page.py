"""Dashboard — Bento grid (spec §7.1). Protection is largest, then Web Map, Threats/Traffic/Ports, Events."""
from __future__ import annotations
try:
    from PySide6.QtWidgets import QWidget, QGridLayout, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame
    from PySide6.QtCore import Qt
    _HAS=True
except Exception: _HAS=False
if _HAS:
    from ui.widgets.bento_card import BentoCard
    from ui.widgets.web_map import WebMap
    from ui.widgets.toggle_switch import ToggleSwitch
    from utils.network_utils import format_speed
    from utils.formatting import fmt_time
    class DashboardPage(QWidget):
        def __init__(self, app, parent=None):
            super().__init__(parent); self.app=app
            grid=QGridLayout(self); grid.setContentsMargins(20,18,20,18); grid.setSpacing(10)
            grid.setColumnStretch(0,1); grid.setColumnStretch(1,1); grid.setColumnStretch(2,1)
            title=QLabel("Dashboard"); title.setObjectName("H1"); grid.addWidget(title,0,0,1,2)
            sub=QLabel("Live protection overview for this PC."); sub.setObjectName("Muted"); grid.addWidget(sub,1,0,1,3)
            # PROTECTION — largest (row 2, col 0-1, spans 2 rows)
            prot=BentoCard("Protection", "Public + Private + Emergency Shield")
            self.prot_public=ToggleSwitch(True); self.prot_private=ToggleSwitch(True); self.prot_shield=ToggleSwitch(False)
            self.prot_status=QLabel("Protected"); self.prot_status.setStyleSheet("font-size:18px; font-weight:700; color:#22C55E;")
            prot.add(self.prot_status)
            for label, sw in (("Public network", self.prot_public),("Private network", self.prot_private),("Emergency Shield", self.prot_shield)):
                row=QHBoxLayout(); row.addWidget(QLabel(label)); row.addStretch(); row.addWidget(sw); prot.add_layout(row)
            self.prot_note=QLabel("All inbound unsolicited traffic is filtered."); self.prot_note.setObjectName("Muted"); prot.add(self.prot_note)
            grid.addWidget(prot,2,0,2,1)
            # WEB MAP
            web=BentoCard("Network map", "PC  ·  apps  ·  Internet")
            self.webmap=WebMap(); web.add(self.webmap); grid.addWidget(web,2,1,2,2)
            # THREATS
            th=BentoCard("Threats", "Last 24h")
            self.threat_label=QLabel("Score —"); self.threat_label.setStyleSheet("font-size:18px; font-weight:700;"); th.add(self.threat_label)
            self.health_label=QLabel("Health score: —"); self.health_label.setObjectName("Muted"); th.add(self.health_label)
            grid.addWidget(th,4,0,1,1)
            # TRAFFIC
            tr=BentoCard("Traffic", "Live")
            self.traffic_up=QLabel("Upload: 0 B/s"); self.traffic_up.setStyleSheet("font-size:14px; font-weight:600;")
            self.traffic_down=QLabel("Download: 0 B/s"); self.traffic_down.setStyleSheet("font-size:14px; font-weight:600;")
            tr.add(self.traffic_up); tr.add(self.traffic_down); grid.addWidget(tr,4,1,1,1)
            # PORTS
            po=BentoCard("Active ports", "Listening + established")
            self.ports_label=QLabel("— listening, — established"); self.ports_label.setStyleSheet("font-size:13px; font-weight:600; font-family:'JetBrains Mono', Consolas, monospace;")
            po.add(self.ports_label); self.ports_detail=QLabel("443  •  80  •  53"); self.ports_detail.setObjectName("Muted"); po.add(self.ports_detail)
            grid.addWidget(po,4,2,1,1)
            # EVENTS
            ev=BentoCard("Recent events", "Security log")
            self.events_label=QLabel("No events yet."); self.events_label.setWordWrap(True); self.events_label.setObjectName("Muted"); ev.add(self.events_label)
            grid.addWidget(ev,5,0,1,3)
            grid.setRowStretch(5,1)
            # wire toggles -> firewall service (with confirmation for OFF handled in main window via signals)
            self.prot_public.toggled.connect(lambda v: self._on_toggle("PUBLIC", v))
            self.prot_private.toggled.connect(lambda v: self._on_toggle("PRIVATE", v))
            self.prot_shield.toggled.connect(lambda v: self._on_shield(v))
            self._pending_confirm=False
        def _on_toggle(self, profile, on):
            if self._pending_confirm: return
            # main window intercepts via callback if set
            if hasattr(self, "on_firewall_toggle") and self.on_firewall_toggle:
                self.on_firewall_toggle(profile, on, self)
            else:
                self.app.firewall.set_profile(profile, on)
        def _on_shield(self, on):
            if self._pending_confirm: return  # refresh() syncing the switch — not a user action
            self.app.firewall.set_emergency_shield(on)
            if hasattr(self, "on_refresh") and self.on_refresh: self.on_refresh()
        def refresh(self, snapshot=None, fw_state=None, events=None):
            if fw_state:
                self._pending_confirm=True
                self.prot_public.setChecked(fw_state.public); self.prot_private.setChecked(fw_state.private); self.prot_shield.setChecked(fw_state.emergency_shield)
                self._pending_confirm=False
                ok = fw_state.public and fw_state.private
                self.prot_status.setText("Protected" if ok else "At risk")
                self.prot_status.setStyleSheet(f"font-size:18px; font-weight:700; color:{'#22C55E' if ok else '#E10600'};")
                self.prot_note.setText(f"Profile: {fw_state.active_profile}, Network: {fw_state.network_name}" + ("  •  Admin: yes" if fw_state.admin else "  •  Admin: no — some changes need elevation"))
            if snapshot:
                conns=snapshot.get("connections", [])
                listening=[c for c in conns if c.status=="LISTEN"]; est=[c for c in conns if c.status=="ESTABLISHED"]
                self.traffic_up.setText(f"Upload: {format_speed(snapshot.get('upload_bps',0))}")
                self.traffic_down.setText(f"Download: {format_speed(snapshot.get('download_bps',0))}")
                self.ports_label.setText(f"{len(listening)} listening, {len(est)} established")
                ports=sorted({c.local_port for c in listening if c.local_port})[:8]
                self.ports_detail.setText(", ".join(map(str, ports)) if ports else "No listening ports")
                # web map: top apps + internet
                from core.process_grouping import group_connections_by_app
                from notifications.notification_manager import is_system_exe
                groups=[g for g in group_connections_by_app(conns) if not is_system_exe(g["display_name"], g["exe"])][:6]
                nodes=[(g["display_name"] or g["product_key"], "unknown" if "unknown" in g["product_key"] else "app") for g in groups]
                if not nodes: nodes=[("No traffic","app")]
                nodes.append(("Internet","internet"))
                self.webmap.set_nodes(nodes)
            if events is not None:
                if events:
                    lines=[f"{fmt_time(e.timestamp)}  {e.application_name or e.event_type} — {e.details[:80]}" for e in events[:5] if not (e.application_name and e.application_name.lower() in ("svchost.exe", "system"))]
                    self.events_label.setText("\n".join(lines)); self.events_label.setStyleSheet("font-size:12px;")
                else:
                    self.events_label.setText("No events yet — your PC is quiet.")
            # health
            try:
                from core.threat_detector import ThreatDetector
                st=self.app.firewall.get_state() if fw_state is None else fw_state
                conns=snapshot.get("connections", []) if snapshot else []
                susp=sum(1 for c in conns if c.status=="LISTEN" and c.local_port in (21,23,3389,445,5900))
                score, reasons = self.app.threats.health_score(firewall_public=st.public, firewall_private=st.private,
                    emergency_shield=st.emergency_shield, listening_count=len([c for c in conns if c.status=="LISTEN"]),
                    suspicious_listening=susp, unknown_apps=0, recent_high_alerts=0)
                self.health_label.setText(f"Health score: {score}/100")
                self.threat_label.setText(f"Score {score}")
            except Exception: pass
else:
    class DashboardPage: pass
