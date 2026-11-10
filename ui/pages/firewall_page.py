"""Firewall page — FR-01..08: per-profile toggles, Emergency Shield, Incident Response, log."""
from __future__ import annotations
try:
    from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QMessageBox, QGridLayout
    from PySide6.QtCore import Qt
    _HAS=True
except Exception: _HAS=False
if _HAS:
    from ui.widgets.bento_card import BentoCard
    from ui.widgets.toggle_switch import ToggleSwitch
    class FirewallPage(QWidget):
        def __init__(self, app, parent=None):
            super().__init__(parent); self.app=app
            lay=QVBoxLayout(self); lay.setContentsMargins(20,18,20,18); lay.setSpacing(10)
            t=QLabel("Firewall"); t.setObjectName("H1"); lay.addWidget(t)
            lay.addWidget(QLabel("Separate control for Public and Private profiles. Turning protection OFF always asks for confirmation."))
            grid=QGridLayout(); grid.setSpacing(14); lay.addLayout(grid)
            self.toggles={}
            for i,(profile, desc) in enumerate([("PUBLIC","Coffee-shop / airport Wi-Fi — strictest."),("PRIVATE","Home / office — trusted network.")]):
                card=BentoCard(f"{profile.title()} profile", desc)
                sw=ToggleSwitch(True); self.toggles[profile]=sw
                row=QHBoxLayout(); row.addWidget(QLabel("Firewall")); row.addStretch(); row.addWidget(sw); card.add_layout(row)
                grid.addWidget(card,0,i)
                sw.toggled.connect(lambda v, p=profile: self._toggle(p,v))
            shield=BentoCard("Emergency Shield", "Blocks all unsolicited inbound connections")
            self.shield_sw=ToggleSwitch(False); row=QHBoxLayout(); row.addWidget(QLabel("Emergency Shield")); row.addStretch(); row.addWidget(self.shield_sw); shield.add_layout(row)
            shield.add(QLabel("Use when you suspect an attack. Outbound traffic keeps working."))
            grid.addWidget(shield,1,0,1,2)
            self.shield_sw.toggled.connect(lambda v: self._shield(v))
            btn_row=QHBoxLayout()
            incident=QPushButton("Incident Response"); incident.setObjectName("Primary"); incident.clicked.connect(self._incident); btn_row.addWidget(incident)
            restore=QPushButton("Restore all protection"); restore.clicked.connect(lambda: self.app.firewall.restore_all() or self.refresh()); btn_row.addWidget(restore)
            btn_row.addStretch(); lay.addLayout(btn_row)
            self.status=QLabel(""); self.status.setObjectName("Muted"); lay.addWidget(self.status)
            lay.addStretch(); self.refresh()
        def _confirm_off(self, profile):
            r=QMessageBox.question(self, "Disable firewall?", f"Turn OFF the {profile.title()} firewall?\nYour PC will be exposed on {profile.lower()} networks.",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            return r==QMessageBox.StandardButton.Yes
        def _toggle(self, profile, on):
            if not on and not self._confirm_off(profile):
                self.toggles[profile].setChecked(True); return
            ok, msg=self.app.firewall.set_profile(profile, on)
            if ok: self.app.logger.firewall_change(profile, "ON" if not on else "OFF", "ON" if on else "OFF")
            self.status.setText(msg); self.refresh()
        def _shield(self, on):
            ok, msg=self.app.firewall.set_emergency_shield(on)
            if ok: self.app.logger.log("EMERGENCY_SHIELD", "HIGH" if on else "LOW", decision="ON" if on else "OFF", details=msg)
            self.status.setText(msg); self.refresh()
        def _incident(self):
            msg=self.app.incident_response(); self.shield_sw.setChecked(True); self.status.setText(msg); self.refresh()
        def refresh(self):
            st=self.app.firewall.get_state()
            for p, sw in self.toggles.items():
                sw.blockSignals(True); sw.setChecked(st.public if p=="PUBLIC" else st.private); sw.blockSignals(False)
            self.shield_sw.blockSignals(True); self.shield_sw.setChecked(st.emergency_shield); self.shield_sw.blockSignals(False)
            self.status.setText(f"Active profile: {st.active_profile}, Network: {st.network_name}, Admin: {'yes' if st.admin else 'no'}")
else:
    class FirewallPage: pass
