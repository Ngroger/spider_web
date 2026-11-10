"""Rules — FR-37..42: CRUD, priority, conflict detection, presets, validation."""
from __future__ import annotations
try:
    from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem,
        QDialog, QFormLayout, QLineEdit, QComboBox, QSpinBox, QCheckBox, QMessageBox, QHeaderView, QGroupBox)
    from PySide6.QtCore import Qt
    _HAS=True
except Exception: _HAS=False
if _HAS:
    from storage.models import FirewallRule
    from core.rules_engine import RulesEngine, PRESETS
    from utils.validators import validate_rule_dict
    class RuleDialog(QDialog):
        def __init__(self, app, rule=None, prefill=None, parent=None):
            super().__init__(parent); self.app=app; self.rule=rule; self.setWindowTitle("Edit rule" if rule else "New rule"); self.setMinimumWidth(460)
            lay=QVBoxLayout(self); form=QFormLayout(); lay.addLayout(form)
            prefill=prefill or {}
            def val(attr, default=""): return getattr(rule, attr, "") if rule else prefill.get(attr, default)
            self.name=QLineEdit(str(val("name",""))); form.addRow("Name *", self.name)
            self.app_path=QLineEdit(str(val("origin_application_path") or "")); self.app_path.setPlaceholderText("C:\\…\\app.exe or empty"); form.addRow("Application path", self.app_path)
            self.direction=QComboBox(); self.direction.addItems(["INBOUND","OUTBOUND","BOTH"]); self.direction.setCurrentText(val("direction","OUTBOUND")); form.addRow("Direction", self.direction)
            self.action=QComboBox(); self.action.addItems(["ALLOW","BLOCK","ASK"]); self.action.setCurrentText(val("action","BLOCK")); form.addRow("Action", self.action)
            self.protocol=QComboBox(); self.protocol.addItems(["TCP","UDP","ICMP","ANY"]); self.protocol.setCurrentText(val("protocol","ANY")); form.addRow("Protocol", self.protocol)
            self.local_port=QLineEdit(str(val("local_port") or "")); self.local_port.setPlaceholderText("80 or 8000-8100 or empty"); form.addRow("Local port", self.local_port)
            self.remote_port=QLineEdit(str(val("remote_port") or "")); form.addRow("Remote port", self.remote_port)
            self.remote_ip=QLineEdit(str(val("remote_ip") or "")); self.remote_ip.setPlaceholderText("1.2.3.4 or 192.168.0.0/16 or empty"); form.addRow("Remote IP / CIDR", self.remote_ip)
            self.profile=QComboBox(); self.profile.addItems(["PUBLIC","PRIVATE","BOTH"]); self.profile.setCurrentText(val("profile","BOTH")); form.addRow("Profile", self.profile)
            self.priority=QSpinBox(); self.priority.setRange(1,1000); self.priority.setValue(int(val("priority",100) or 100)); form.addRow("Priority (lower = first)", self.priority)
            self.enabled=QCheckBox("Enabled"); self.enabled.setChecked(rule.enabled if rule else True); form.addRow("", self.enabled)
            btns=QHBoxLayout(); save=QPushButton("Save rule"); save.setObjectName("Primary"); save.clicked.connect(self._save); btns.addWidget(save)
            cancel=QPushButton("Cancel"); cancel.clicked.connect(self.reject); btns.addWidget(cancel); lay.addLayout(btns)
        def _save(self):
            d={"name":self.name.text().strip(),"origin_application_path":self.app_path.text().strip() or None,
               "direction":self.direction.currentText(),"action":self.action.currentText(),"protocol":self.protocol.currentText(),
               "local_port":self.local_port.text().strip() or None,"remote_port":self.remote_port.text().strip() or None,
               "remote_ip":self.remote_ip.text().strip() or None,"profile":self.profile.currentText(),
               "priority":self.priority.value(),"enabled":self.enabled.isChecked()}
            errs=validate_rule_dict(d)
            if errs: QMessageBox.warning(self,"Invalid rule","\n".join(errs)); return
            # Fix: never mutate the live rule before the user confirms.
            # Check conflicts against a throwaway candidate; the caller applies _data on accept.
            cand=FirewallRule(**d)
            if self.rule: cand.id=self.rule.id
            conflicts=RulesEngine.find_conflicts(self.app.rules.list(), cand)
            if conflicts:
                if QMessageBox.question(self,"Conflicting rule?", "Conflicts with: " + ", ".join(r.name for r in conflicts) + "\nSave anyway?")!=QMessageBox.StandardButton.Yes: return
            self._data=d; self.accept()
    class RulesPage(QWidget):
        def __init__(self, app, parent=None):
            super().__init__(parent); self.app=app
            lay=QVBoxLayout(self); lay.setContentsMargins(20,18,20,18); lay.setSpacing(12)
            t=QLabel("Rules"); t.setObjectName("H1"); lay.addWidget(t)
            lay.addWidget(QLabel("Lower priority wins. BLOCK beats ALLOW when both match. Conflicts are flagged before saving."))
            # Fix #5: system filter — one row, no extra page.
            sysrow=QHBoxLayout(); sysrow.addWidget(QLabel("System filter:"))
            add_sys=QPushButton("Add system rules (svchost, System, etc. — allow, no notifications)")
            add_sys.clicked.connect(self._add_system_rules); sysrow.addWidget(add_sys)
            from PySide6.QtWidgets import QCheckBox as _CB
            self.hide_system=_CB("Hide system rules"); self.hide_system.setChecked(False); self.hide_system.toggled.connect(self.refresh); sysrow.addWidget(self.hide_system)
            sysrow.addStretch(); lay.addLayout(sysrow)
            # presets
            presets=QHBoxLayout(); presets.addWidget(QLabel("Presets:"))
            for p in PRESETS:
                b=QPushButton(p["name"]); b.clicked.connect(lambda _=False, pp=p: self._preset(pp)); presets.addWidget(b)
            presets.addStretch(); lay.addLayout(presets)
            self.table=QTableWidget(0,7); self.table.setHorizontalHeaderLabels(["Priority","Name","Direction","Action","Protocol","Ports / IP","Profile"])
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows); self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            self.table.verticalHeader().setVisible(False); lay.addWidget(self.table, 1)
            btns=QHBoxLayout()
            for label, fn, obj in (("New rule", self._new, "Primary"),("Edit", self._edit, None),("Enable / Disable", self._toggle, None),("Delete", self._delete, "Danger")):
                b=QPushButton(label)
                if obj: b.setObjectName(obj)
                b.clicked.connect(fn); btns.addWidget(b)
            btns.addStretch(); lay.addLayout(btns)
            self.refresh()
        def _add_system_rules(self):
            from core.rules_engine import system_filter_rules
            existing={r.name for r in self.app.rules.list()}
            added=0
            for rule in system_filter_rules():
                if rule.name not in existing:
                    self.app.rules.create(rule); added+=1
            self.app.logger.rule_change("CREATE", f"System filter rules ({added} added)")
            self.refresh()
            QMessageBox.information(self, "System filter", f"{added} system rules added. System traffic is now allowed silently and will not create notifications.")
        def refresh(self):
            rules=self.app.rules.list()
            if self.hide_system.isChecked():
                rules=[r for r in rules if not r.name.startswith("System:")]
            self._rules=rules; self.table.setRowCount(0)
            for r in rules:
                row=self.table.rowCount(); self.table.insertRow(row)
                ports=f"local {r.local_port or 'any'}, remote {r.remote_port or 'any'}, {r.remote_ip or 'any IP'}"
                for col,v in enumerate([str(r.priority), r.name, r.direction, r.action, r.protocol, ports, r.profile + ("" if r.enabled else " (disabled)")]):
                    self.table.setItem(row, col, QTableWidgetItem(v))
        def _sel(self):
            rows=self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
            return self._rules[rows[0].row()] if rows else None
        def _preset(self, p):
            rule=FirewallRule(name=p["name"], direction=p.get("direction","OUTBOUND"), action=p.get("action","BLOCK"),
                              protocol=p.get("protocol","ANY"), local_port=p.get("local_port"), remote_port=p.get("remote_port"),
                              remote_ip=p.get("remote_ip"), profile=p.get("profile","BOTH"), priority=p.get("priority",100))
            dlg=RuleDialog(self.app, rule=None, prefill={"name":rule.name,"direction":rule.direction,"action":rule.action,"protocol":rule.protocol,
                          "local_port":rule.local_port or "","remote_port":rule.remote_port or "","remote_ip":rule.remote_ip or "","profile":rule.profile,"priority":rule.priority}, parent=self)
            if dlg.exec(): self._save_dialog(dlg, None)
        def _new(self):
            dlg=RuleDialog(self.app, parent=self)
            if dlg.exec(): self._save_dialog(dlg, None)
        def _edit(self):
            r=self._sel()
            if not r: return
            dlg=RuleDialog(self.app, rule=r, parent=self)
            if dlg.exec():
                for k,v in dlg._data.items(): setattr(r,k,v)
                self.app.rules.update(r); self.app.logger.rule_change("UPDATE", r.name); self.refresh()
        def _save_dialog(self, dlg, _):
            d=dlg._data; rule=FirewallRule(**d); self.app.rules.create(rule); self.app.logger.rule_change("CREATE", rule.name); self.refresh()
        def _toggle(self):
            r=self._sel()
            if not r: return
            self.app.rules.set_enabled(r.id, not r.enabled); self.app.logger.rule_change("TOGGLE", r.name, old=str(r.enabled), new=str(not r.enabled)); self.refresh()
        def _delete(self):
            r=self._sel()
            if not r: return
            if QMessageBox.question(self,"Delete rule?", f"Delete “{r.name}”? This cannot be undone.")!=QMessageBox.StandardButton.Yes: return
            self.app.rules.delete(r.id); self.app.logger.rule_change("DELETE", r.name); self.refresh()
else:
    class RulesPage: pass
