"""Connections page — FR-09..17: live list, search/filter/sort, block from row, details."""
from __future__ import annotations
try:
    from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QComboBox, QMessageBox
    from PySide6.QtCore import Qt
    _HAS=True
except Exception: _HAS=False
if _HAS:
    from ui.widgets.connection_table import ConnectionTable
    from core.port_inspector import PortInspector
    class ConnectionsPage(QWidget):
        def __init__(self, app, parent=None):
            super().__init__(parent); self.app=app; self._conns=[]
            lay=QVBoxLayout(self); lay.setContentsMargins(20,18,20,18); lay.setSpacing(12)
            t=QLabel("Connections"); t.setObjectName("H1"); lay.addWidget(t)
            filt=QHBoxLayout()
            self.search=QLineEdit(); self.search.setPlaceholderText("Search by process, IP, port, PID…"); self.search.textChanged.connect(self._apply); filt.addWidget(self.search, 3)
            self.proto=QComboBox(); self.proto.addItems(["All protocols","TCP","UDP"]); self.proto.currentTextChanged.connect(self._apply); filt.addWidget(self.proto)
            self.state=QComboBox(); self.state.addItems(["All states","ESTABLISHED","LISTEN","TIME_WAIT","CLOSE_WAIT"]); self.state.currentTextChanged.connect(self._apply); filt.addWidget(self.state)
            self.susp_only=QPushButton("Suspicious only"); self.susp_only.setCheckable(True); self.susp_only.toggled.connect(self._apply); filt.addWidget(self.susp_only)
            from PySide6.QtWidgets import QCheckBox as _CB
            self.hide_system=_CB("Hide system apps"); self.hide_system.setChecked(True); self.hide_system.toggled.connect(self._apply); filt.addWidget(self.hide_system)
            refresh=QPushButton("Refresh"); refresh.clicked.connect(self.refresh); filt.addWidget(refresh)
            lay.addLayout(filt)
            self.table=ConnectionTable(); lay.addWidget(self.table, 1)
            btns=QHBoxLayout()
            block=QPushButton("Block selected app"); block.setObjectName("Danger"); block.clicked.connect(self._block_selected); btns.addWidget(block)
            rule=QPushButton("Create rule from selected"); rule.clicked.connect(self._rule_from_selected); btns.addWidget(rule)
            copy=QPushButton("Copy details"); copy.clicked.connect(self._copy); btns.addWidget(copy)
            btns.addStretch(); self.count=QLabel(""); self.count.setObjectName("Muted"); btns.addWidget(self.count); lay.addLayout(btns)
            self.detail=QLabel("Select a connection to inspect it."); self.detail.setObjectName("Mono"); self.detail.setWordWrap(True); lay.addWidget(self.detail)
            self.table.itemSelectionChanged.connect(self._show_detail)
        def refresh(self, snapshot=None):
            conns = snapshot.get("connections", []) if snapshot else PortInspector().get_connections()
            self._conns=conns; self._apply()
        def _apply(self):
            # Fix #5: hide svchost / System / etc. unless the user unchecks the box.
            if self.hide_system.isChecked():
                from notifications.notification_manager import is_system_exe
                base=[c for c in self._conns if not is_system_exe(c.process_name, c.exe)]
            else:
                base=self._conns
            proto=None if self.proto.currentText()=="All protocols" else self.proto.currentText()
            state=None if self.state.currentText()=="All states" else self.state.currentText()
            filtered=PortInspector.filter_connections(base, query=self.search.text(), proto=proto, state=state, only_suspicious=self.susp_only.isChecked())
            self.table.set_connections(filtered, risk_fn=PortInspector.is_suspicious)
            self.count.setText(f"{len(filtered)} of {len(base)} connections")
        def _selected(self):
            idx=self.table.selected_connection_index()
            if idx<0: return None
            try:
                from PySide6.QtCore import Qt as _Qt
                item=self.table.item(idx,0)
                return item.data(_Qt.ItemDataRole.UserRole) if item is not None else None
            except Exception: return None
        def _block_selected(self):
            c=self._selected()
            if not c: QMessageBox.information(self,"No selection","Select a connection first."); return
            r=QMessageBox.question(self,"Block application?", f"Block {c.process_name} ({c.exe or 'unknown path'}) and its related processes?\nThis creates a BLOCK rule.",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if r!=QMessageBox.StandardButton.Yes: return
            from core.rules_engine import RulesEngine
            rule=RulesEngine.rule_for_app_block(c.process_name, c.exe)
            self.app.rules.create(rule); self.app.logger.rule_change("CREATE", rule.name)
            QMessageBox.information(self,"Blocked", f"{c.process_name} blocked. Rule created.")
        def _rule_from_selected(self):
            c=self._selected()
            if not c: QMessageBox.information(self,"No selection","Select a connection first."); return
            # navigate to Rules page via parent main window
            mw=self.window()
            if hasattr(mw,"open_rules_with"): mw.open_rules_with(prefill={"remote_ip": c.remote_ip or "", "remote_port": str(c.remote_port or ""), "origin_application_path": c.exe or ""})
        def _copy(self):
            c=self._selected()
            if not c: return
            from PySide6.QtWidgets import QApplication
            QApplication.clipboard().setText(f"{c.process_name} pid={c.pid} {c.proto} {c.local_ip}:{c.local_port} -> {c.remote_ip}:{c.remote_port} {c.status} exe={c.exe}")
            self.detail.setText("Copied to clipboard.")
        def _show_detail(self):
            c=self._selected()
            if not c: return
            self.detail.setText(f"{c.process_name}, PID {c.pid}, {c.proto} {c.local_ip}:{c.local_port} -> {c.remote_ip}:{c.remote_port}, {c.status}\nPath: {c.exe or '—'}")
else:
    class ConnectionsPage: pass
