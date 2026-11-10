"""Left sidebar — logo + nav + version. Text labels only, no icons, no emoji."""
from __future__ import annotations
try:
    from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QFrame
    from PySide6.QtCore import Qt, Signal
    _HAS = True
except Exception: _HAS = False
NAV = ["Dashboard", "Firewall", "Connections", "Ports", "Applications", "Rules", "Notifications", "Logs", "Settings"]
if _HAS:
    class Sidebar(QWidget):
        navigate = Signal(str)
        def __init__(self, parent=None):
            super().__init__(parent); self.setFixedWidth(200)
            self.setStyleSheet("background:#0A0A0B; border-right:1px solid #26262B;")
            lay = QVBoxLayout(self); lay.setContentsMargins(14, 16, 14, 14); lay.setSpacing(2)
            logo = QLabel("Spider Web"); logo.setStyleSheet("font-size:15px; font-weight:700;")
            lay.addWidget(logo)
            sub = QLabel("Firewall  ·  v2.0"); sub.setStyleSheet("font-size:11px; color:#9A9AA3;")
            lay.addWidget(sub)
            div = QFrame(); div.setFixedHeight(1); div.setStyleSheet("background:#26262B; margin:10px 0;"); lay.addWidget(div)
            self.buttons = {}
            for key in NAV:
                b = QPushButton(key); b.setObjectName("Nav"); b.setCursor(Qt.CursorShape.PointingHandCursor)
                b.clicked.connect(lambda _=False, k=key: self.select(k))
                lay.addWidget(b); self.buttons[key] = b
            lay.addStretch()
            foot = QLabel("Local only. Data stays on this PC."); foot.setStyleSheet("font-size:11px; color:#6B6B73;")
            foot.setWordWrap(True); lay.addWidget(foot)
            self.select("Dashboard")
        def select(self, key):
            for k, b in self.buttons.items():
                b.setObjectName("NavActive" if k == key else "Nav")
                b.setStyleSheet("")
            for b in self.buttons.values(): b.style().unpolish(b); b.style().polish(b)
            self.navigate.emit(key)
else:
    class Sidebar: pass
