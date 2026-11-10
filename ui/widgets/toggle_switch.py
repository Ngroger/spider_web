"""Toggle switch — small, quiet, muted red when ON (not neon)."""
from __future__ import annotations
try:
    from PySide6.QtWidgets import QCheckBox
    from PySide6.QtCore import Qt
    _HAS = True
except Exception: _HAS = False
if _HAS:
    class ToggleSwitch(QCheckBox):
        def __init__(self, checked=False, parent=None):
            super().__init__(parent); self.setChecked(checked); self.setCursor(Qt.CursorShape.PointingHandCursor)
            self.setStyleSheet("""
            QCheckBox::indicator { width: 38px; height: 20px; border-radius: 10px; background: #26262B; border: 1px solid #33333A; }
            QCheckBox::indicator:checked { background: #C50000; border: 1px solid #C50000; }
            QCheckBox::indicator:unchecked { background: #26262B; }
            """)
else:
    class ToggleSwitch: pass
