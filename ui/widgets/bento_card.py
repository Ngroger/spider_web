"""Bento card: title row + content, thin border, 8px radius. Quiet, not glossy."""
from __future__ import annotations
try:
    from PySide6.QtWidgets import QFrame, QVBoxLayout, QHBoxLayout, QLabel
    _HAS = True
except Exception: _HAS = False
if _HAS:
    class BentoCard(QFrame):
        def __init__(self, title: str, subtitle: str = "", badge: str = "", parent=None):
            super().__init__(parent); self.setObjectName("Panel")
            self.setStyleSheet("QFrame#Panel { background:#141417; border:1px solid #26262B; border-radius:8px; }")
            lay = QVBoxLayout(self); lay.setContentsMargins(14, 12, 14, 12); lay.setSpacing(8)
            head = QHBoxLayout()
            t = QLabel(title); t.setObjectName("H2"); head.addWidget(t)
            if badge:
                b = QLabel(badge); b.setStyleSheet("font-size:11px; color:#9A9AA3;"); head.addWidget(b)
            head.addStretch()
            if subtitle:
                s = QLabel(subtitle); s.setObjectName("Muted"); head.addWidget(s)
            lay.addLayout(head)
            self.body = QVBoxLayout(); self.body.setSpacing(8); lay.addLayout(self.body)
            div = QFrame(); div.setFixedHeight(1); div.setStyleSheet("background:#1F1F23;")
            lay.insertWidget(1, div)
        def add(self, w): self.body.addWidget(w); return w
        def add_layout(self, l): self.body.addLayout(l); return l
else:
    class BentoCard: pass
