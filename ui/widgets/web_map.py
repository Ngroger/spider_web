"""Network map: PC in centre, apps as nodes. Calm diagram, not a spider-web gimmick."""
from __future__ import annotations
import math
try:
    from PySide6.QtWidgets import QWidget
    from PySide6.QtCore import Qt, QPointF
    from PySide6.QtGui import QPainter, QPen, QBrush, QFont, QColor
    _HAS = True
except Exception: _HAS = False
if _HAS:
    class WebMap(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent); self.setMinimumHeight(170)
            self.nodes = []
        def set_nodes(self, nodes):
            self.nodes = list(nodes)[:8]; self.update()
        def paintEvent(self, ev):
            p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
            w, h = self.width(), self.height(); cx, cy = w * 0.5, h * 0.5
            for r in (38, 70, 102):
                p.setPen(QPen(QColor("#1F1F23"), 1)); p.drawEllipse(QPointF(cx, cy), r, r * 0.72)
            p.setPen(QPen(QColor("#26262B"), 1))
            n = max(1, len(self.nodes))
            for i, (label, kind) in enumerate(self.nodes):
                ang = -math.pi / 2 + i * (2 * math.pi / n)
                x = cx + math.cos(ang) * min(w * 0.38, 150); y = cy + math.sin(ang) * min(h * 0.38, 70)
                p.drawLine(QPointF(cx, cy), QPointF(x, y))
                col = QColor("#C50000") if kind == "unknown" else QColor("#6B6B73") if kind == "internet" else QColor("#9A9AA3")
                p.setBrush(QBrush(col)); p.setPen(QPen(col, 1)); p.drawEllipse(QPointF(x, y), 4, 4)
                p.setPen(QPen(QColor("#9A9AA3"), 1)); p.setFont(QFont("Segoe UI", 8))
                p.drawText(QPointF(x - 28, y + 20), label[:18])
            p.setBrush(QBrush(QColor("#C50000"))); p.setPen(QPen(QColor("#C50000"), 1))
            p.drawEllipse(QPointF(cx, cy), 12, 12)
            p.setPen(QPen(QColor("white"), 1)); p.setFont(QFont("Segoe UI", 8, QFont.Weight.DemiBold))
            p.drawText(QPointF(cx - 9, cy + 3), "PC")
else:
    class WebMap: pass
