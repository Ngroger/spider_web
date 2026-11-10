"""Consolidated notification — plain top-level window, bottom-right.

Fix #3 (was invisible): the old toast was a CHILD of MainWindow
(parent=self) with WA_TranslucentBackground + a stylesheet background on
the widget itself. Qt clipped it to the main window, _place() used a
height of 0 (layout not yet done), so only a thin black strip showed —
the "SPIDER WEB • SECURITY ALERT" bar from the screenshot.

Now: parent=None (real top-level), solid background on an inner QFrame
(no translucent hacks), adjustSize() BEFORE placing, raise_() +
activateWindow(), stacked by MainWindow so several toasts don't overlap.
Shows: who (app + exe path), where (destination), risk, process count,
and three real buttons: Allow / Block / Details. Auto-closes after 20s.
"""
from __future__ import annotations
try:
    from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame
    from PySide6.QtCore import Qt, QTimer
    _HAS_QT = True
except Exception:
    _HAS_QT = False

class NotificationWindow(QWidget if _HAS_QT else object):
    def __init__(self, group, on_allow=None, on_block=None, on_details=None, parent=None):
        if not _HAS_QT: raise RuntimeError("PySide6 is required for NotificationWindow")
        # NOTE: parent is deliberately ignored — this must be top-level.
        super().__init__(None)
        self.group = group; self._on_allow = on_allow; self._on_block = on_block; self._on_details = on_details
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.Tool)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setFixedWidth(360)
        self._build()
        self.adjustSize()  # height is now real — _place() in MainWindow can use it
        self._timer = QTimer(self); self._timer.setSingleShot(True); self._timer.timeout.connect(self.close)
        self._timer.start(20000)
    def _build(self):
        outer = QVBoxLayout(self); outer.setContentsMargins(0, 0, 0, 0)
        card = QFrame(); card.setStyleSheet(
            "QFrame { background: #17171A; border: 1px solid #26262B; border-radius: 8px; }")
        outer.addWidget(card)
        root = QVBoxLayout(card); root.setContentsMargins(14, 12, 14, 12); root.setSpacing(6)
        # header: title + close
        head = QHBoxLayout()
        title = QLabel("Spider Web  —  Security alert"); title.setStyleSheet("font-size:11px; color:#9A9AA3;")
        head.addWidget(title); head.addStretch()
        close = QPushButton("×"); close.setFixedSize(22, 22)
        close.setStyleSheet("background:transparent; border:none; color:#9A9AA3; font-size:16px; padding:0;")
        close.clicked.connect(self.close); head.addWidget(close)
        root.addLayout(head)
        # who
        app_name = QLabel(self.group.origin_application or "Unknown app")
        app_name.setStyleSheet("font-size:14px; font-weight:600;"); app_name.setWordWrap(True); root.addWidget(app_name)
        exe = ""
        try:
            conns = self.group.connections or []
            if conns and isinstance(conns[0], dict): exe = conns[0].get("exe") or ""
        except Exception: pass
        if exe:
            exe_l = QLabel(exe); exe_l.setStyleSheet("font-size:11px; color:#9A9AA3;")
            exe_l.setWordWrap(True); root.addWidget(exe_l)
        # where + risk
        dest = QLabel(f"Connecting to  {self.group.destination}   ·   Risk: {self.group.risk_level}")
        dest.setStyleSheet("font-family:'JetBrains Mono', Consolas, monospace; font-size:12px;")
        dest.setWordWrap(True); root.addWidget(dest)
        meta = QLabel(f"{self.group.process_count} related process(es)  ·  {self.group.connection_count} connection(s)")
        meta.setStyleSheet("font-size:11px; color:#9A9AA3;"); root.addWidget(meta)
        # buttons — always visible, real actions
        btns = QHBoxLayout(); btns.setSpacing(8)
        allow = QPushButton("Allow"); allow.setFixedHeight(30)
        allow.setStyleSheet("background:#1B1B1F; border:1px solid #26262B; border-radius:6px; font-weight:500;")
        allow.clicked.connect(self._allow); btns.addWidget(allow)
        block = QPushButton("Block"); block.setFixedHeight(30)
        block.setStyleSheet("background:#C50000; border:1px solid #C50000; color:white; border-radius:6px; font-weight:600;")
        block.clicked.connect(self._block); btns.addWidget(block)
        details = QPushButton("Details"); details.setFixedHeight(30)
        details.setStyleSheet("background:transparent; border:1px solid #26262B; border-radius:6px;")
        details.clicked.connect(self._details); btns.addWidget(details)
        root.addLayout(btns)
    def _allow(self):
        if self._on_allow: self._on_allow(self.group)
        self.close()
    def _block(self):
        if self._on_block: self._on_block(self.group)
        self.close()
    def _details(self):
        if self._on_details: self._on_details(self.group)
        self.close()
