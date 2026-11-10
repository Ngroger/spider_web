"""Theme — minimalist red/black, Bento grid. QSS + helpers. Spec §7.

Fix #2 (de-neuralise): the old theme was the giveaway — 14px radii
everywhere, 800-weight uppercase headings, neon-red pills, 1.2px
letter-spacing. Real tools look quieter: 8px radii, 600-700 weight,
sentence-case headings, muted red only for real actions. No emoji
anywhere in the UI — text labels only.
"""
from __future__ import annotations
from app.constants import *

QSS = f"""
* {{ font-family: '{FONT_BODY}'; color: {COLOR_TEXT}; }}
QMainWindow, QWidget#Root {{ background: {COLOR_BG}; }}
QWidget#Panel, QFrame#Panel {{ background: {COLOR_PANEL}; border: 1px solid {COLOR_BORDER}; border-radius: 8px; }}
QWidget#Panel2, QFrame#Panel2 {{ background: {COLOR_PANEL_2}; border: 1px solid {COLOR_BORDER}; border-radius: 8px; }}
QLabel {{ background: transparent; }}
QLabel#H1 {{ font-size: 20px; font-weight: 700; }}
QLabel#H2 {{ font-size: 13px; font-weight: 600; }}
QLabel#Caption {{ font-size: 11px; color: {COLOR_MUTED}; }}
QLabel#Muted {{ color: {COLOR_MUTED}; font-size: 12px; }}
QLabel#Mono, QLineEdit#Mono {{ font-family: '{FONT_MONO}'; font-size: 12px; }}
QLineEdit, QComboBox, QSpinBox {{ background: {COLOR_PANEL_2}; border: 1px solid {COLOR_BORDER}; border-radius: 6px; padding: 7px 10px; font-size: 13px; }}
QLineEdit:focus, QComboBox:focus {{ border: 1px solid {COLOR_RED}; }}
QComboBox QAbstractItemView {{ background: {COLOR_PANEL_2}; selection-background-color: {COLOR_CRIMSON}; }}
QPushButton {{ background: {COLOR_PANEL_2}; border: 1px solid {COLOR_BORDER}; border-radius: 6px; padding: 7px 12px; font-size: 13px; font-weight: 500; }}
QPushButton:hover {{ border-color: #3A3A40; }}
QPushButton:pressed {{ background: #222227; }}
QPushButton#Primary {{ background: {COLOR_RED_BUTTON}; border: 1px solid {COLOR_RED_BUTTON}; color: white; font-weight: 600; }}
QPushButton#Primary:hover {{ background: #A80000; }}
QPushButton#Danger {{ background: transparent; border: 1px solid {COLOR_RED}; color: {COLOR_RED}; }}
QPushButton#Ghost {{ background: transparent; border: 1px solid {COLOR_BORDER}; }}
QPushButton#Nav {{ background: transparent; border: none; text-align: left; padding: 8px 12px; border-radius: 6px; font-size: 13px; font-weight: 500; color: {COLOR_MUTED}; }}
QPushButton#Nav:hover {{ background: {COLOR_PANEL_2}; color: {COLOR_TEXT}; }}
QPushButton#NavActive {{ background: {COLOR_PANEL_2}; border: none; border-left: 2px solid {COLOR_RED}; text-align: left; padding: 8px 12px 8px 10px; border-radius: 6px; font-size: 13px; font-weight: 600; color: white; }}
QTableWidget {{ background: {COLOR_PANEL}; border: 1px solid {COLOR_BORDER}; border-radius: 8px; gridline-color: {COLOR_BORDER}; selection-background-color: #2A0A0B; font-size: 12px; }}
QTableWidget::item {{ padding: 6px 8px; border: none; }}
QHeaderView::section {{ background: {COLOR_PANEL_2}; color: {COLOR_MUTED}; border: none; border-bottom: 1px solid {COLOR_BORDER}; padding: 8px; font-size: 11px; font-weight: 600; }}
QScrollBar:vertical {{ background: transparent; width: 6px; }}
QScrollBar::handle:vertical {{ background: {COLOR_BORDER}; border-radius: 3px; }}
QTabWidget::pane {{ border: none; }}
QTabBar::tab {{ background: transparent; padding: 8px 14px; color: {COLOR_MUTED}; font-weight: 500; }}
QTabBar::tab:selected {{ color: {COLOR_TEXT}; border-bottom: 2px solid {COLOR_RED}; }}
QCheckBox {{ spacing: 8px; }}
QMessageBox {{ background: {COLOR_PANEL}; }}
"""

def apply_theme(app):
    app.setStyleSheet(QSS)

def pill(text: str, kind: str = "muted") -> str:
    colors = {"red": COLOR_RED, "green": COLOR_GREEN, "amber": COLOR_AMBER, "muted": COLOR_BORDER, "crimson": COLOR_CRIMSON}
    c = colors.get(kind, COLOR_BORDER)
    return f'<span style="background:{c}; color:white; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:600;">{text}</span>'
