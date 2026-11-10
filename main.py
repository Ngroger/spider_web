"""Entry point — Spider Web Firewall v2.0.
Usage:  python main.py            (GUI)
        python main.py --demo      (GUI + one demo notification after start)
        python -m pytest tests/   (tests, no GUI needed)
"""
from __future__ import annotations
import os, signal, sys
# Fix #1: force UTF-8 on RU Windows so netsh / logs never hit cp1251 decode errors.
os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("PYTHONIOENCODING", "utf-8:replace")
def main():
    from app.application import Application
    from utils.logging_utils import get_logger
    log=get_logger("spider_web")
    app_core=Application()
    app_core.start_monitoring()
    try:
        from PySide6.QtWidgets import QApplication, QMessageBox
        from ui.theme import apply_theme
        from ui.main_window import MainWindow
    except ImportError as e:
        log.error("PySide6 is required for the GUI: %s", e)
        print("PySide6 is required. Install with:  pip install -r requirements.txt")
        return 2
    qapp=QApplication(sys.argv)
    # Ctrl+C in the console should quit the GUI cleanly, not dump
    # KeyboardInterrupt tracebacks from inside _tick (see err_log.txt tail).
    try:
        signal.signal(signal.SIGINT, lambda *_: qapp.quit())
    except Exception: pass
    qapp.setApplicationName("Spider Web Firewall"); qapp.setOrganizationName("Spider Web")
    apply_theme(qapp)
    win=MainWindow(app_core); win.show()
    if "--demo" in sys.argv:
        from PySide6.QtCore import QTimer
        def _demo():
            from notifications.notification_manager import NotificationManager
            mgr=app_core.notifications
            g=mgr.create_group(origin_application="Figma", origin_pid=4242,
                related_processes=[{"pid":4242,"name":"figma.exe"},{"pid":4243,"name":"figma_agent.exe"},{"pid":4244,"name":"figma_helper.exe"}],
                connections=[{"remote_ip":"18.210.12.4","remote_port":443,"proto":"TCP"}],
                direction="OUTBOUND", risk="LOW")
            win.show_notification(g)
        QTimer.singleShot(1200, _demo)
    try:
        code=qapp.exec()
    except KeyboardInterrupt:
        code=0
    app_core.stop()
    return code
if __name__=="__main__":
    raise SystemExit(main())
