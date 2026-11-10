"""Security helpers: admin check, least-privilege."""
from __future__ import annotations
import os, sys
def is_admin() -> bool:
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False
def is_windows() -> bool:
    return sys.platform.startswith("win")
