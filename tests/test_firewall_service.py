"""Regression: set_profile / set_emergency_shield must not deadlock (RLock).
Previously a plain Lock + nested get_state() froze the app on any toggle."""
import tempfile, pathlib
from app.config import Config
from core.firewall_service import FirewallService

def test_toggle_does_not_deadlock():
    tmp=pathlib.Path(tempfile.mkdtemp())
    svc=FirewallService(config=Config(path=tmp/"c.json"))
    assert svc.set_profile("PUBLIC", False)[0] is True
    assert svc.get_state().public is False
    assert svc.set_profile("PUBLIC", True)[0] is True
    assert svc.set_emergency_shield(True)[0] is True
    assert svc.get_state().emergency_shield is True
    assert svc.set_emergency_shield(False)[0] is True
