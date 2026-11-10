"""Regression tests for the 2026-11-10 fix batch (see dev_logs.txt).
Covers: #1 cp866 decode, #2 no emoji, #4 fresh-only / baseline,
#5 system filter, plus the re-restored companion fixes (RLock, RuleDialog).
No Qt needed for these tests (pure logic + file scans).
"""
import pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# --- #1: cp866 decode never returns None / never raises ---
def test_win32_decodes_cp866_bytes():
    from utils.win32 import _decode, run_win_command, safe_upper
    # byte 0x98 is the exact byte from err_log.txt: invalid in cp1251, valid in cp866 (й)
    assert _decode(b"State  ON \x98") != ""
    assert "ON" in safe_upper(_decode(b"State  ON \x98"))
    assert safe_upper(None) == ""
    assert safe_upper("") == ""

def test_firewall_get_state_never_none_on_bad_bytes(monkeypatch):
    import core.firewall_service as fs
    # Simulate netsh returning cp866 bytes with byte 0x98 — the old code crashed here.
    monkeypatch.setattr("utils.win32.subprocess.run",
        lambda *a, **k: type("R", (), {"returncode": 0, "stdout": b"State  ON \x98"})())
    import utils.win32 as w
    rc, out = w.run_win_command(["netsh", "advfirewall", "show", "publicprofile", "state"])
    assert rc == 0 and "ON" in out.upper()
    # RLock: set_profile -> get_state under the same lock must not deadlock.
    import threading
    assert isinstance(fs.FirewallService(backend=fs._SimulatedBackend())._lock, type(threading.RLock()))

# --- #2: no emoji in UI code ---
def test_no_emoji_in_ui_py_files():
    emoji = re.compile(r"[\U0001F000-\U0001FAFF\U00002600-\U000027BF]")
    bad = []
    for f in (ROOT / "ui").rglob("*.py"):
        if f.name.endswith("_1.py"):
            continue  # snapshot-restored duplicates, excluded from the delivered zip
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if emoji.search(line):
                bad.append(f"{f.relative_to(ROOT)}:{i}:{line.strip()}")
    assert not bad, "\n".join(bad)

# --- #5: system filter ---
def test_system_apps_never_notify():
    from notifications.notification_manager import NotificationManager, is_system_exe
    assert is_system_exe("svchost.exe", r"C:\Windows\System32\svchost.exe")
    assert is_system_exe("System", "")
    assert is_system_exe("lsass.exe", r"C:\Windows\System32\lsass.exe")
    assert not is_system_exe("chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe")
    assert not is_system_exe("figma.exe", r"C:\Users\x\AppData\Figma\figma.exe")
    m = NotificationManager()
    for exe in ("svchost.exe", "System", "Registry", "lsass.exe"):
        ok, why = m.should_notify(app_name=exe, exe_name=exe, remote_ip="93.184.216.34",
                                  remote_port=443, risk="HIGH")
        assert ok is False and "System" in why, (exe, why)

def test_system_filter_rules_cover_svchost():
    from core.rules_engine import system_filter_rules
    rules = system_filter_rules()
    assert len(rules) >= 10
    assert all(r.action == "ALLOW" and r.priority == 1 for r in rules)
    assert any("svchost" in r.name.lower() for r in rules)

# --- #4: fresh-only / baseline ---
def test_baseline_connections_never_notify():
    from notifications.notification_manager import NotificationManager
    m = NotificationManager()
    m.set_baseline({(1234, "93.184.216.34", 443, "TCP")})
    ok, why = m.should_notify(app_name="chrome.exe", exe_name="chrome.exe",
                              exe_path=r"C:\Chrome\chrome.exe",
                              remote_ip="93.184.216.34", remote_port=443,
                              risk="HIGH", pid=1234, proto="TCP")
    assert ok is False and "before firewall" in why
    # Same app, NEW destination after start -> not baseline -> may notify in Strict.
    m.set_sensitivity("Strict")
    ok2, _ = m.should_notify(app_name="chrome.exe", exe_name="chrome.exe",
                             exe_path=r"C:\Chrome\chrome.exe",
                             remote_ip="8.8.8.8", remote_port=443,
                             risk="MEDIUM", pid=1234, proto="TCP")
    assert ok2 is True

def test_threat_detector_counts_repeated_same_port_attempts():
    # Repeated attempts to the SAME port are brute-force — observe() must
    # count them (the re-poll protection lives in MainWindow._tick, which only
    # feeds NEW (pid, ip, port) keys, not in observe()).
    from core.threat_detector import ThreatDetector
    d = ThreatDetector(brute_min=3)
    alerts = []
    for _ in range(3):
        alerts += d.observe(remote_ip="1.2.3.4", local_port=22, direction="INBOUND")
    assert any(a["type"] == "BRUTE_FORCE" for a in alerts)

# --- companion: RuleDialog must not mutate before accept (checked via source) ---
def test_rule_dialog_does_not_mutate_live_rule():
    src = (ROOT / "ui" / "pages" / "rules_page.py").read_text(encoding="utf-8")
    assert "for k,v in d.items(): setattr(self.rule,k,v)" not in src
    assert "cand=FirewallRule(**d)" in src
