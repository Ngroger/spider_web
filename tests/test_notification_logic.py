from notifications.notification_manager import NotificationManager

def test_loopback_never_notifies():
    m=NotificationManager()
    assert m.should_notify(app_name="x", remote_ip="127.0.0.1", risk="HIGH")[0] is False

def test_trusted_low_risk_silent():
    m=NotificationManager(); m.set_sensitivity("Balanced")
    assert m.should_notify(app_name="chrome", exe_name="chrome.exe", remote_ip="8.8.8.8", remote_port=443, risk="LOW", is_trusted_app=True)[0] is False

def test_unknown_external_medium_notifies_in_balanced():
    m=NotificationManager(); m.set_sensitivity("Balanced")
    assert m.should_notify(app_name="unknown.exe", remote_ip="93.184.216.34", remote_port=443, risk="MEDIUM")[0] is True

def test_minimal_only_high():
    m=NotificationManager(); m.set_sensitivity("Minimal")
    assert m.should_notify(app_name="u", remote_ip="93.184.216.34", risk="MEDIUM")[0] is False
    assert m.should_notify(app_name="u", remote_ip="93.184.216.34", risk="HIGH")[0] is True

def test_dedup():
    m=NotificationManager()
    assert m.is_duplicate("Figma","1.2.3.4:443") is False
    assert m.is_duplicate("Figma","1.2.3.4:443") is True

def test_group_counts():
    m=NotificationManager()
    g=m.create_group(origin_application="Figma", related_processes=[{"pid":1},{"pid":2}],
                     connections=[{"a":1},{"b":2},{"c":3}], risk="LOW")
    assert g.process_count==2 and g.connection_count==3
