from core.threat_detector import ThreatDetector
def test_port_scan():
    d=ThreatDetector()
    alerts=[]
    for port in range(8000, 8012):
        alerts += d.observe(remote_ip="203.0.113.9", local_port=port, direction="INBOUND")
    assert any(a["type"]=="PORT_SCAN" for a in alerts)

def test_brute_force():
    d=ThreatDetector()
    alerts=[]
    for _ in range(12):
        alerts += d.observe(remote_ip="198.51.100.7", local_port=22, direction="INBOUND")
    assert any(a["type"]=="BRUTE_FORCE" for a in alerts)

def test_local_ip_ignored():
    d=ThreatDetector()
    assert d.observe(remote_ip="192.168.1.5", local_port=80, direction="INBOUND")==[]
    assert d.observe(remote_ip="127.0.0.1", local_port=80, direction="INBOUND")==[]

def test_health_score():
    d=ThreatDetector()
    score, reasons = d.health_score(firewall_public=True, firewall_private=True, emergency_shield=False,
        listening_count=5, suspicious_listening=0, unknown_apps=0, recent_high_alerts=0)
    assert score==100
    score2, _ = d.health_score(firewall_public=False, firewall_private=True, emergency_shield=False,
        listening_count=5, suspicious_listening=0, unknown_apps=0, recent_high_alerts=0)
    assert score2 < score
