from storage.models import NetworkConnection
from core.port_inspector import PortInspector

def _c(**kw):
    d=dict(proto="TCP", local_ip="0.0.0.0", local_port=443, remote_ip="", remote_port=None, status="LISTEN", pid=1, process_name="svc.exe", exe="")
    d.update(kw); return NetworkConnection(**d)

def test_filter_and_suspicious():
    conns=[_c(local_port=443), _c(local_port=3389, process_name="rdp"), _c(local_port=80, status="ESTABLISHED", remote_ip="1.2.3.4", remote_port=80)]
    assert len(PortInspector.filter_connections(conns, query="3389"))==1
    assert len(PortInspector.filter_connections(conns, only_suspicious=True))==1
    ok, why = PortInspector.is_suspicious(_c(local_port=3389))
    assert ok and "3389" in why
    assert PortInspector.is_suspicious(_c(local_port=443))[0] is False

def test_sort():
    conns=[_c(local_port=8080), _c(local_port=80)]
    assert PortInspector.sort_connections(conns, key="local_port")[0].local_port==80
