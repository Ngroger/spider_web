from core.network_monitor import NetworkMonitor
def test_snapshot_shape():
    m=NetworkMonitor(interval_sec=60)
    snap=m.snapshot()
    assert "connections" in snap and "upload_bps" in snap and "download_bps" in snap
    assert snap["upload_bps"]>=0 and snap["download_bps"]>=0
    for c in snap["connections"]:
        assert hasattr(c, "local_port") and hasattr(c, "process_name")
