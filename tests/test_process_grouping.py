from storage.models import ProcessInfo, NetworkConnection
from core.process_grouping import group_processes, group_connections_by_app, find_origin

def _p(pid, name, ppid=None, exe=""):
    return ProcessInfo(pid=pid, name=name, ppid=ppid, exe=exe or f"C:\\Apps\\{name}")

def test_figma_helpers_fold_into_one_group():
    procs=[_p(100,"figma.exe"), _p(101,"figma_agent.exe",ppid=100), _p(102,"figma_helper.exe",ppid=100)]
    groups=group_processes(procs)
    assert len(groups)==1
    assert groups[0]["origin"].name=="figma.exe"
    assert len(groups[0]["processes"])==3

def test_different_apps_stay_separate():
    procs=[_p(100,"chrome.exe"), _p(200,"figma.exe")]
    assert len(group_processes(procs))==2

def test_group_connections_by_app():
    conns=[NetworkConnection(process_name="chrome.exe", pid=1, remote_ip="1.1.1.1", remote_port=443),
           NetworkConnection(process_name="chrome.exe", pid=1, remote_ip="8.8.8.8", remote_port=443),
           NetworkConnection(process_name="figma.exe", pid=2, remote_ip="1.1.1.1", remote_port=443)]
    groups=group_connections_by_app(conns)
    by={g["product_key"]: g for g in groups}
    assert len(by["chrome"]["connections"])==2
    assert len(by["figma"]["connections"])==1
