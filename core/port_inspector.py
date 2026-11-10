"""Port inspector — spec §5.2, FR-09..17. Pure psutil, testable without Qt."""
from __future__ import annotations
import psutil
from storage.models import NetworkConnection
from utils.network_utils import is_suspicious_port

class PortInspector:
    def __init__(self, proc_cache: dict | None = None):
        self._proc_cache = proc_cache or {}
    def _proc_info(self, pid):
        if pid is None: return ("", "", None)
        if pid in self._proc_cache: return self._proc_cache[pid]
        try:
            p=psutil.Process(pid); info=(p.name(), p.exe(), p.create_time())
        except Exception:
            info=("", "", None)
        self._proc_cache[pid]=info
        return info
    def get_connections(self) -> list[NetworkConnection]:
        out=[]
        try:
            raw=psutil.net_connections(kind="inet")
        except Exception:
            return out
        for c in raw:
            laddr=getattr(c,"laddr",None); raddr=getattr(c,"raddr",None)
            name, exe, _ctime=self._proc_info(c.pid)
            out.append(NetworkConnection(
                proto="TCP" if c.type==1 else "UDP" if c.type==2 else str(c.type),
                local_ip=laddr.ip if laddr else "", local_port=laddr.port if laddr else None,
                remote_ip=raddr.ip if raddr else "", remote_port=raddr.port if raddr else None,
                status=c.status or "", pid=c.pid, process_name=name, exe=exe,
                process_create_time=_ctime))
        return out
    def get_listening(self) -> list[NetworkConnection]:
        return [c for c in self.get_connections() if c.status=="LISTEN"]
    def get_established(self) -> list[NetworkConnection]:
        return [c for c in self.get_connections() if c.status=="ESTABLISHED"]
    @staticmethod
    def filter_connections(conns, query="", proto=None, state=None, only_suspicious=False):
        q=(query or "").lower().strip()
        out=[]
        for c in conns:
            if proto and c.proto!=proto: continue
            if state and c.status!=state: continue
            if only_suspicious and not (is_suspicious_port(c.local_port) or is_suspicious_port(c.remote_port)): continue
            if q:
                hay=f"{c.process_name} {c.exe} {c.local_ip} {c.local_port} {c.remote_ip} {c.remote_port} {c.status} {c.pid}".lower()
                if q not in hay: continue
            out.append(c)
        return out
    @staticmethod
    def sort_connections(conns, key="local_port", reverse=False):
        def _k(c):
            v=getattr(c, key, "")
            return (v is None, v)
        return sorted(conns, key=_k, reverse=reverse)
    @staticmethod
    def is_suspicious(c: NetworkConnection) -> tuple[bool,str]:
        if is_suspicious_port(c.local_port):
            return True, f"Listening on sensitive port {c.local_port}"
        if is_suspicious_port(c.remote_port):
            return True, f"Remote sensitive port {c.remote_port}"
        if c.status=="LISTEN" and c.local_ip in ("0.0.0.0","::"):
            # listening on all interfaces is not by itself suspicious — only flag with sensitive port
            return False, ""
        return False, ""
