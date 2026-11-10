"""Live network monitor — polls psutil, computes per-app traffic, emits via callback.
Runs on a background thread; UI never blocks (NFR-01)."""
from __future__ import annotations
import threading, time
import psutil
from core.port_inspector import PortInspector

class NetworkMonitor:
    def __init__(self, interval_sec=3, on_update=None):
        self.interval=interval_sec; self.on_update=on_update
        self._stop=threading.Event(); self._thread=None
        self.inspector=PortInspector()
        self._prev_io=None; self._prev_ts=None
        self.last_snapshot=None
    def start(self):
        if self._thread and self._thread.is_alive(): return
        self._stop.clear(); self._thread=threading.Thread(target=self._loop, daemon=True, name="net-monitor"); self._thread.start()
    def stop(self):
        self._stop.set()
        if self._thread: self._thread.join(timeout=2)
    def snapshot(self):
        conns=self.inspector.get_connections()
        up, down = self._traffic_speed()
        # per-process IO is not reliably available per-connection on Windows without a driver;
        # we report system totals + per-app connection counts (honest, spec §5.4 FR-31 "where feasible").
        return {"connections": conns, "upload_bps": up, "download_bps": down,
                "listening": [c for c in conns if c.status=="LISTEN"],
                "established": [c for c in conns if c.status=="ESTABLISHED"],
                "timestamp": time.time()}
    def _traffic_speed(self):
        try:
            cur=psutil.net_io_counters(); now=time.time()
            if self._prev_io is None:
                self._prev_io=cur; self._prev_ts=now; return 0.0, 0.0
            dt=max(0.1, now-self._prev_ts)
            up=(cur.bytes_sent-self._prev_io.bytes_sent)/dt
            down=(cur.bytes_recv-self._prev_io.bytes_recv)/dt
            self._prev_io=cur; self._prev_ts=now
            return max(0.0, up), max(0.0, down)
        except Exception:
            return 0.0, 0.0
    def _loop(self):
        while not self._stop.is_set():
            try:
                snap=self.snapshot(); self.last_snapshot=snap
                if self.on_update: self.on_update(snap)
            except Exception:
                pass
            self._stop.wait(self.interval)
