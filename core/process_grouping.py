"""Origin-based process grouping — spec §6.1, FR-18/22, Table 10.
One launch = one group. Helpers (figma_agent.exe etc.) fold into the origin app.
Never extend trust to unknown children of a trusted app (spec §6.2)."""
from __future__ import annotations
import os, re
from collections import defaultdict
from storage.models import ProcessInfo, NetworkConnection

# Known helper suffixes / patterns that belong to the same product
_HELPER_PATTERNS = [
    r"_agent$", r"_helper$", r"helper$", r"_service$", r"service$", r"_updater$",
    r"updater$", r"_crashpad$", r"crashpad", r"_broker$", r"gpu-process", r"renderer",
    r"utility", r"extension", r"plugin", r"host$", r"_host$", r"worker$", r"_worker$",
]
# Well-known multi-process products: explicit origin mapping
_PRODUCT_FAMILIES = {
    "chrome": "chrome", "msedge": "msedge", "firefox": "firefox", "brave": "brave",
    "figma": "figma", "figma_agent": "figma", "figma_helper": "figma",
    "spotify": "spotify", "spotify_helper": "spotify",
    "discord": "discord", "discord_helper": "discord",
    "slack": "slack", "slack_helper": "slack",
    "teams": "teams", "code": "code", "code_helper": "code",
}

def _stem(exe_or_name: str) -> str:
    base=os.path.basename(exe_or_name or "").lower()
    if base.endswith(".exe"): base=base[:-4]
    return base

def _product_key(stem: str) -> str:
    stem=stem.lower()
    if stem in _PRODUCT_FAMILIES: return _PRODUCT_FAMILIES[stem]
    # strip helper suffixes
    for pat in _HELPER_PATTERNS:
        stem2=re.sub(pat, "", stem)
        if stem2 and stem2!=stem:
            stem=stem2; break
    return stem

def find_origin(processes: list[ProcessInfo]) -> ProcessInfo | None:
    """Origin = process whose parent is not in the group, or the oldest / topmost one.
    Heuristic, explainable: walk parent links; if no parent info, pick process whose
    exe dir is the product dir and whose stem == product key."""
    if not processes: return None
    by_pid={p.pid: p for p in processes if p.pid is not None}
    # candidates whose parent is outside the group
    candidates=[p for p in processes if p.ppid not in by_pid]
    if candidates:
        # prefer the one that is NOT a helper
        non_helpers=[p for p in candidates if _product_key(_stem(p.name))==_stem(p.name)]
        pool=non_helpers or candidates
        # prefer shortest name / earliest pid as origin
        return sorted(pool, key=lambda p: (p.pid or 0))[0]
    return sorted(processes, key=lambda p: (p.pid or 0))[0]

def group_processes(processes: list[ProcessInfo], connections: list[NetworkConnection] | None = None):
    """Group by (product_key, exe directory). Returns list of dicts:
       {origin, processes, connections, product_key}"""
    conns = connections or []
    buckets: dict[tuple, list[ProcessInfo]] = defaultdict(list)
    for p in processes:
        stem=_stem(p.name or p.exe)
        key=_product_key(stem)
        exe_dir=os.path.dirname(p.exe or "").lower() if p.exe else ""
        # group by product + directory when directory known, else product only
        buckets[(key, exe_dir)].append(p)
    # merge buckets that share product key AND one exe dir is prefix of another (same install)
    groups=[]
    for (key, _dir), procs in buckets.items():
        origin=find_origin(procs)
        pid_set={p.pid for p in procs if p.pid is not None}
        g_conns=[c for c in conns if c.pid in pid_set]
        groups.append({"product_key":key, "origin":origin, "processes":procs, "connections":g_conns})
    # sort: most connections first, then most processes
    groups.sort(key=lambda g: (len(g["connections"]), len(g["processes"])), reverse=True)
    return groups

def group_connections_by_app(connections: list[NetworkConnection]):
    """Lightweight grouping used by the Applications page: by process name stem."""
    buckets: dict[str, list[NetworkConnection]] = defaultdict(list)
    for c in connections:
        buckets[_product_key(_stem(c.process_name or c.exe)) or "unknown"].append(c)
    out=[]
    for key, conns in buckets.items():
        first=conns[0]
        out.append({"product_key":key, "display_name": first.process_name or key,
                    "pid": first.pid, "exe": first.exe, "connections": conns})
    out.sort(key=lambda g: len(g["connections"]), reverse=True)
    return out
