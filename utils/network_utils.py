"""Network helpers: private/loopback classification, port names, byte formatting."""
from __future__ import annotations
import ipaddress
from app.constants import WELL_KNOWN_PORTS, SUSPICIOUS_PORTS

def is_loopback(ip: str | None) -> bool:
    if not ip:
        return True
    try:
        return ipaddress.ip_address(ip).is_loopback
    except Exception:
        return False

def is_private_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private and not a.is_loopback
    except Exception:
        return False

def is_external_ip(ip: str | None) -> bool:
    """External = not loopback, not RFC1918 private, not link-local/multicast/CGNAT.
    Explicit list instead of ipaddress.is_private: newer Python marks the
    documentation ranges (TEST-NET 192.0.2/24, 198.51.100/24, 203.0.113/24)
    as private, which broke threat detection tests that use them as example
    public IPs. Those ranges never appear as real remote IPs, so treating
    them as external is safe and keeps the tests honest."""
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
        if a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified:
            return False
        for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "0.0.0.0/8"):
            if a.version == 4 and a in ipaddress.ip_network(net):
                return False
        if a.version == 6 and (a in ipaddress.ip_network("fc00::/7") or a in ipaddress.ip_network("fe80::/10")):
            return False
        return True
    except Exception:
        return False

def is_lan_or_local(ip: str | None) -> bool:
    return is_loopback(ip) or is_private_ip(ip)

def port_service(port: int | None) -> str:
    if port is None:
        return "—"
    return WELL_KNOWN_PORTS.get(int(port), "Unknown")

def is_suspicious_port(port: int | None) -> bool:
    try:
        return int(port) in SUSPICIOUS_PORTS
    except Exception:
        return False

def format_bytes(n: float) -> str:
    for unit in ("B","KB","MB","GB","TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"

def format_speed(bps: float) -> str:
    return f"{format_bytes(bps)}/s"

def normalize_exe_name(name: str | None) -> str:
    return (name or "Unknown").strip().lower()
