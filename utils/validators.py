"""Input validation (spec FR-40, NFR-06). Pure functions, no Qt, fully tested."""
from __future__ import annotations
import ipaddress, re, os

_PORT_RE = re.compile(r"^\d{1,5}$")

def is_valid_port(value) -> bool:
    try:
        if isinstance(value, str) and not _PORT_RE.match(value.strip()):
            return False
        n = int(value)
        return 1 <= n <= 65535
    except Exception:
        return False

def is_valid_port_range(value) -> bool:
    """Accepts '80', '8000-8100', ''/None (means ANY)."""
    if value is None or (isinstance(value, str) and value.strip() in ("", "*")):
        return True
    s = str(value).strip()
    if "-" in s:
        a, b = s.split("-", 1)
        return is_valid_port(a.strip()) and is_valid_port(b.strip()) and int(a) <= int(b)
    return is_valid_port(s)

def port_in_range(port: int, spec) -> bool:
    if spec is None or (isinstance(spec, str) and spec.strip() in ("", "*")):
        return True
    s = str(spec).strip()
    if "-" in s:
        a, b = s.split("-", 1)
        return int(a) <= int(port) <= int(b)
    return int(s) == int(port)

def is_valid_ip(value) -> bool:
    if not value or str(value).strip() in ("", "*"):
        return True  # empty = ANY
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except Exception:
        return False

def is_valid_cidr_or_ip(value) -> bool:
    if not value or str(value).strip() in ("", "*"):
        return True
    s = str(value).strip()
    try:
        if "/" in s:
            ipaddress.ip_network(s, strict=False)
        else:
            ipaddress.ip_address(s)
        return True
    except Exception:
        return False

def ip_matches(ip: str, rule_ip) -> bool:
    if not rule_ip or str(rule_ip).strip() in ("", "*"):
        return True
    if not ip:
        return False
    try:
        if "/" in str(rule_ip):
            return ipaddress.ip_address(ip) in ipaddress.ip_network(str(rule_ip), strict=False)
        return ipaddress.ip_address(ip) == ipaddress.ip_address(str(rule_ip))
    except Exception:
        return False

def is_valid_exe_path(value) -> bool:
    if not value:
        return True  # rule may be port/IP only
    s = str(value).strip()
    if len(s) > 260:
        return False
    if ".." in s.split(os.sep):
        # still allow relative-ish names like "chrome.exe" — only block traversal in paths
        if os.sep in s or "/" in s:
            return False
    return True

def validate_rule_dict(d: dict) -> list[str]:
    errs = []
    if not d.get("name"):
        errs.append("Rule name is required.")
    if d.get("direction") not in ("INBOUND","OUTBOUND","BOTH"):
        errs.append("Direction must be INBOUND, OUTBOUND or BOTH.")
    if d.get("action") not in ("ALLOW","BLOCK","ASK"):
        errs.append("Action must be ALLOW, BLOCK or ASK.")
    if d.get("protocol") not in ("TCP","UDP","ICMP","ANY"):
        errs.append("Protocol must be TCP, UDP, ICMP or ANY.")
    if not is_valid_port_range(d.get("local_port")):
        errs.append("Invalid local port / range.")
    if not is_valid_port_range(d.get("remote_port")):
        errs.append("Invalid remote port / range.")
    if not is_valid_cidr_or_ip(d.get("remote_ip")):
        errs.append("Invalid remote IP / CIDR.")
    if d.get("profile") not in ("PUBLIC","PRIVATE","BOTH"):
        errs.append("Profile must be PUBLIC, PRIVATE or BOTH.")
    if not is_valid_exe_path(d.get("origin_application_path")):
        errs.append("Invalid application path.")
    try:
        int(d.get("priority", 100))
    except Exception:
        errs.append("Priority must be an integer.")
    return errs
