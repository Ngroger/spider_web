"""Constants — Spider Web Firewall v2.0. Single source of truth for colours, ports, thresholds."""
from __future__ import annotations

APP_NAME = "Spider Web Firewall"
APP_VERSION = "2.0.0"
ORG_NAME = "Spider Web"

# --- Palette: minimalist red / black (spec §7, Table 12) ---
COLOR_BG = "#0A0A0B"
COLOR_PANEL = "#141417"
COLOR_PANEL_2 = "#1B1B1F"
COLOR_BORDER = "#26262B"
COLOR_BORDER_RED = "#3A0D0E"
COLOR_TEXT = "#F2F2F2"
COLOR_MUTED = "#9A9AA3"
COLOR_DIM = "#6B6B73"
COLOR_RED = "#E10600"
COLOR_RED_BUTTON = "#C50000"  # muted red for buttons / toggles — less neon, more human
COLOR_CRIMSON = "#8A0F16"
COLOR_GREEN = "#22C55E"
COLOR_AMBER = "#F59E0B"
COLOR_BLUE = "#3B82F6"

FONT_HEADING = "Segoe UI, Inter, Arial"
FONT_BODY = "Segoe UI, Inter, Arial"
FONT_MONO = "JetBrains Mono, Consolas, Cascadia Code, monospace"

# --- Known suspicious / sensitive ports (spec FR-16) ---
SUSPICIOUS_PORTS = {21, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5900, 6379, 8080, 8443, 27017}
WELL_KNOWN_PORTS = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",67:"DHCP",68:"DHCP",80:"HTTP",110:"POP3",
    123:"NTP",143:"IMAP",443:"HTTPS",445:"SMB",993:"IMAPS",995:"POP3S",1433:"MSSQL",
    3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5900:"VNC",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",
}
# --- Threat thresholds (spec FR-44/45) ---
PORT_SCAN_MIN_PORTS = 8
PORT_SCAN_WINDOW_SEC = 60
BRUTE_FORCE_MIN_ATTEMPTS = 10
BRUTE_FORCE_WINDOW_SEC = 60
NOTIFICATION_DEDUP_WINDOW_SEC = 300
GROUP_SESSION_TIMEOUT_SEC = 3600

# --- System executables: NEVER notify, NEVER show as user traffic (fix #5) ---
# These are Windows itself. Their traffic is allowed silently via system
# filter rules (Rules page -> "Add system rules"). The user must not see
# svchost / System / Registry etc. in notifications, dashboard map or
# Applications/Connections lists (unless they explicitly uncheck "Hide system apps").
SYSTEM_EXES = {
    "svchost.exe","system","system idle process","registry","smss.exe","csrss.exe",
    "wininit.exe","services.exe","lsass.exe","lsalso.exe","winlogon.exe","explorer.exe",
    "searchindexer.exe","searchindexer.exe","spoolsv.exe","spooler.exe","dwm.exe",
    "fontdrvhost.exe","sihost.exe","taskhostw.exe","taskhost.exe","ctfmon.exe",
    "audiodg.exe","dllhost.exe","rundll32.exe","conhost.exe","conhost.exe",
    "lsm.exe","winresume.exe","memcompression","secure system","ntoskrnl.exe",
    "wmiprvse.exe","wmiapsrv.exe","trustedinstaller.exe","tiworker.exe","vssvc.exe",
    "searchprotocolhost.exe","searchfilterhost.exe","sched.exe","taskeng.exe",
    "googleupdate.exe","onedrive.exe","msmpeng.exe","mpdefrag.exe","securityhealthservice.exe",
    "sense.exe","msdtc.exe","sppsvc.exe","wudfhost.exe","dasHost.exe","broker.exe",
    "runtimebroker.exe","backgroundtaskhost.exe","smartscreen.exe","fontcachehost.exe",
    "dwm.exe","csrss.exe","logonui.exe","userinit.exe","dwm.exe",
}
TRUSTED_SYSTEM_EXES = SYSTEM_EXES  # backwards-compat alias
# Paths that mean "this is Windows itself", even if the exe name is unknown.
SYSTEM_PATHS = (
    "\\windows\\system32", "\\windows\\syswow64", "\\windows\\winsxs",
    "\\windows\\servicing", "\\windows\\systemapps", "\\windows\\immersivecontrolpanel",
)
# Friendly names for the Rules page system filter (exe -> display name).
SYSTEM_APPS = [
    ("svchost.exe", "Service Host (svchost)"),
    ("System", "System (kernel, PID 4)"),
    ("Registry", "Registry"),
    ("lsass.exe", "Local Security Authority (lsass)"),
    ("services.exe", "Services (services)"),
    ("winlogon.exe", "Windows Logon (winlogon)"),
    ("explorer.exe", "File Explorer (explorer)"),
    ("dwm.exe", "Desktop Window Manager (dwm)"),
    ("searchindexer.exe", "Windows Search (SearchIndexer)"),
    ("spoolsv.exe", "Print Spooler (spoolsv)"),
    ("dllhost.exe", "COM Surrogate (dllhost)"),
    ("rundll32.exe", "RunDll32"),
    ("conhost.exe", "Console Host (conhost)"),
    ("audiodg.exe", "Windows Audio (audiodg)"),
]
TRUSTED_BROWSERS = {"chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe","arc.exe"}

# --- Windows Firewall profile names as used by netsh ---
PROFILE_PUBLIC = "PUBLIC"
PROFILE_PRIVATE = "PRIVATE"
PROFILE_DOMAIN = "DOMAIN"
ALL_PROFILES = (PROFILE_PUBLIC, PROFILE_PRIVATE)

SENSITIVITY_MODES = ("Minimal", "Balanced", "Strict")
