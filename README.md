# Spider Web Firewall — v2.0

Windows desktop firewall + live network monitor + consolidated notifications.
**Minimalist black/red, Bento grid.** Local-only — no cloud, SQLite on this PC.

## Quick start (Windows 10 / 11)

Recommended — via `uv` (no system Python needed):

```bat
run-uv.bat
```

or manually:

```bat
uv run main.py
```

Without `uv`:

```bat
py -3.11 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

> `run-uv.bat` / `run.bat` / `main.py` force `PYTHONUTF8=1` — on RU Windows
> `netsh` outputs cp866, and without this the log filled with
> `UnicodeDecodeError` (see `dev_logs.txt`, fix #1).

> Firewall changes need **Administrator** rights. Right-click → *Run as administrator* for real `netsh` changes.
> Without admin / outside Windows the app runs in **simulated mode** — UI, rules, logs and grouping all work, firewall toggles are stored locally.

Demo notification:

```bat
python main.py --demo
```

## What it does (spec §5 / §19 acceptance criteria)

| Area | Behaviour |
|---|---|
| Firewall | Public / Private ON/OFF independently, confirmation before OFF, Emergency Shield (blocks all unsolicited inbound), Incident Response |
| Ports & Connections | Live TCP/UDP, listening + established, process / PID / exe, search / filter / sort, suspicious-port highlight, copy details |
| Notifications | **One per app launch** — helpers fold into the origin app. External-only, trusted/system traffic silent. **Fresh-only:** connections that existed before the firewall started never notify. **System filter:** svchost / System / lsass etc. never notify (Rules page → System filter). Allow / Block / Details. Dedup 5 min. Minimal / Balanced / Strict |
| Applications | Per-app network Task Manager: connections, endpoints, Block / Allow / End process (with confirmation) |
| Rules | CRUD, priority (lower wins), conflict detection, presets, full validation (IP/CIDR, ports, exe path) |
| Security | Port-scan + brute-force detection (threshold + cooldown), health score 0–100, event log, CSV/JSON export |
| Design | `#0A0A0B` + `#E10600`, Bento dashboard, glass toasts only for notifications, mono font for IP/port/PID |

## Project structure (spec §9)

```
main.py  app/  ui/  core/  notifications/  storage/  utils/  tests/
```

`ui/` never talks to Windows APIs directly — everything goes through `core/*` services.

## Tests

```bat
python -m pytest tests/ -q
```

Core logic (rules, grouping, threat detection, notifications, validators, port inspector) is tested without Qt, so it runs on any machine.

## Data

`%APPDATA%\SpiderWebFirewall\spider_web.db` (SQLite) + `config.json`. Nothing is sent anywhere.
