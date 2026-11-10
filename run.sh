#!/bin/sh
# Spider Web Firewall — dev launcher (simulated firewall outside Windows)
python3 -m venv .venv 2>/dev/null || true
. .venv/bin/activate 2>/dev/null || true
pip install -r requirements.txt 2>/dev/null || true
python3 main.py "$@"
