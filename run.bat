set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8:replace
@echo off
REM Spider Web Firewall — Windows launcher
py -3.11 -m venv .venv 2>nul
call .venv\Scripts\activate.bat
pip install -r requirements.txt
python main.py %*
