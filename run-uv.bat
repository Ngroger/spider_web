@echo off
REM Spider Web Firewall — запуск через uv (системный python НЕ нужен)
REM uv сам скачает Python 3.11, создаст .venv и поставит зависимости
where uv >nul 2>nul || (echo [x] uv не найден. Установи:  powershell -c "irm https://astral.sh/uv/install.ps1 | iex"  & exit /b 1)
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8:replace
uv python install 3.11
uv sync
uv run main.py %*
