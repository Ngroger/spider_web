# Spider Web Firewall — запуск через uv (системный python НЕ нужен)
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host '[x] uv не найден. Установи:' -ForegroundColor Red
    Write-Host 'irm https://astral.sh/uv/install.ps1 | iex' -ForegroundColor Yellow
    exit 1
}
uv python install 3.11
uv sync
uv run main.py $args
