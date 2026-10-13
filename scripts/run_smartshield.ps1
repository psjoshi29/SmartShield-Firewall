# =====================================================================
# SmartShield Firewall Simulator - Windows PowerShell Launcher
# =====================================================================

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir\.."
Set-Location $ProjectRoot

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  SmartShield Cyber Firewall Simulator" -ForegroundColor White
Write-Host "  College-Level Security Engineering Project" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "[INFO] Creating virtual environment (.venv)..." -ForegroundColor Yellow
    py -3.12 -m venv .venv
    if ($LASTEXITCODE -ne 0) {
        python -m venv .venv
    }
    Write-Host "[INFO] Installing dependencies from requirements.txt..." -ForegroundColor Yellow
    & "$VenvPython" -m pip install --upgrade pip
    & "$VenvPython" -m pip install -r requirements.txt
}

Write-Host "[INFO] Launching SmartShield Dashboard on http://127.0.0.1:8501..." -ForegroundColor Green
& "$VenvPython" run_app.py
