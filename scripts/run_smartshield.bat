@echo off
REM =====================================================================
REM SmartShield Firewall Simulator - Windows One-Click Launcher (Batch)
REM =====================================================================

cd /d "%~dp0\.."

echo ===================================================
echo   SmartShield Cyber Firewall Simulator
echo   College-Level Security Engineering Project
echo ===================================================
echo.

IF NOT EXIST ".venv\Scripts\python.exe" (
    echo [INFO] Virtual environment not found. Initializing .venv with Python 3.12+...
    py -3.12 -m venv .venv
    IF ERRORLEVEL 1 (
        echo [ERROR] Python 3.12+ launcher failed. Trying default python...
        python -m venv .venv
    )
    echo [INFO] Installing required dependencies...
    .venv\Scripts\python -m pip install --upgrade pip
    .venv\Scripts\python -m pip install -r requirements.txt
)

echo [INFO] Launching SmartShield Dashboard on http://127.0.0.1:8501...
.venv\Scripts\python run_app.py
pause
