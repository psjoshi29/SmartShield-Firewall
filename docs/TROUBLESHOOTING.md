# SmartShield: Troubleshooting & Diagnostics Guide

This guide provides troubleshooting solutions for common issues encountered during setup, test execution, and dashboard operation on Windows 10/11.

---

## 1. PowerShell Script Execution Policy Restriction

### Symptom:
When running `.\scripts\run_smartshield.ps1` or activating `.venv\Scripts\Activate.ps1`, PowerShell outputs:
```
File ... cannot be loaded because running scripts is disabled on this system.
```

### Root Cause:
Windows PowerShell restricts arbitrary script execution by default (`Restricted` policy).

### Resolution:
Run this command in your active PowerShell window (affects only the current session, requiring no admin privileges):
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
Then rerun:
```powershell
.\scripts\run_smartshield.ps1
```

Alternatively, use the batch launcher:
```cmd
.\scripts\run_smartshield.bat
```

---

## 2. Port 8501 Already in Use

### Symptom:
Streamlit fails to bind to port `8501` or opens a different port like `8502`.

### Root Cause:
Another application or prior Streamlit instance is still occupying port 8501.

### Resolution:
Specify an alternative port when launching:
```powershell
.\.venv\Scripts\streamlit run smartshield/gui/app.py --server.port 8505
```
Or terminate the lingering process on port 8501 via PowerShell:
```powershell
Stop-Process -Id (Get-NetTCPConnection -LocalPort 8501).OwningProcess -Force
```

---

## 3. Python 3.12+ Launcher (`py`) Not Found

### Symptom:
`py: command not found` or `The term 'py' is not recognized`.

### Resolution:
Use standard Python directly:
```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
```

---

## 4. Resetting a Corrupted Database or Configuration

### Symptom:
Errors loading `data/rules.json` or `data/events.db`.

### Resolution:
SmartShield automatically falls back to default seed rules if `rules.json` is missing or corrupted. To perform a clean reset:
1. Delete the corrupted files:
   ```powershell
   Remove-Item data\rules.json -ErrorAction SilentlyContinue
   Remove-Item data\events.db* -ErrorAction SilentlyContinue
   ```
2. Relaunch the application (`python run_app.py`). SmartShield will automatically regenerate clean default rules from `data/default_rules.json` and initialize a fresh SQLite database.

---

## 5. Pytest Execution Diagnostics

### Symptom:
Running `pytest` yields command not found.

### Resolution:
Always run pytest through the virtual environment's Python executable:
```powershell
.\.venv\Scripts\python -m pytest -v
```

---

## 6. Safe Sandbox Notice
SmartShield is a software-defined simulator. If network traffic on your physical Wi-Fi or Ethernet card is not being blocked, this is by design: SmartShield does not alter your physical network adapters or Windows Defender Firewall without explicit administrative driver integration.
