"""Top-level runner script for SmartShield Firewall Dashboard."""

import subprocess
import sys
from pathlib import Path

if __name__ == "__main__":
    app_path = Path(__file__).resolve().parent / "smartshield" / "gui" / "app.py"
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app_path),
        "--server.headless=true",
        "--server.address=127.0.0.1",
        "--browser.gatherUsageStats=false",
    ]
    print("=" * 60)
    print("Starting SmartShield Cyber Firewall Simulator Dashboard...")
    print(f"Executing: {' '.join(cmd)}")
    print("=" * 60)
    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\nSmartShield stopped safely.")
