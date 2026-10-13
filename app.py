"""SmartShield: Root Streamlit Dashboard Application Entry Point.

Run directly with:
    streamlit run app.py
"""

import sys
from pathlib import Path

# Add project root directory to Python path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from smartshield.gui.app import main

if __name__ == "__main__":
    main()
