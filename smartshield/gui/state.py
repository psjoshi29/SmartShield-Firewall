"""Session state initialization and singleton resource management."""

from pathlib import Path
import streamlit as st

from smartshield.engine.ruleset import RuleSet
from smartshield.simulator.runner import SimulationRunner
from smartshield.storage.config import ConfigManager
from smartshield.storage.db import EventDatabase

WORKSPACE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = WORKSPACE_DIR / "data"
CONFIG_FILE = DATA_DIR / "rules.json"
DEFAULT_SEED_FILE = DATA_DIR / "default_rules.json"
DB_FILE = DATA_DIR / "events.db"


def init_app_state() -> None:
    """Initialize shared Streamlit session state and database resources."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if "config_manager" not in st.session_state:
        # If rules.json doesn't exist yet, seed from default_rules.json if present
        if not CONFIG_FILE.exists() and DEFAULT_SEED_FILE.exists():
            import shutil
            shutil.copyfile(DEFAULT_SEED_FILE, CONFIG_FILE)

        st.session_state.config_manager = ConfigManager(CONFIG_FILE)

    if "ruleset" not in st.session_state:
        st.session_state.ruleset = st.session_state.config_manager.load_ruleset()

    if "db" not in st.session_state:
        st.session_state.db = EventDatabase(DB_FILE)

    if "runner" not in st.session_state:
        st.session_state.runner = SimulationRunner(
            ruleset=st.session_state.ruleset,
            db=st.session_state.db,
        )
        # Seed baseline events if DB is empty
        if st.session_state.db.count_events() == 0:
            st.session_state.runner.seed_demo_traffic(total_records=75)


def get_ruleset() -> RuleSet:
    return st.session_state.ruleset


def get_db() -> EventDatabase:
    return st.session_state.db


def get_runner() -> SimulationRunner:
    return st.session_state.runner


def persist_ruleset() -> None:
    """Persist current ruleset state to disk."""
    st.session_state.config_manager.save_ruleset(st.session_state.ruleset)
    # Re-sync runner reference
    st.session_state.runner.ruleset = st.session_state.ruleset
