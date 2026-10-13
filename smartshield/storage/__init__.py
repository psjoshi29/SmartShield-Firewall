"""Storage module for SmartShield: Configuration persistence and SQLite event logging."""

from smartshield.storage.config import ConfigManager
from smartshield.storage.db import EventDatabase

__all__ = ["ConfigManager", "EventDatabase"]
