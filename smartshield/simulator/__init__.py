"""Synthetic packet simulation and scenario generation for SmartShield."""

from smartshield.simulator.scenarios import SCENARIO_CATALOG, ScenarioDef
from smartshield.simulator.generator import generate_scenario_packets
from smartshield.simulator.runner import SimulationRunner

__all__ = [
    "SCENARIO_CATALOG",
    "ScenarioDef",
    "generate_scenario_packets",
    "SimulationRunner",
]
