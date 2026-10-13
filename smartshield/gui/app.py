"""SmartShield Main Streamlit Application Entrypoint."""

import sys
from pathlib import Path
import streamlit as st

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from smartshield.gui.pages.analytics_view import render_analytics_page
from smartshield.gui.pages.firewall_rules import render_firewall_rules_page
from smartshield.gui.pages.overview import render_overview_page
from smartshield.gui.pages.packet_inspector import render_packet_inspector_page
from smartshield.gui.pages.security_logs import render_security_logs_page
from smartshield.gui.pages.settings_about import render_settings_about_page
from smartshield.gui.pages.traffic_simulator import render_traffic_simulator_page
from smartshield.gui.state import get_db, get_ruleset, init_app_state
from smartshield.gui.styles import CYBER_DARK_CSS


def main() -> None:
    st.set_page_config(
        page_title="SmartShield | Cyber Firewall Simulator",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Inject dark cybersecurity stylesheet
    st.markdown(CYBER_DARK_CSS, unsafe_allow_html=True)

    # Initialize session state & resources
    init_app_state()

    ruleset = get_ruleset()
    db = get_db()

    # Sidebar Navigation & Status
    with st.sidebar:
        st.markdown(
            """
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
                <span style="font-size: 2.2rem;">🛡️</span>
                <div>
                    <div style="font-size: 1.3rem; font-weight: 800; color: #00d2ff; letter-spacing: 0.05em;">SMARTSHIELD</div>
                    <div style="font-size: 0.75rem; color: #8b949e; letter-spacing: 0.05em;">NEXT-GEN FIREWALL SIMULATOR</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("<hr style='border-color: #1f293d; margin: 10px 0;'>", unsafe_allow_html=True)

        pages = {
            "📊 Overview": render_overview_page,
            "🚀 Traffic Simulator": render_traffic_simulator_page,
            "🛡️ Firewall Rules": render_firewall_rules_page,
            "📋 Security Logs": render_security_logs_page,
            "📈 Analytics": render_analytics_page,
            "🔍 Packet Inspector": render_packet_inspector_page,
            "⚙️ Settings & About": render_settings_about_page,
        }

        selected_page = st.radio(
            "Navigation",
            options=list(pages.keys()),
            index=0,
            label_visibility="collapsed",
        )

        st.markdown("<hr style='border-color: #1f293d; margin: 20px 0 15px 0;'>", unsafe_allow_html=True)

        # Telemetry Quick-Look
        st.markdown(
            f"""
            <div style="background-color: #111726; border: 1px solid #1f293d; border-radius: 8px; padding: 12px; font-size: 0.82rem;">
                <div style="color: #8b949e; font-weight: 600; margin-bottom: 6px;">FIREWALL ENGINE STATUS</div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                    <span style="color: #cbd5e1;">Engine Mode:</span>
                    <span style="color: #00e676; font-weight: 600;">ACTIVE (Sim)</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                    <span style="color: #cbd5e1;">Default Policy:</span>
                    <span style="color: {'#ff1744' if ruleset.default_action.value == 'BLOCK' else '#00e676'}; font-weight: 600;">{ruleset.default_action.value}</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                    <span style="color: #cbd5e1;">Active Policies:</span>
                    <span style="color: #00d2ff; font-weight: 600;">{len(ruleset.get_active_rules())}</span>
                </div>
                <div style="display: flex; justify-content: space-between;">
                    <span style="color: #cbd5e1;">Logged Events:</span>
                    <span style="color: #e6edf3; font-weight: 600;">{db.count_events():,}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            """
            <div style="margin-top: 20px; text-align: center; font-size: 0.72rem; color: #64748b;">
                SmartShield v1.0.0 &bull; Windows 10/11 Architecture
                <br>User-Space Sandbox Simulation
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Render selected page
    render_func = pages[selected_page]
    render_func()


if __name__ == "__main__":
    main()
