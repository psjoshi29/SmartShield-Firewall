"""Settings & About page: Project architecture, data reset, and WFP roadmap."""

import streamlit as st

from smartshield.engine.models import Action
from smartshield.gui.state import get_db, get_ruleset, get_runner, persist_ruleset
from smartshield.gui.styles import render_simulated_banner


def render_settings_about_page() -> None:
    st.markdown(render_simulated_banner(), unsafe_allow_html=True)

    st.title("Settings & Technical Documentation")
    st.caption("Engine configuration, storage maintenance, and Windows security architecture reference.")

    ruleset = get_ruleset()
    db = get_db()
    runner = get_runner()

    tab_settings, tab_data, tab_arch, tab_guide = st.tabs([
        "⚙️ Engine Settings",
        "🗄️ Data Management",
        "🏗️ Windows Architecture & WFP",
        "📖 User Guide",
    ])

    with tab_settings:
        st.markdown("##### Firewall Engine Global Settings")
        cur_def = ruleset.default_action.value
        new_def = st.radio(
            "Default Fallback Action (When no rule matches)",
            options=["BLOCK", "ALLOW"],
            index=0 if cur_def == "BLOCK" else 1,
            help="Default-Deny (BLOCK) is standard cybersecurity best practice.",
        )
        if new_def != cur_def:
            ruleset.set_default_action(Action.from_str(new_def))
            persist_ruleset()
            st.success(f"Default action updated to {new_def}!")
            st.rerun()

        st.markdown("---")
        st.markdown(
            """
            - **Rule Matching Model:** Deterministic First-Match Priority Chain.
            - **Subnet Engine:** Standard-library IPv4 CIDR matching via `ipaddress.IPv4Network`.
            - **Port Engine:** Discrete and range boundaries (1 - 65535).
            - **Storage Engine:** Atomic JSON writer (`os.replace`) & SQLite WAL database.
            """
        )

    with tab_data:
        st.markdown("##### Storage & Demonstration Maintenance")
        total_evts = db.count_events()
        st.write(f"Current logged events in database: **{total_evts:,}**")

        c_d1, c_d2 = st.columns(2)
        with c_d1:
            st.markdown("###### Seed Demo Traffic")
            st.caption("Generate a baseline set of realistic web, SSH, and port scan events.")
            if st.button("🌱 Seed Baseline Traffic (60 records)"):
                count = runner.seed_demo_traffic(total_records=60)
                st.success(f"Generated {count} baseline demo records!")
                st.rerun()

        with c_d2:
            st.markdown("###### Reset Event Database")
            st.caption("Permanently clear all logged events from the SQLite audit table.")
            confirm_clear = st.checkbox("Confirm database reset")
            if st.button("🗑️ Reset Database", type="secondary"):
                if confirm_clear:
                    db.reset_database()
                    st.success("Database table cleared successfully!")
                    st.rerun()
                else:
                    st.warning("Please check the confirmation box.")

    with tab_arch:
        st.markdown("##### Windows Network Integration & Limitations")
        st.markdown(
            """
            > [!IMPORTANT]
            > **Architectural Boundary Disclaimer:** SmartShield is developed as an educational packet simulator and pure firewall decision engine. It runs in user-space and **does not** hook live Windows network interfaces or modify the built-in Windows Defender Firewall without administrative consent.

            ### Live Packet Filtering Approaches on Windows 10/11
            1. **Windows Filtering Platform (WFP):**
               - The official kernel-mode packet filtering API built into Windows.
               - Requires building a Kernel-Mode Driver Framework (KMDF) driver signed with an Extended Validation (EV) code-signing certificate.
               - Intercepts packets at the Network, Transport, and Application layers via `FwpsCalloutRegister`.
            2. **WinDivert (Windows Packet Divert):**
               - A user-mode packet interception library running on top of a signed kernel driver (`WinDivert.sys`).
               - Captures network packets matching a filter string, allows user-space inspection/modification, and reinjects or drops them.
            3. **NDIS Lightweight Filters (LWF):**
               - Intercepts traffic directly between protocol drivers and physical network adapters.
            
            ### SmartShield Scope & Safety
            By isolating the firewall decision engine into a modular architecture, SmartShield delivers full production-grade rule evaluation, CIDR subnet matching, and audit logging without kernel instability or disruption of host Windows network connectivity.
            """
        )

    with tab_guide:
        st.markdown("##### Built-in Operator Guide")
        st.markdown(
            """
            ### Step-by-Step System Walkthrough
            1. **Traffic Simulator:** Navigate to `Traffic Simulator`, pick *External Port Scan & Reconnaissance*, and click `Generate & Evaluate Packets`. Notice how ports 23, 445, and 3389 are blocked by high-priority defensive rules.
            2. **Overview:** Return to `Overview` to see live KPI metrics update instantly.
            3. **Rule Management:** In `Firewall Rules`, experiment with adding a custom rule (e.g. Block Port 8080) and test it in `Packet Inspector`.
            4. **Packet Inspector:** Craft synthetic packets and observe the step-by-step trace showing which conditions passed and which rule fired.
            5. **Forensic Audit:** In `Security Logs`, filter by *BLOCK* and click `Export Safe CSV` to download a formula-injection-safe audit report.
            """
        )
