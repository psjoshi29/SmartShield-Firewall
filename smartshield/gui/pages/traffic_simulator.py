"""Traffic Simulator page: Synthetic scenario generation and live engine evaluation."""

import pandas as pd
import streamlit as st

from smartshield.gui.state import get_runner
from smartshield.gui.styles import render_simulated_banner
from smartshield.simulator.scenarios import SCENARIO_CATALOG


def render_traffic_simulator_page() -> None:
    st.markdown(render_simulated_banner(), unsafe_allow_html=True)

    st.title("Synthetic Traffic Simulator")
    st.caption("Generate deterministic synthetic packets and evaluate them through the live rule engine.")

    runner = get_runner()

    col_ctrl, col_info = st.columns([2, 1])

    with col_ctrl:
        scenario_keys = list(SCENARIO_CATALOG.keys())
        scenario_labels = [f"{SCENARIO_CATALOG[k].name} ({SCENARIO_CATALOG[k].category})" for k in scenario_keys]

        selected_label = st.selectbox(
            "Select Simulation Scenario",
            scenario_labels,
            index=0,
            help="Choose a pre-configured realistic traffic pattern to inject into the firewall engine.",
        )
        selected_key = scenario_keys[scenario_labels.index(selected_label)]
        scenario_def = SCENARIO_CATALOG[selected_key]

        packet_count = st.slider("Number of Packets to Synthesize", min_value=5, max_value=150, value=25, step=5)

        generate_btn = st.button("🚀 Generate & Evaluate Packets", type="primary", use_container_width=True)

    with col_info:
        st.markdown(
            f"""
            <div style="background-color: #111726; border: 1px solid #1f293d; border-radius: 8px; padding: 16px;">
                <div style="color: #00d2ff; font-weight: 600; font-size: 0.9rem; margin-bottom: 8px;">Scenario Profile</div>
                <div style="font-size: 0.85rem; color: #f0f6fc; margin-bottom: 6px;"><strong>Category:</strong> {scenario_def.category}</div>
                <div style="font-size: 0.85rem; color: #8b949e; margin-bottom: 10px;">{scenario_def.description}</div>
                <div style="color: #f59e0b; font-weight: 600; font-size: 0.85rem;">Expected Outcome:</div>
                <div style="font-size: 0.85rem; color: #cbd5e1;">{scenario_def.expected_outcome}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    if generate_btn:
        with st.spinner("Synthesizing and evaluating packets in memory..."):
            decisions = runner.run_scenario(scenario_key=selected_key, count=packet_count)

        allow_cnt = sum(1 for d in decisions if d.action.value == "ALLOW")
        block_cnt = sum(1 for d in decisions if d.action.value == "BLOCK")

        st.success(f"Successfully evaluated {len(decisions)} synthetic packets! Allowed: {allow_cnt} | Blocked: {block_cnt}")

        # Render Table
        rows = []
        for d in decisions:
            pkt = d.packet
            rows.append({
                "Action": d.action.value,
                "Proto": pkt.protocol.value if pkt else "ANY",
                "Direction": pkt.direction.value if pkt else "ANY",
                "Source IP": pkt.src_ip if pkt else "N/A",
                "Src Port": pkt.src_port if pkt else 0,
                "Dest IP": pkt.dst_ip if pkt else "N/A",
                "Dst Port": pkt.dst_port if pkt else 0,
                "Matched Rule": d.rule_id or "DEFAULT",
                "Decision Reason": d.reason,
            })

        df_display = pd.DataFrame(rows)
        st.dataframe(df_display, use_container_width=True, hide_index=True)
    else:
        st.info("Select a scenario and click 'Generate & Evaluate Packets' to run a live simulation.")
