"""Packet Inspector page: Interactive manual packet crafting and trace visualization."""

import pandas as pd
import streamlit as st

from smartshield.engine.models import Direction, Packet, Protocol
from smartshield.engine.validator import PacketValidationError, validate_packet
from smartshield.gui.state import get_runner
from smartshield.gui.styles import render_simulated_banner


def render_packet_inspector_page() -> None:
    st.markdown(render_simulated_banner(), unsafe_allow_html=True)

    st.title("Interactive Packet Inspector")
    st.caption("Craft a custom synthetic IP packet and trace its step-by-step evaluation through each firewall rule.")

    runner = get_runner()

    # Packet Crafting Form
    with st.form("packet_craft_form"):
        st.markdown("##### 🧪 Packet Header Specification")
        p1, p2, p3 = st.columns(3)
        with p1:
            src_ip = st.text_input("Source IPv4 Address", value="192.168.1.50")
            dst_ip = st.text_input("Destination IPv4 Address", value="142.250.190.46")
        with p2:
            src_port = st.number_input("Source Port (1-65535)", min_value=1, max_value=65535, value=52140)
            dst_port = st.number_input("Destination Port (1-65535)", min_value=1, max_value=65535, value=443)
        with p3:
            proto = st.selectbox("Transport Protocol", options=["TCP", "UDP", "ICMP"])
            direction = st.selectbox("Flow Direction", options=["OUTBOUND", "INBOUND"])
            flags = st.text_input("TCP Flags (e.g. SYN, ACK)", value="SYN")

        log_decision = st.checkbox("Log evaluated packet to Security Audit database", value=True)
        inspect_btn = st.form_submit_button("🔍 Inspect & Trace Packet Evaluation", type="primary")

    if inspect_btn:
        raw_pkt_dict = {
            "src_ip": src_ip.strip(),
            "dst_ip": dst_ip.strip(),
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "protocol": proto,
            "direction": direction,
            "flags": flags.strip(),
            "payload_size": 64,
            "is_simulated": True,
            "description": "Manual Packet Inspection Test",
        }

        try:
            validated_pkt = validate_packet(raw_pkt_dict)
            decision = runner.inspect_packet(validated_pkt, log_to_db=log_decision)

            # Glowing Decision Hero Card
            if decision.action.value == "ALLOW":
                card_html = f"""
                <div class="decision-card-allow">
                    <div class="decision-title-allow">ACTION: ALLOW</div>
                    <div style="font-size: 1.1rem; color: #f0f6fc; margin-bottom: 6px;"><strong>{decision.rule_name}</strong> ({decision.rule_id or 'DEFAULT'})</div>
                    <div style="font-size: 0.95rem; color: #8b949e;">{decision.reason}</div>
                </div>
                """
            else:
                card_html = f"""
                <div class="decision-card-block">
                    <div class="decision-title-block">ACTION: BLOCK</div>
                    <div style="font-size: 1.1rem; color: #f0f6fc; margin-bottom: 6px;"><strong>{decision.rule_name}</strong> ({decision.rule_id or 'DEFAULT'})</div>
                    <div style="font-size: 0.95rem; color: #8b949e;">{decision.reason}</div>
                </div>
                """
            st.markdown(card_html, unsafe_allow_html=True)

            # Step-by-step Rule Trace
            st.subheader("Step-by-Step Rule Evaluation Trace")
            st.caption("Shows each active rule checked in strict priority order, identifying condition matches or mismatches.")

            trace_rows = []
            for step in decision.steps:
                trace_rows.append({
                    "Priority": step.priority,
                    "Rule ID": step.rule_id,
                    "Rule Name": step.rule_name,
                    "Matched": "🎯 YES" if step.matched else "❌ NO",
                    "Src IP": "✅" if step.src_ip_match else "❌",
                    "Dst IP": "✅" if step.dst_ip_match else "❌",
                    "Src Port": "✅" if step.src_port_match else "❌",
                    "Dst Port": "✅" if step.dst_port_match else "❌",
                    "Proto": "✅" if step.proto_match else "❌",
                    "Dir": "✅" if step.dir_match else "❌",
                    "Evaluation Result": step.explanation,
                })

            if trace_rows:
                st.dataframe(pd.DataFrame(trace_rows), use_container_width=True, hide_index=True)
            else:
                st.info("No rule evaluation steps generated.")

        except PacketValidationError as val_err:
            st.error(f"⚠️ Packet Validation Failed: {val_err}")
    else:
        st.info("Configure packet header fields above and click 'Inspect & Trace Packet Evaluation'.")
