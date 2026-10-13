"""Overview page: Executive cybersecurity dashboard and real-time posture."""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from smartshield.analytics.analyzer import (
    compute_kpis,
    get_direction_df,
    get_protocol_df,
    get_timeline_df,
)
from smartshield.gui.state import get_db, get_ruleset
from smartshield.gui.styles import render_kpi_card, render_simulated_banner


def render_overview_page() -> None:
    st.markdown(render_simulated_banner(), unsafe_allow_html=True)

    db = get_db()
    ruleset = get_ruleset()
    kpis = compute_kpis(db)

    # Header section
    col_head1, col_head2 = st.columns([3, 1])
    with col_head1:
        st.title("System Overview & Telemetry")
        st.caption("Active monitoring of synthetic network ingress and egress evaluation.")
    with col_head2:
        st.markdown(
            f"""
            <div style="text-align: right; padding-top: 10px;">
                <span class="badge-neutral">Default Policy: <strong>{ruleset.default_action.value}</strong></span>
                <br><span style="font-size: 0.8rem; color: #8b949e;">Active Rules: {len(ruleset.get_active_rules())}/{len(ruleset.rules)}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # 4 Metric Cards
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            render_kpi_card("Total Processed", f"{kpis['total']:,}", "Synthetic packet audits", "kpi-cyan"),
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            render_kpi_card("Allowed Traffic", f"{kpis['allowed']:,}", "Permitted egress / authorized ingress", "kpi-allow"),
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            render_kpi_card("Blocked Packets", f"{kpis['blocked']:,}", "Threat probes & policy violations", "kpi-block"),
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            render_kpi_card("Block Rate", f"{kpis['block_rate']}%", "Defensive drop ratio", "kpi-cyan"),
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # Traffic Trend over Time Chart
    st.subheader("Traffic Disposition Over Time")
    timeline_df = get_timeline_df(db)

    if not timeline_df.empty:
        fig_trend = px.bar(
            timeline_df,
            x="Hour",
            y="Count",
            color="Action",
            color_discrete_map={"ALLOW": "#00e676", "BLOCK": "#ff1744"},
            barmode="group",
            template="plotly_dark",
            height=320,
        )
        fig_trend.update_layout(
            paper_bgcolor="#111726",
            plot_bgcolor="#111726",
            margin=dict(l=20, r=20, t=20, b=20),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            xaxis=dict(gridcolor="#1f293d"),
            yaxis=dict(gridcolor="#1f293d"),
        )
        st.plotly_chart(fig_trend, use_container_width=True)
    else:
        st.info("No timeline data recorded yet. Run a simulation from the Traffic Simulator page.")

    # Two column charts: Protocol & Direction
    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.subheader("Transport Protocols")
        proto_df = get_protocol_df(db)
        if not proto_df.empty:
            fig_proto = px.pie(
                proto_df,
                names="Protocol",
                values="Count",
                hole=0.55,
                color="Protocol",
                color_discrete_map={"TCP": "#00d2ff", "UDP": "#3a7bd5", "ICMP": "#f59e0b", "ANY": "#8b949e"},
                template="plotly_dark",
                height=260,
            )
            fig_proto.update_layout(
                paper_bgcolor="#111726",
                plot_bgcolor="#111726",
                margin=dict(l=10, r=10, t=10, b=10),
            )
            st.plotly_chart(fig_proto, use_container_width=True)
        else:
            st.info("No protocol events recorded.")

    with col_chart2:
        st.subheader("Direction Distribution")
        dir_df = get_direction_df(db)
        if not dir_df.empty:
            fig_dir = px.bar(
                dir_df,
                x="Direction",
                y="Count",
                color="Direction",
                color_discrete_map={"INBOUND": "#ec4899", "OUTBOUND": "#3b82f6"},
                template="plotly_dark",
                height=260,
            )
            fig_dir.update_layout(
                paper_bgcolor="#111726",
                plot_bgcolor="#111726",
                margin=dict(l=10, r=10, t=10, b=10),
                showlegend=False,
                xaxis=dict(gridcolor="#1f293d"),
                yaxis=dict(gridcolor="#1f293d"),
            )
            st.plotly_chart(fig_dir, use_container_width=True)
        else:
            st.info("No directional events recorded.")

    # Recent Audit Log Activity
    st.subheader("Recent Firewall Decisions")
    recent_events = db.query_events(limit=8)
    if recent_events:
        table_rows = []
        for ev in recent_events:
            table_rows.append({
                "Timestamp": ev["timestamp"][:19].replace("T", " "),
                "Direction": ev["direction"],
                "Source": f"{ev['src_ip']}:{ev['src_port']}",
                "Destination": f"{ev['dst_ip']}:{ev['dst_port']}",
                "Protocol": ev["protocol"],
                "Action": ev["action"],
                "Matched Rule": ev["matched_rule_id"] or "DEFAULT",
                "Reason": ev["reason"],
            })
        st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No recent events to display.")
