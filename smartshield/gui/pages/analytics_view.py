"""Analytics page: Threat intelligence profiling and traffic distribution charts."""

import pandas as pd
import plotly.express as px
import streamlit as st

from smartshield.analytics.analyzer import (
    compute_kpis,
    get_direction_df,
    get_protocol_df,
    get_timeline_df,
    get_top_blocked_ports_df,
)
from smartshield.gui.state import get_db
from smartshield.gui.styles import render_kpi_card, render_simulated_banner


def render_analytics_page() -> None:
    st.markdown(render_simulated_banner(), unsafe_allow_html=True)

    st.title("Security Analytics & Threat Profiling")
    st.caption("Deep-dive telemetry into policy enforcement, targeted ports, and attack surface probes.")

    db = get_db()
    kpis = compute_kpis(db)

    # Top summary metrics
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(render_kpi_card("Allowed Egress/Ingress", f"{kpis['allowed']:,}", "Permitted packets", "kpi-allow"), unsafe_allow_html=True)
    with c2:
        st.markdown(render_kpi_card("Blocked Policy Drops", f"{kpis['blocked']:,}", "Dropped packets", "kpi-block"), unsafe_allow_html=True)
    with c3:
        st.markdown(render_kpi_card("Total Examined", f"{kpis['total']:,}", "Audited synthetic packets", "kpi-cyan"), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Frequently Blocked Destination Ports Chart
    st.subheader("Frequently Blocked Ports (Target Surface)")
    ports_df = get_top_blocked_ports_df(db)

    if not ports_df.empty:
        fig_ports = px.bar(
            ports_df,
            x="Port",
            y="Blocked Packets",
            text="Blocked Packets",
            color="Blocked Packets",
            color_continuous_scale="Reds",
            template="plotly_dark",
            height=320,
        )
        fig_ports.update_layout(
            paper_bgcolor="#111726",
            plot_bgcolor="#111726",
            margin=dict(l=20, r=20, t=20, b=20),
            xaxis=dict(gridcolor="#1f293d", title="Target Port"),
            yaxis=dict(gridcolor="#1f293d", title="Dropped Packet Count"),
        )
        st.plotly_chart(fig_ports, use_container_width=True)
        st.caption("Common targets include: Port 23 (Telnet), Port 445 (SMB), Port 3389 (RDP), Port 21 (FTP).")
    else:
        st.info("No blocked packets recorded yet.")

    # Two column charts: Protocol breakdown & Direction breakdown
    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("Transport Protocols Distribution")
        proto_df = get_protocol_df(db)
        if not proto_df.empty:
            fig_p = px.pie(
                proto_df,
                names="Protocol",
                values="Count",
                template="plotly_dark",
                color_discrete_sequence=["#00d2ff", "#3a7bd5", "#f59e0b", "#8b949e"],
                height=280,
            )
            fig_p.update_layout(paper_bgcolor="#111726", plot_bgcolor="#111726", margin=dict(l=10, r=10, t=10, b=10))
            st.plotly_chart(fig_p, use_container_width=True)
        else:
            st.info("No protocol data.")

    with col_b:
        st.subheader("Traffic Flow Direction")
        dir_df = get_direction_df(db)
        if not dir_df.empty:
            fig_d = px.bar(
                dir_df,
                x="Direction",
                y="Count",
                template="plotly_dark",
                color="Direction",
                color_discrete_map={"INBOUND": "#ec4899", "OUTBOUND": "#3b82f6"},
                height=280,
            )
            fig_d.update_layout(paper_bgcolor="#111726", plot_bgcolor="#111726", margin=dict(l=10, r=10, t=10, b=10), showlegend=False)
            st.plotly_chart(fig_d, use_container_width=True)
        else:
            st.info("No directional data.")

    # Timeline trend
    st.subheader("Chronological Event Trend")
    timeline_df = get_timeline_df(db)
    if not timeline_df.empty:
        fig_time = px.line(
            timeline_df,
            x="Hour",
            y="Count",
            color="Action",
            color_discrete_map={"ALLOW": "#00e676", "BLOCK": "#ff1744"},
            markers=True,
            template="plotly_dark",
            height=300,
        )
        fig_time.update_layout(
            paper_bgcolor="#111726",
            plot_bgcolor="#111726",
            margin=dict(l=20, r=20, t=20, b=20),
            xaxis=dict(gridcolor="#1f293d"),
            yaxis=dict(gridcolor="#1f293d"),
        )
        st.plotly_chart(fig_time, use_container_width=True)
    else:
        st.info("No timeline data recorded.")
