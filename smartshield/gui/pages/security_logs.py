"""Security Logs audit page: Filtering, pagination, and safe CSV export."""

import pandas as pd
import streamlit as st

from smartshield.gui.state import get_db
from smartshield.gui.styles import render_simulated_banner


def render_security_logs_page() -> None:
    st.markdown(render_simulated_banner(), unsafe_allow_html=True)

    st.title("Security Audit Logs")
    st.caption("Immutable forensic record of evaluated network packets and rule decisions.")

    db = get_db()

    # Filter controls
    with st.expander("🔍 Search & Filter Controls", expanded=True):
        f1, f2, f3, f4 = st.columns(4)
        with f1:
            filter_action = st.selectbox("Action", options=["ALL", "ALLOW", "BLOCK"], index=0)
        with f2:
            filter_proto = st.selectbox("Protocol", options=["ALL", "TCP", "UDP", "ICMP"], index=0)
        with f3:
            filter_dir = st.selectbox("Direction", options=["ALL", "INBOUND", "OUTBOUND"], index=0)
        with f4:
            filter_port_str = st.text_input("Port (or blank)", "").strip()
            filter_port = int(filter_port_str) if filter_port_str.isdigit() else None

        search_text = st.text_input("Free-text Search (IP address, rule name, or reason)", "").strip()

    # Pagination controls
    page_size = 25
    total_matches = db.count_events(
        action=filter_action if filter_action != "ALL" else None,
        protocol=filter_proto if filter_proto != "ALL" else None,
        direction=filter_dir if filter_dir != "ALL" else None,
        port=filter_port,
        search=search_text if search_text else None,
    )

    col_meta, col_export = st.columns([3, 1])
    with col_meta:
        st.write(f"Showing matching events: **{total_matches:,}** records found.")
    with col_export:
        # Secure CSV Export Button
        csv_data = db.export_csv_string(
            action=filter_action if filter_action != "ALL" else None,
            protocol=filter_proto if filter_proto != "ALL" else None,
            direction=filter_dir if filter_dir != "ALL" else None,
            search=search_text if search_text else None,
        )
        st.download_button(
            label="📥 Export Safe CSV",
            data=csv_data,
            file_name="smartshield_security_audit.csv",
            mime="text/csv",
            help="Exports audit log with automated CSV formula injection neutralization.",
            use_container_width=True,
        )

    if total_matches == 0:
        st.info("No security logs match the current query criteria. Try adjusting the filter parameters.")
        return

    total_pages = max(1, (total_matches + page_size - 1) // page_size)
    page_num = st.number_input("Page Number", min_value=1, max_value=total_pages, value=1, step=1)
    offset = (page_num - 1) * page_size

    # Query matching records
    events = db.query_events(
        limit=page_size,
        offset=offset,
        action=filter_action if filter_action != "ALL" else None,
        protocol=filter_proto if filter_proto != "ALL" else None,
        direction=filter_dir if filter_dir != "ALL" else None,
        port=filter_port,
        search=search_text if search_text else None,
    )

    display_rows = []
    for ev in events:
        display_rows.append({
            "ID": ev["id"],
            "Timestamp": ev["timestamp"][:19].replace("T", " "),
            "Action": ev["action"],
            "Direction": ev["direction"],
            "Protocol": ev["protocol"],
            "Source": f"{ev['src_ip']}:{ev['src_port']}",
            "Destination": f"{ev['dst_ip']}:{ev['dst_port']}",
            "Matched Rule": ev["matched_rule_id"] or "DEFAULT",
            "Rule Name": ev["matched_rule_name"] or "Default Fallback",
            "Reason": ev["reason"],
        })

    st.dataframe(pd.DataFrame(display_rows), use_container_width=True, hide_index=True)
