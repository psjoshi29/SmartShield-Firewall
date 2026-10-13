"""Firewall Rules management page: CRUD, validation, prioritization, and default policy."""

import pandas as pd
import streamlit as st

from smartshield.engine.models import Action, Direction, Protocol, Rule
from smartshield.engine.validator import RuleValidationError, validate_rule
from smartshield.gui.state import get_ruleset, persist_ruleset
from smartshield.gui.styles import render_simulated_banner


def render_firewall_rules_page() -> None:
    st.markdown(render_simulated_banner(), unsafe_allow_html=True)

    st.title("Firewall Security Policies")
    st.caption("Configure deterministic rule priority, subnet/CIDR filters, port ranges, and default policy.")

    ruleset = get_ruleset()

    # Default Policy Switcher Card
    with st.expander("⚙️ Fallback Default Policy", expanded=False):
        col_pol1, col_pol2 = st.columns([2, 1])
        with col_pol1:
            st.markdown(
                "When an inspected packet matches none of the active firewall rules below, the firewall applies this default fallback disposition."
            )
        with col_pol2:
            current_default = ruleset.default_action.value
            new_default = st.selectbox(
                "Default Fallback Action",
                options=["BLOCK", "ALLOW"],
                index=0 if current_default == "BLOCK" else 1,
                help="College demo profile defaults to strict BLOCK (Default-Deny).",
            )
            if new_default != current_default:
                ruleset.set_default_action(Action.from_str(new_default))
                persist_ruleset()
                st.success(f"Default fallback policy updated to {new_default}!")
                st.rerun()

    # Rule Search & Filter
    search_query = st.text_input("🔍 Search Rules (by ID, Name, Description, IP, or Port)", "").strip().lower()

    # Rules Display Table
    filtered_rules = [
        r for r in ruleset.rules
        if not search_query or (
            search_query in r.id.lower()
            or search_query in r.name.lower()
            or search_query in r.description.lower()
            or search_query in r.src_ip.lower()
            or search_query in r.dst_ip.lower()
            or search_query in r.dst_ports.lower()
        )
    ]

    rule_rows = []
    for r in filtered_rules:
        rule_rows.append({
            "Priority": r.priority,
            "ID": r.id,
            "Enabled": "✅ YES" if r.enabled else "❌ NO",
            "Name": r.name,
            "Action": r.action.value,
            "Direction": r.direction.value,
            "Protocol": r.protocol.value,
            "Source IP": r.src_ip,
            "Dest IP": r.dst_ip,
            "Dest Ports": r.dst_ports,
        })

    st.subheader(f"Active Ruleset ({len(filtered_rules)} rules)")
    if rule_rows:
        st.dataframe(pd.DataFrame(rule_rows), use_container_width=True, hide_index=True)
    else:
        st.warning("No firewall rules matched your search query.")

    st.markdown("---")

    # Tabs for Add, Edit/Toggle, Reorder, Delete
    tab_add, tab_edit, tab_reorder, tab_delete = st.tabs(["➕ Add New Rule", "✏️ Edit / Toggle Rule", "🔃 Reorder Priority", "🗑️ Delete Rule"])

    # TAB: ADD RULE
    with tab_add:
        st.markdown("##### Create a New Security Policy")
        with st.form("add_rule_form"):
            c1, c2, c3 = st.columns(3)
            with c1:
                new_id = st.text_input("Rule ID (e.g. RULE-008)", value=f"RULE-00{len(ruleset.rules)+1}")
                new_name = st.text_input("Rule Name", placeholder="e.g. Block Port Scan")
            with c2:
                new_priority = st.number_input("Priority (1 = Highest, 1000 = Lowest)", min_value=1, max_value=1000, value=50, step=10)
                new_enabled = st.checkbox("Enabled Immediately", value=True)
            with c3:
                new_action = st.selectbox("Action", options=["BLOCK", "ALLOW"])
                new_direction = st.selectbox("Direction", options=["INBOUND", "OUTBOUND", "ANY"])

            c4, c5, c6 = st.columns(3)
            with c4:
                new_proto = st.selectbox("Protocol", options=["TCP", "UDP", "ICMP", "ANY"])
                new_src_ports = st.text_input("Source Ports (or * for any)", value="*")
            with c5:
                new_src_ip = st.text_input("Source IP / CIDR Subnet (or * for any)", value="*")
                new_dst_ports = st.text_input("Destination Ports (e.g. 80,443 or 80-443)", value="80")
            with c6:
                new_dst_ip = st.text_input("Destination IP / CIDR Subnet (or * for any)", value="*")
                new_desc = st.text_input("Rule Description", placeholder="e.g. Policy rationale")

            submit_add = st.form_submit_button("Add Rule to Engine", type="primary")

            if submit_add:
                rule_dict = {
                    "id": new_id,
                    "name": new_name,
                    "description": new_desc,
                    "priority": int(new_priority),
                    "enabled": new_enabled,
                    "src_ip": new_src_ip,
                    "dst_ip": new_dst_ip,
                    "src_ports": new_src_ports,
                    "dst_ports": new_dst_ports,
                    "protocol": new_proto,
                    "direction": new_direction,
                    "action": new_action,
                }
                try:
                    rule_obj = validate_rule(rule_dict)
                    ruleset.add_rule(rule_obj)
                    persist_ruleset()
                    st.success(f"Rule [{new_id}] '{new_name}' successfully added and persisted!")
                    st.rerun()
                except (RuleValidationError, ValueError) as err:
                    st.error(f"Rule Validation Error: {err}")

    # TAB: EDIT / TOGGLE RULE
    with tab_edit:
        st.markdown("##### Edit or Toggle Rule Status")
        rule_options = [f"[{r.id}] {r.name} (Priority {r.priority})" for r in ruleset.rules]
        if rule_options:
            selected_edit_str = st.selectbox("Select Rule to Edit", rule_options)
            selected_rule_id = selected_edit_str.split("]")[0].replace("[", "")
            target_rule = ruleset.get_rule(selected_rule_id)

            if target_rule:
                with st.form("edit_rule_form"):
                    e1, e2 = st.columns(2)
                    with e1:
                        edit_name = st.text_input("Rule Name", value=target_rule.name)
                        edit_desc = st.text_input("Description", value=target_rule.description)
                        edit_priority = st.number_input("Priority", min_value=1, max_value=1000, value=target_rule.priority)
                        edit_enabled = st.checkbox("Rule Enabled", value=target_rule.enabled)
                    with e2:
                        edit_action = st.selectbox("Action", ["BLOCK", "ALLOW"], index=0 if target_rule.action.value == "BLOCK" else 1)
                        edit_dir = st.selectbox("Direction", ["INBOUND", "OUTBOUND", "ANY"], index=["INBOUND", "OUTBOUND", "ANY"].index(target_rule.direction.value))
                        edit_proto = st.selectbox("Protocol", ["TCP", "UDP", "ICMP", "ANY"], index=["TCP", "UDP", "ICMP", "ANY"].index(target_rule.protocol.value))
                        edit_dst_ports = st.text_input("Destination Ports", value=target_rule.dst_ports)

                    submit_edit = st.form_submit_button("Save Changes", type="primary")
                    if submit_edit:
                        updated_dict = {
                            "id": target_rule.id,
                            "name": edit_name,
                            "description": edit_desc,
                            "priority": int(edit_priority),
                            "enabled": edit_enabled,
                            "src_ip": target_rule.src_ip,
                            "dst_ip": target_rule.dst_ip,
                            "src_ports": target_rule.src_ports,
                            "dst_ports": edit_dst_ports,
                            "protocol": edit_proto,
                            "direction": edit_dir,
                            "action": edit_action,
                        }
                        try:
                            updated_obj = validate_rule(updated_dict)
                            ruleset.update_rule(target_rule.id, updated_obj)
                            persist_ruleset()
                            st.success(f"Rule [{target_rule.id}] successfully updated!")
                            st.rerun()
                        except (RuleValidationError, ValueError) as err:
                            st.error(f"Validation Error: {err}")
        else:
            st.info("No rules to edit.")

    # TAB: REORDER PRIORITY
    with tab_reorder:
        st.markdown("##### Prioritize Rules")
        st.markdown("Move higher priority rules to the top of the evaluation chain.")
        rule_ids = [r.id for r in ruleset.rules]
        if rule_ids:
            reordered = st.multiselect("Reorder evaluation list (select in desired order)", options=rule_ids, default=rule_ids)
            if st.button("Apply New Order"):
                if len(reordered) == len(rule_ids):
                    ruleset.reorder_rules(reordered)
                    persist_ruleset()
                    st.success("Rule priorities successfully re-indexed!")
                    st.rerun()
                else:
                    st.error("Please include all rules in the reordered list.")

    # TAB: DELETE RULE
    with tab_delete:
        st.markdown("##### Remove Rule from Engine")
        rule_del_options = [f"[{r.id}] {r.name}" for r in ruleset.rules]
        if rule_del_options:
            selected_del = st.selectbox("Select Rule to Delete", rule_del_options)
            del_id = selected_del.split("]")[0].replace("[", "")

            confirm_del = st.checkbox(f"I confirm permanent deletion of rule {del_id}")
            if st.button("🗑️ Permanently Delete Rule", type="secondary"):
                if confirm_del:
                    ruleset.delete_rule(del_id)
                    persist_ruleset()
                    st.success(f"Rule {del_id} successfully deleted!")
                    st.rerun()
                else:
                    st.warning("Please tick the confirmation checkbox to delete.")
        else:
            st.info("No rules available to delete.")
