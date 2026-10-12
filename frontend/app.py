"""Streamlit Web Dashboard for AI Agent Tool-Call Risk Detector."""

import json

import pandas as pd
import streamlit as st

from frontend.api_client import RiskDetectorAPIClient

st.set_page_config(
    page_title="AI Agent Risk Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

api_client = RiskDetectorAPIClient()

st.title("🛡️ AI Agent Tool-Call Risk Detector")
st.caption("Proxy Guardrail evaluating AI agent tool-call execution risk in real time.")

# Check Backend Health
health = api_client.health_check()
if health.get("status") == "ok":
    st.sidebar.success("● Backend API Online (v0.1.0)")
else:
    st.sidebar.error(f"▲ Backend Offline: {health.get('error', 'Unreachable')}")

tab_monitor, tab_metrics, tab_audit = st.tabs(["🚀 Live Monitor", "📊 Model Metrics", "🔗 Tamper-Evident Audit Chain"])

# ==============================================================================
# TAB 1: LIVE MONITOR
# ==============================================================================
with tab_monitor:
    st.subheader("Plan Security Inspection")

    scenarios = api_client.get_scenarios()
    scenario_names = ["(Custom Plan)"] + [s["name"] for s in scenarios]
    selected_scenario = st.selectbox("Load Preset Scenario:", scenario_names)

    default_plan = {
        "steps": [
            {
                "tool_name": "database_query",
                "arguments": {"query": "SELECT id, name FROM users WHERE id = 42 LIMIT 1"},
                "side_effect_class": "read",
                "destination": "internal",
                "data_sensitivity": "internal",
                "reversible": True,
                "estimated_cost": 0.05,
            }
        ]
    }

    if selected_scenario != "(Custom Plan)":
        matched = next((s for s in scenarios if s["name"] == selected_scenario), None)
        if matched:
            default_plan = matched["plan"]
            st.info(f"**Description**: {matched['description']} | **Expected Decision**: `{matched['expected_decision']}`")

    plan_text = st.text_area(
        "Tool-Call Plan (JSON):",
        value=json.dumps(default_plan, indent=2),
        height=250,
    )

    col_btn, _ = st.columns([1, 4])
    with col_btn:
        analyze_clicked = st.button("🔍 Analyze Plan", use_container_width=True, type="primary")

    if analyze_clicked:
        try:
            parsed_plan = json.loads(plan_text)
            with st.spinner("Evaluating deterministic rules and ensemble ML models..."):
                response = api_client.analyze_plan(parsed_plan)

            action = response.get("action", "BLOCK")
            risk_score = response.get("risk_score", 0.0)
            critical = response.get("critical_violations", 0)
            latency = response.get("latency_ms", 0.0)
            audit_id = response.get("audit_id", "")
            rationale = response.get("rationale", "")
            rule_hits = response.get("rule_hits", [])
            votes = response.get("model_votes", {})
            contributions = response.get("feature_contributions", {})

            st.divider()

            # Decision Banner
            banner_cols = st.columns([2, 1, 1, 1])
            with banner_cols[0]:
                if action == "ALLOW":
                    st.success("### Decision: ✅ **ALLOW**")
                elif action == "CONFIRM":
                    st.info("### Decision: 👤 **CONFIRM** (Human Approval Required)")
                elif action == "REVISE":
                    st.warning("### Decision: ⚠️ **REVISE** (Plan Revision Needed)")
                else:
                    st.error("### Decision: 🚫 **BLOCK** (Security Violation)")
            with banner_cols[1]:
                st.metric("Calibrated Risk Score", f"{risk_score:.2f}")
            with banner_cols[2]:
                st.metric("Critical Violations", critical)
            with banner_cols[3]:
                st.metric("Analysis Latency", f"{latency:.1f} ms")

            st.write(f"**Security Rationale**: {rationale}")
            st.caption(f"Audit Identifier: `{audit_id}`")

            # Detailed Panels
            col_left, col_right = st.columns(2)
            with col_left:
                st.write("#### 🛡️ Triggered Rule Scans")
                if rule_hits:
                    for hit in rule_hits:
                        st.markdown(f"- 🔴 **{hit}**")
                else:
                    st.write("No deterministic rule violations triggered.")

                st.write("#### 🗳️ Ensemble Model Votes")
                if votes:
                    df_votes = pd.DataFrame(
                        [
                            {"Model": "Random Forest", "High-Risk Prob": f"{votes.get('rf_prob', 0.0):.4f}"},
                            {"Model": "XGBoost", "High-Risk Prob": f"{votes.get('xgb_prob', 0.0):.4f}"},
                            {"Model": "Decision Tree", "High-Risk Prob": f"{votes.get('dt_prob', 0.0):.4f}"},
                            {"Model": "Isolation Forest", "Anomaly Flagged": "YES (Anomaly)" if votes.get("iso_flag") else "NO"},
                        ]
                    )
                    st.dataframe(df_votes, hide_index=True, use_container_width=True)
                else:
                    st.caption("Model vote breakdown not available.")

            with col_right:
                st.write("#### 🔬 Top Feature Risk Contributions")
                if contributions:
                    df_contrib = pd.DataFrame(
                        list(contributions.items()), columns=["Feature", "Contribution Weight"]
                    ).sort_values("Contribution Weight", ascending=False)
                    st.dataframe(df_contrib, hide_index=True, use_container_width=True)
                    st.bar_chart(df_contrib.set_index("Feature"))
                else:
                    st.caption("No positive feature risk contributions detected.")

        except json.JSONDecodeError as e:
            st.error(f"Invalid JSON format in plan editor: {e}")

# ==============================================================================
# TAB 2: METRICS
# ==============================================================================
with tab_metrics:
    st.subheader("Offline Model Evaluation Metrics")
    metrics_data = api_client.get_metrics()

    if metrics_data.get("available") and metrics_data.get("models"):
        models_dict = metrics_data["models"]
        rows = []
        for name, m in models_dict.items():
            rows.append({
                "Model": name.replace("_", " ").title(),
                "F1 Score": m["f1"],
                "Precision": m["precision"],
                "Recall": m["recall"],
                "AUROC": m["auroc"],
                "Latency (ms)": m["latency_ms"],
            })
        df_metrics = pd.DataFrame(rows)
        st.dataframe(df_metrics, hide_index=True, use_container_width=True)

        st.write("#### Performance Comparison")
        chart_data = df_metrics.set_index("Model")[["F1 Score", "Precision", "Recall", "AUROC"]]
        st.bar_chart(chart_data)
    else:
        st.info("Metrics report currently unavailable. Run `python -m backend.training.evaluate` to generate metrics.")

# ==============================================================================
# TAB 3: AUDIT CHAIN
# ==============================================================================
with tab_audit:
    st.subheader("Tamper-Evident SHA-256 Audit Log Chain")

    col_verify, col_refresh = st.columns([1, 4])
    with col_verify:
        if st.button("🔐 Verify Hash Chain", type="secondary"):
            v_res = api_client.verify_audit_chain()
            if v_res.get("valid"):
                st.success("✅ **Hash Chain Intact**: All cryptographic link hashes are valid.")
            else:
                st.error(f"❌ **Chain Tampered / Broken**: {v_res.get('reason')} at ID: {v_res.get('broken_at_id')}")

    logs = api_client.get_audit_logs(limit=30)
    if isinstance(logs, dict):
        logs = logs.get("logs", [])
    if logs and isinstance(logs, list):
        st.write(f"Showing most recent **{len(logs)}** decision records:")
        log_rows = []
        for r in logs:
            if isinstance(r, dict):
                log_rows.append({
                    "Timestamp (UTC)": r.get("timestamp"),
                    "Decision": r.get("decision"),
                    "Trajectory ID": r.get("trajectory_id"),
                    "Rationale": r.get("rationale"),
                    "Current Hash": str(r.get("current_hash", ""))[:16] + "...",
                    "Prev Hash": str(r.get("prev_hash", ""))[:16] + "...",
                })
        if log_rows:
            st.dataframe(pd.DataFrame(log_rows), hide_index=True, use_container_width=True)
        else:
            st.info("No decisions logged in audit chain yet.")
    else:
        st.info("No decisions logged in audit chain yet.")
