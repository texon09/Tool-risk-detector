"""Minimal ChatGPT/Gemini-style Streamlit chat UI for PlanGuard live demo.

Key aesthetics:
- Single clean centered column.
- Minimal light theme.
- Sidebar with PlanGuard URL, API key, and 'New chat' button.
- Subtle badge under assistant responses: ALLOW 0.03, CONFIRM 0.62, REVISE 0.45, BLOCK 0.99.
- Expandable rationale line and triggered rule IDs.
- 'View in PlanGuard' link to {FRONTEND_URL}/audit?id={audit_id}.
- Inline Approve / Deny buttons for CONFIRM requests.
"""

from __future__ import annotations

import os

import streamlit as st
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage

from chat_demo.agent import GuardedAgent
from chat_demo.guard_client import GuardClient

load_dotenv()

# Streamlit Page Config
st.set_page_config(
    page_title="PlanGuard Agent Chat",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="expanded",
)

# Custom minimal CSS for muted badges and clean UI
st.markdown(
    """
    <style>
    .guard-badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.78rem;
        font-family: monospace;
        font-weight: 600;
        margin-top: 6px;
        margin-bottom: 4px;
    }
    .badge-allow {
        background-color: #e6f4ea;
        color: #137333;
        border: 1px solid #ceead6;
    }
    .badge-confirm {
        background-color: #fef7e0;
        color: #b06000;
        border: 1px solid #feefc3;
    }
    .badge-revise {
        background-color: #feefe3;
        color: #c53929;
        border: 1px solid #fad2cf;
    }
    .badge-block {
        background-color: #fce8e6;
        color: #c5221f;
        border: 1px solid #f9dedc;
    }
    .badge-none {
        background-color: #f1f3f4;
        color: #5f6368;
    }
    .audit-link {
        font-size: 0.78rem;
        color: #1a73e8;
        text-decoration: none;
        margin-left: 10px;
    }
    .audit-link:hover {
        text-decoration: underline;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Sidebar Configuration
with st.sidebar:
    st.subheader("PlanGuard Settings")
    planguard_url = st.text_input(
        "PlanGuard URL",
        value=os.getenv("PLANGUARD_URL", "http://127.0.0.1:8000"),
        help="Backend FastAPI URL for PlanGuard analysis",
    )
    planguard_key = st.text_input(
        "PlanGuard API Key (Optional)",
        value=os.getenv("PLANGUARD_API_KEY", ""),
        type="password",
        help="Optional API key for registered user audit history",
    )
    google_key = st.text_input(
        "Google API Key",
        value=os.getenv("GOOGLE_API_KEY", ""),
        type="password",
        help="Gemini API Key from Google AI Studio",
    )
    frontend_url = st.text_input(
        "Dashboard URL",
        value=os.getenv("FRONTEND_URL", "http://localhost:3000"),
        help="Frontend Dashboard URL for audit log deep-links",
    )

    if st.button("New Chat", use_container_width=True):
        st.session_state.messages = []
        st.session_state.history = []
        st.session_state.pending_confirm = None
        st.rerun()

    st.markdown("---")
    st.caption("PlanGuard pre-execution risk scoring with Gemini 2.5 Flash.")

# Initialize session state
if "messages" not in st.session_state:
    st.session_state.messages = []
if "history" not in st.session_state:
    st.session_state.history = []
if "pending_confirm" not in st.session_state:
    st.session_state.pending_confirm = None


def render_guard_badge(action: str, score: float, audit_id: str, rationale: str, rule_hits: list[str]):
    """Render quiet muted badge and expandable details below assistant message."""
    if not action or action == "NONE":
        return

    css_class = f"badge-{action.lower()}"
    badge_html = f"<span class='guard-badge {css_class}'>{action} {score:.2f}</span>"
    if audit_id and audit_id != "fail-closed-client":
        link = f"{frontend_url.rstrip('/')}/audit?id={audit_id}"
        badge_html += f"<a class='audit-link' href='{link}' target='_blank'>View in PlanGuard ({audit_id[:8]}...)</a>"
    elif audit_id:
        badge_html += f"<span class='audit-link'>ID: {audit_id}</span>"

    st.markdown(badge_html, unsafe_allow_html=True)

    with st.expander("Security details", expanded=False):
        if rationale:
            st.markdown(f"**Rationale:** {rationale}")
        if rule_hits:
            st.markdown(f"**Triggered rules:** `{', '.join(rule_hits)}`")
        if audit_id:
            st.caption(f"Full audit ID: `{audit_id}`")


# Render chat history
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])
        if msg["role"] == "assistant" and "guard_info" in msg:
            g = msg["guard_info"]
            render_guard_badge(
                action=g.get("action", "NONE"),
                score=g.get("risk_score", 0.0),
                audit_id=g.get("audit_id", ""),
                rationale=g.get("rationale", ""),
                rule_hits=g.get("rule_hits", []),
            )

# Handle Pending Confirmation (Approve / Deny)
if st.session_state.pending_confirm:
    pending = st.session_state.pending_confirm
    st.warning("Action requires human approval before proceeding.")
    col1, col2 = st.columns([1, 1])
    with col1:
        if st.button("Approve", type="primary", use_container_width=True):
            guard_client = GuardClient(base_url=planguard_url, api_key=planguard_key)
            agent = GuardedAgent(guard_client=guard_client, api_key=google_key)
            with st.spinner("Executing approved actions..."):
                res = agent.resume_approved_plan(
                    history=st.session_state.history,
                    pending_tool_calls=pending["tool_calls"],
                )
                st.session_state.history = res["updated_history"]
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": res["reply"],
                    "guard_info": {
                        "action": "ALLOW",
                        "risk_score": 0.0,
                        "audit_id": pending["audit_id"],
                        "rationale": "Human approval granted.",
                        "rule_hits": [],
                    },
                })
                st.session_state.pending_confirm = None
                st.rerun()

    with col2:
        if st.button("Deny", use_container_width=True):
            st.session_state.messages.append({
                "role": "assistant",
                "content": "Execution was denied by the user. No tools were executed.",
                "guard_info": {
                    "action": "BLOCK",
                    "risk_score": pending.get("risk_score", 1.0),
                    "audit_id": pending.get("audit_id", ""),
                    "rationale": "User explicitly denied execution.",
                    "rule_hits": ["user_denied"],
                },
            })
            st.session_state.pending_confirm = None
            st.rerun()

# Handle new user input
prompt = st.chat_input("Ask agent with PlanGuard safety...")
if prompt:
    # Display user query
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Check for Google API key
    if not google_key:
        err_msg = "Please enter your Google API Key in the sidebar to run the agent."
        st.session_state.messages.append({"role": "assistant", "content": err_msg})
        with st.chat_message("assistant"):
            st.error(err_msg)
    else:
        # Run agent
        with st.chat_message("assistant"):
            with st.spinner("Analyzing plan with PlanGuard..."):
                guard_client = GuardClient(base_url=planguard_url, api_key=planguard_key)
                agent = GuardedAgent(guard_client=guard_client, api_key=google_key)

                # Add user query to agent history
                st.session_state.history.append(HumanMessage(content=prompt))

                turn_result = agent.run_turn(st.session_state.history)
                st.session_state.history = turn_result["updated_history"]

                reply_text = turn_result["reply"]
                st.markdown(reply_text)

                render_guard_badge(
                    action=turn_result["action"],
                    score=turn_result["risk_score"],
                    audit_id=turn_result["audit_id"],
                    rationale=turn_result["rationale"],
                    rule_hits=turn_result["rule_hits"],
                )

                st.session_state.messages.append({
                    "role": "assistant",
                    "content": reply_text,
                    "guard_info": {
                        "action": turn_result["action"],
                        "risk_score": turn_result["risk_score"],
                        "audit_id": turn_result["audit_id"],
                        "rationale": turn_result["rationale"],
                        "rule_hits": turn_result["rule_hits"],
                    },
                })

                if turn_result["action"] == "CONFIRM":
                    st.session_state.pending_confirm = {
                        "tool_calls": turn_result["pending_plan"],
                        "audit_id": turn_result["audit_id"],
                        "risk_score": turn_result["risk_score"],
                    }
                    st.rerun()
