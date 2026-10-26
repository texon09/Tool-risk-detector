"""Minimal ChatGPT-style Streamlit chat UI for PlanGuard live demo.

Decisions:
  ALLOW  → LLM answer + small green badge. No buttons.
  BLOCK  → Short refusal + small red badge. No buttons.
  CONFIRM → Inline card with step list, rationale, [Approve] [Deny] buttons.
  REVISE  → Inline card with step list, rationale, [Ask to revise] [Cancel] buttons.

All card text is built deterministically from plan data (no extra LLM calls).
The LLM is cached via st.cache_resource to avoid re-initialising on every rerun.
"""

from __future__ import annotations

import os
import time
from typing import Any

import streamlit as st
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage

from chat_demo.agent import GuardedAgent, build_step_list
from chat_demo.guard_client import GuardClient

load_dotenv()

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="PlanGuard Agent Chat",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------
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
        margin-top: 4px;
        margin-bottom: 2px;
    }
    .badge-allow  { background:#e6f4ea; color:#137333; border:1px solid #ceead6; }
    .badge-confirm{ background:#fef7e0; color:#b06000; border:1px solid #feefc3; }
    .badge-revise { background:#feefe3; color:#c53929; border:1px solid #fad2cf; }
    .badge-block  { background:#fce8e6; color:#c5221f; border:1px solid #f9dedc; }
    .badge-none   { background:#f1f3f4; color:#5f6368; }
    .audit-link {
        font-size: 0.78rem; color:#1a73e8;
        text-decoration:none; margin-left:10px;
    }
    .audit-link:hover { text-decoration:underline; }
    .decision-card {
        border:1px solid #e0e0e0; border-radius:8px;
        padding:14px 18px; margin-top:10px; background:#fafafa;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.subheader("PlanGuard Settings")
    planguard_url = st.text_input(
        "PlanGuard URL",
        value=os.getenv("PLANGUARD_URL", "http://127.0.0.1:8000"),
        help="Backend FastAPI URL",
    )
    planguard_key = st.text_input(
        "PlanGuard API Key (Optional)",
        value=os.getenv("PLANGUARD_API_KEY", ""),
        type="password",
        help="Optional API key for per-user audit history",
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
        help="Frontend URL for audit deep-links",
    )

    if st.button("New Chat", use_container_width=True):
        for key in ("messages", "history", "pending"):
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    model_choice = st.selectbox(
        "Gemini Model",
        options=["gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-3.8-flash"],
        index=0,
        help="Active Gemini model for tool calling agent",
    )
    st.markdown("---")
    st.caption("PlanGuard pre-execution risk scoring · " + model_choice)

# ---------------------------------------------------------------------------
# LLM cache – created once per (api_key, model) combination
# ---------------------------------------------------------------------------
@st.cache_resource(show_spinner=False)
def _get_llm(api_key: str, model_name: str = "gemini-3.5-flash-lite"):
    """Cached LLM with safe retry/timeout defaults."""
    from chat_demo.agent import make_llm  # noqa: PLC0415
    return make_llm(api_key, model_name)


# ---------------------------------------------------------------------------
# Session state initialisation
# ---------------------------------------------------------------------------
if "messages" not in st.session_state:
    st.session_state.messages = []        # List[{role, content, guard_info?}]
if "history" not in st.session_state:
    st.session_state.history = []         # LangChain message objects
if "pending" not in st.session_state:
    st.session_state.pending = None       # None or pending-decision dict


# ---------------------------------------------------------------------------
# Helper: audit badge HTML
# ---------------------------------------------------------------------------
def _badge_html(action: str, score: float, audit_id: str, audit_base_url: str) -> str:
    css = f"badge-{action.lower()}"
    b = f"<span class='guard-badge {css}'>{action} {score:.2f}</span>"
    if audit_id and audit_id != "fail-closed-client":
        link = f"{audit_base_url.rstrip('/')}/audit?id={audit_id}"
        b += f"<a class='audit-link' href='{link}' target='_blank'>View in PlanGuard ({audit_id[:8]}…)</a>"
    elif audit_id:
        b += f"<span class='audit-link'>ID: {audit_id}</span>"
    return b


def render_guard_badge(
    guard_events: list[dict[str, Any]],
    action: str = "NONE",
    score: float = 0.0,
    audit_id: str = "",
):
    """Render one badge per guard evaluation step."""
    events = guard_events or []
    if not events and action and action != "NONE":
        events = [{"action": action, "risk_score": score, "audit_id": audit_id}]
    if not events:
        return

    badges = " &nbsp; ".join(
        _badge_html(
            ev.get("action", "NONE"),
            float(ev.get("risk_score", 0.0)),
            ev.get("audit_id", ""),
            frontend_url,
        )
        for ev in events
    )
    st.markdown(f"<div style='margin-top:6px'>{badges}</div>", unsafe_allow_html=True)

    rationale_lines = []
    for i, ev in enumerate(events, 1):
        prefix = f"**Step {i}** " if len(events) > 1 else ""
        if ev.get("rationale"):
            rationale_lines.append(f"{prefix}{ev['rationale']}")
        if ev.get("rule_hits"):
            hits = ", ".join(ev["rule_hits"])
            rationale_lines.append(f"<span style='color:#888;font-size:0.78rem'>Rules: {hits}</span>")
        if ev.get("audit_id"):
            rationale_lines.append(f"<span style='color:#888;font-size:0.78rem'>Audit: {ev['audit_id']}</span>")

    if rationale_lines:
        with st.expander("PlanGuard details", expanded=False):
            st.markdown("<br>".join(rationale_lines), unsafe_allow_html=True)



# ---------------------------------------------------------------------------
# CONFIRM / REVISE card rendering (in history replay)
# ---------------------------------------------------------------------------
def render_decision_card_static(g: dict[str, Any]):
    """Render a resolved decision card (no buttons) for history replay."""
    action = g.get("action", "NONE")
    if action not in ("CONFIRM", "REVISE"):
        return
    outcome = g.get("card_outcome", "resolved")
    st.markdown(
        f"<div class='decision-card'>"
        f"<b>Decision: {action}</b> — {outcome}"
        f"</div>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Helper functions (must be defined before first use below)
# ---------------------------------------------------------------------------

def _append_assistant_message(
    content: str,
    guard_info: dict[str, Any],
    card_outcome: str = "",
    original_action: str = "",
    original_audit_id: str = "",
) -> None:
    """Append an assistant message to session_state.messages."""
    info = dict(guard_info)
    if card_outcome:
        info["card_outcome"] = card_outcome
    if original_action:
        info["original_action"] = original_action
    if original_audit_id:
        info["original_audit_id"] = original_audit_id
    st.session_state.messages.append({
        "role": "assistant",
        "content": content,
        "guard_info": info,
    })


def _handle_turn_result(res: dict[str, Any], p_history: list) -> None:  # noqa: ARG001
    """After a revise-round, store the new result or set a new pending card."""
    action = res["action"]
    if action in ("CONFIRM", "REVISE"):
        st.session_state.pending = {
            "action": action,
            "tool_calls": res.get("tool_calls", []),
            "plan_steps": res.get("plan_steps", []),
            "rationale": res.get("rationale", ""),
            "rule_hits": res.get("rule_hits", []),
            "risk_score": res.get("risk_score", 0.0),
            "audit_id": res.get("audit_id", ""),
            "revise_attempts": res.get("revise_attempts", 0) + 1,
            "max_revise_attempts": res.get("max_revise_attempts", 2),
            "guard_events": res.get("guard_events", []),
            "history": res["updated_history"],
        }
        _append_assistant_message(
            "",
            {
                "action": action,
                "risk_score": res.get("risk_score", 0.0),
                "audit_id": res.get("audit_id", ""),
                "rationale": res.get("rationale", ""),
                "rule_hits": res.get("rule_hits", []),
                "guard_events": res.get("guard_events", []),
            },
            card_outcome="pending",
        )
    else:
        reply = res.get("reply") or (
            "Cancelled. Nothing was executed." if action == "BLOCK" else "Done."
        )
        _append_assistant_message(
            reply,
            {
                "action": action,
                "risk_score": res.get("risk_score", 0.0),
                "audit_id": res.get("audit_id", ""),
                "rationale": res.get("rationale", ""),
                "rule_hits": res.get("rule_hits", []),
                "guard_events": res.get("guard_events", []),
            },
        )
        st.session_state.pending = None


# ---------------------------------------------------------------------------
# Render chat history
# ---------------------------------------------------------------------------
for _msg in st.session_state.messages:
    with st.chat_message(_msg["role"]):
        st.markdown(_msg["content"])
        if _msg["role"] == "assistant" and "guard_info" in _msg:
            _g = _msg["guard_info"]
            _act = _g.get("action", "NONE")
            render_guard_badge(
                guard_events=_g.get("guard_events", []),
                action=_act,
                score=_g.get("risk_score", 0.0),
                audit_id=_g.get("audit_id", ""),
            )
            if _act in ("CONFIRM", "REVISE"):
                render_decision_card_static(_g)

# ---------------------------------------------------------------------------
# Pending decision card (interactive – only shown once, before new input)
# ---------------------------------------------------------------------------
if st.session_state.pending is not None:
    pending = st.session_state.pending
    p_action = pending["action"]          # "CONFIRM" or "REVISE"
    p_tool_calls = pending["tool_calls"]
    p_plan_steps = pending.get("plan_steps", [])
    p_rationale = pending.get("rationale", "")
    p_rule_hits = pending.get("rule_hits", [])
    p_risk_score = pending.get("risk_score", 0.0)
    p_audit_id = pending.get("audit_id", "")
    p_revise_attempts = pending.get("revise_attempts", 0)
    p_max_revise = pending.get("max_revise_attempts", 2)
    p_history = pending["history"]        # snapshot of history at time of decision

    step_lines = build_step_list(p_tool_calls, p_plan_steps)

    with st.chat_message("assistant"):
        # Card title
        if p_action == "CONFIRM":
            st.markdown("### 🔔 The assistant wants your approval")
        else:
            st.markdown("### ⚠️ PlanGuard asked the assistant to change its plan")

        # What it wants to do
        st.markdown("**What the assistant wants to do:**")
        for line in step_lines:
            st.markdown(line)

        # Why
        st.markdown("**Why this needs a decision:**")
        st.markdown(p_rationale)
        if p_rule_hits:
            rules_str = ", ".join(p_rule_hits)
            st.markdown(
                f"<span style='color:#888;font-size:0.78rem'>Triggered rules: {rules_str}</span>",
                unsafe_allow_html=True,
            )
        badge_html = _badge_html(p_action, p_risk_score, p_audit_id, frontend_url)
        st.markdown(badge_html, unsafe_allow_html=True)

        st.markdown("---")

        if p_action == "CONFIRM":
            st.markdown("_Are you comfortable letting the assistant do this?_")
            col1, col2 = st.columns([1, 1])
            with col1:
                approve_key = f"approve_{p_audit_id}"
                if st.button("✅ Approve", key=approve_key, use_container_width=True, type="primary"):
                    # Build agent with cached LLM (no re-init)
                    guard_client = GuardClient(base_url=planguard_url, api_key=planguard_key)
                    llm = _get_llm(google_key, model_choice) if google_key else None
                    agent = GuardedAgent(guard_client=guard_client, llm=llm)
                    with st.spinner("Executing approved plan…"):
                        res = agent.resume_approved_plan(
                            history=p_history,
                            pending_tool_calls=p_tool_calls,
                        )
                    st.session_state.history = res["updated_history"]
                    _append_assistant_message(
                        res["reply"],
                        res,
                        card_outcome="approved",
                        original_action=p_action,
                        original_audit_id=p_audit_id,
                    )
                    st.session_state.pending = None
                    st.rerun()
            with col2:
                deny_key = f"deny_{p_audit_id}"
                if st.button("❌ Deny", key=deny_key, use_container_width=True):
                    _append_assistant_message(
                        "Cancelled. Nothing was executed.",
                        {"action": "BLOCK", "risk_score": p_risk_score, "audit_id": p_audit_id,
                         "rationale": "User denied.", "rule_hits": ["user_denied"],
                         "guard_events": pending.get("guard_events", [])},
                        card_outcome="denied",
                        original_action=p_action,
                        original_audit_id=p_audit_id,
                    )
                    st.session_state.history = p_history  # roll back history
                    st.session_state.pending = None
                    st.rerun()

        else:  # REVISE
            attempts_left = p_max_revise - p_revise_attempts
            if attempts_left > 0:
                st.markdown(f"_Revisions remaining: {attempts_left}/{p_max_revise}_")
                user_note = st.text_input(
                    "Add a note for the assistant (optional)",
                    key=f"revise_note_{p_audit_id}",
                    placeholder="e.g. Only read report.txt, no external posts.",
                )
                col1, col2 = st.columns([1, 1])
                with col1:
                    revise_key = f"revise_{p_audit_id}_{p_revise_attempts}"
                    if st.button("🔄 Ask assistant to revise", key=revise_key,
                                 use_container_width=True, type="primary"):
                        guard_client = GuardClient(base_url=planguard_url, api_key=planguard_key)
                        llm = _get_llm(google_key, model_choice) if google_key else None
                        agent = GuardedAgent(guard_client=guard_client, llm=llm)
                        with st.status("Agent revising plan…") as sb:
                            res = agent.run_revise_round(
                                history=p_history,
                                guard_rationale=p_rationale,
                                rule_hits=p_rule_hits,
                                user_note=user_note,
                                revise_attempts=p_revise_attempts,
                                max_revise_attempts=p_max_revise,
                                on_status=lambda label: sb.update(label=label),
                            )
                            sb.update(label="Complete", state="complete")
                        st.session_state.history = res["updated_history"]
                        _handle_turn_result(res, p_history)
                        st.rerun()
                with col2:
                    cancel_key = f"cancel_{p_audit_id}_{p_revise_attempts}"
                    if st.button("🚫 Cancel", key=cancel_key, use_container_width=True):
                        _append_assistant_message(
                            "Cancelled. Nothing was executed.",
                            {"action": "BLOCK", "risk_score": p_risk_score, "audit_id": p_audit_id,
                             "rationale": "User cancelled revision.", "rule_hits": ["user_cancelled"],
                             "guard_events": pending.get("guard_events", [])},
                            card_outcome="cancelled",
                            original_action=p_action,
                            original_audit_id=p_audit_id,
                        )
                        st.session_state.history = p_history
                        st.session_state.pending = None
                        st.rerun()
            else:
                st.error("Revision cap reached — plan cannot be executed.")
                st.session_state.pending = None




# ---------------------------------------------------------------------------
# New user message input
# ---------------------------------------------------------------------------
prompt = st.chat_input("Ask the agent… (PlanGuard protects every action)")
if prompt:
    # If there's a pending decision outstanding, cancel it silently
    if st.session_state.pending is not None:
        p = st.session_state.pending
        _append_assistant_message(
            "Cancelled. Nothing was executed.",
            {"action": "BLOCK", "risk_score": p.get("risk_score", 1.0),
             "audit_id": p.get("audit_id", ""), "rationale": "New message cancelled prior pending plan.",
             "rule_hits": ["user_new_message_cancel"], "guard_events": p.get("guard_events", [])},
            card_outcome="auto-cancelled",
            original_action=p["action"],
        )
        st.session_state.history = p["history"]  # roll back
        st.session_state.pending = None

    # Show user message
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Guard: API key required
    if not google_key:
        err = "⚠️ Please enter your **Google API Key** in the sidebar."
        st.session_state.messages.append({"role": "assistant", "content": err})
        with st.chat_message("assistant"):
            st.error(err)
        st.stop()

    # Run agent
    with st.chat_message("assistant"):
        guard_client = GuardClient(base_url=planguard_url, api_key=planguard_key)
        llm = _get_llm(google_key, model_choice)
        agent = GuardedAgent(guard_client=guard_client, llm=llm)

        st.session_state.history.append(HumanMessage(content=prompt))

        t_start = time.perf_counter()
        with st.status("Agent thinking…", expanded=False) as status_box:
            turn_result = agent.run_turn(
                st.session_state.history,
                on_status=lambda label: status_box.update(label=label),
            )
            st.session_state.history = turn_result["updated_history"]
            status_box.update(label="Complete", state="complete")
        t_elapsed = time.perf_counter() - t_start

        action = turn_result["action"]

        # Timing debug (small caption, not in chat bubble copy)
        timings = turn_result.get("timings", {})
        timing_parts = []
        for k, v in timings.items():
            timing_parts.append(f"{k}: {v:.1f}s")
        if timing_parts:
            st.caption("⏱ " + " | ".join(timing_parts))

        if action in ("CONFIRM", "REVISE"):
            # Show the decision card in the current bubble first time
            step_lines = build_step_list(
                turn_result.get("tool_calls", []),
                turn_result.get("plan_steps", []),
            )
            if action == "CONFIRM":
                st.markdown("### 🔔 The assistant wants your approval")
            else:
                st.markdown("### ⚠️ PlanGuard asked the assistant to change its plan")
            st.markdown("**What the assistant wants to do:**")
            for line in step_lines:
                st.markdown(line)
            st.markdown("**Why this needs a decision:**")
            st.markdown(turn_result.get("rationale", ""))
            if turn_result.get("rule_hits"):
                st.markdown(
                    f"<span style='color:#888;font-size:0.78rem'>Rules: {', '.join(turn_result['rule_hits'])}</span>",
                    unsafe_allow_html=True,
                )
            render_guard_badge(
                guard_events=turn_result.get("guard_events", []),
                action=action,
                score=turn_result["risk_score"],
                audit_id=turn_result["audit_id"],
            )

            # Save to session – buttons rendered at top of next rerun
            st.session_state.pending = {
                "action": action,
                "tool_calls": turn_result.get("tool_calls", []),
                "plan_steps": turn_result.get("plan_steps", []),
                "rationale": turn_result.get("rationale", ""),
                "rule_hits": turn_result.get("rule_hits", []),
                "risk_score": turn_result["risk_score"],
                "audit_id": turn_result["audit_id"],
                "revise_attempts": turn_result.get("revise_attempts", 0),
                "max_revise_attempts": turn_result.get("max_revise_attempts", 2),
                "guard_events": turn_result.get("guard_events", []),
                "history": turn_result["updated_history"],
            }
            # Save placeholder message (no content – card handles it)
            _append_assistant_message(
                "",
                {
                    "action": action,
                    "risk_score": turn_result["risk_score"],
                    "audit_id": turn_result["audit_id"],
                    "rationale": turn_result.get("rationale", ""),
                    "rule_hits": turn_result.get("rule_hits", []),
                    "guard_events": turn_result.get("guard_events", []),
                    "card_outcome": "pending",
                },
            )
            st.rerun()

        else:
            # ALLOW / BLOCK / error
            reply = turn_result.get("reply", "")
            if reply:
                st.markdown(reply)
            render_guard_badge(
                guard_events=turn_result.get("guard_events", []),
                action=action,
                score=turn_result["risk_score"],
                audit_id=turn_result["audit_id"],
            )
            _append_assistant_message(
                reply,
                {
                    "action": action,
                    "risk_score": turn_result["risk_score"],
                    "audit_id": turn_result["audit_id"],
                    "rationale": turn_result.get("rationale", ""),
                    "rule_hits": turn_result.get("rule_hits", []),
                    "guard_events": turn_result.get("guard_events", []),
                },
            )
