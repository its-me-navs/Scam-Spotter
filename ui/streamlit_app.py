"""Streamlit UI.  Run from the project root:  streamlit run ui/streamlit_app.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st

from app.llm import get_llm
from app.pipeline import ScamSpotter


@st.cache_resource
def load_bot():
    return ScamSpotter(llm=get_llm())


bot = load_bot()
kb = bot.kb

st.set_page_config(page_title="Scam Spotter", page_icon="🛡️")
st.title(f"🛡️ {kb['app_name']} Scam Spotter")
st.caption(kb["app_note"])

phase = st.sidebar.radio(
    "Phase",
    ["retrieval", "llm", "hybrid"],
    format_func={"retrieval": "Phase 2: retrieval only (no AI)", "llm": "Phase 1: LLM", "hybrid": "Hybrid router"}.get,
)
if phase != "retrieval" and getattr(bot.llm, "name", "mock") == "mock":
    st.sidebar.warning("No real LLM configured (LLM_PROVIDER not set); using the offline mock model.")
show_debug = st.sidebar.checkbox("Show guardrail / confidence details", value=True)
st.sidebar.markdown("**Never share your OTP, PIN or password with anyone, including this bot.**")

if "history" not in st.session_state:
    st.session_state.history = []

for role, text, meta in st.session_state.history:
    with st.chat_message(role):
        st.write(text)
        if meta and show_debug:
            st.caption(meta)

if prompt := st.chat_input("Describe a suspicious call, message, link or payment..."):
    # Only the redacted text is stored in history; raw input is never logged.
    reply = bot.ask(prompt, phase)
    from app.guardrails import redact
    shown, _ = redact(prompt)
    st.session_state.history.append(("user", shown, None))
    meta = (f"{reply.status} | category={reply.category_id} | confidence={reply.confidence} | "
            f"{reply.latency_ms:.0f} ms" + (f" | {'; '.join(reply.guardrail_events)}" if reply.guardrail_events else ""))
    st.session_state.history.append(("assistant", reply.text, meta))
    st.rerun()
