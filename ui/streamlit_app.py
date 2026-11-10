"""Streamlit UI.  Run from the project root:  streamlit run ui/streamlit_app.py

For every message it shows, live, what the system is doing (language detected, sensitive data removed before
the model sees anything, model called, output checked), then streams the checked answer.
The answer is only streamed AFTER the output guardrails have passed it, so nothing unchecked is ever shown.
"""
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st

from app.config import PHASE_LABELS, enabled_phases
from app.guardrails import redact
from app.language import LANG_LABELS
from app.llm import get_llm
from app.pipeline import ScamSpotter

ICONS = {"ok": "✅", "info": "🔹", "warn": "⚠️", "block": "⛔"}


@st.cache_resource
def load_bot():
    return ScamSpotter(llm=get_llm())


def stream_words(text: str, delay: float):
    """Typewriter effect: yield the already-checked text a few words at a time."""
    for piece in re.findall(r"\S+\s*|\n+", text):
        yield piece
        if delay:
            time.sleep(delay)


def trace_lines(trace) -> str:
    return "\n\n".join(f"{ICONS.get(s, '🔹')} {t}" for s, t in trace)


bot = load_bot()
kb = bot.kb

st.set_page_config(page_title="Scam Spotter", page_icon="🛡️")
st.title(f"🛡️ {kb['app_name']} Scam Spotter")
st.caption(kb["app_note"])

# ---- sidebar ----
phases = enabled_phases()
if len(phases) == 1:
    phase = phases[0]
    st.sidebar.markdown(f"**{PHASE_LABELS[phase]}**")
else:
    phase = st.sidebar.radio("Phase", list(phases), format_func=PHASE_LABELS.get)
if phase != "retrieval" and getattr(bot.llm, "name", "mock") == "mock":
    st.sidebar.warning("No real LLM configured (LLM_PROVIDER not set); using the offline mock model.")

lang_choice = st.sidebar.selectbox(
    "Reply language", ["auto", "en", "hi", "kn"],
    format_func=lambda k: "Auto-detect (from the script you type)" if k == "auto" else LANG_LABELS[k])
lang = None if lang_choice == "auto" else lang_choice

show_steps = st.sidebar.checkbox("Show live steps (what the system is doing)", value=True)
pace = st.sidebar.slider("Step speed (seconds per step, for demos)", 0.0, 1.0, 0.35, 0.05)
show_debug = st.sidebar.checkbox("Show category / confidence details", value=True)
st.sidebar.markdown("**Never share your OTP, PIN or password with anyone, including this bot.**")

if "history" not in st.session_state:
    st.session_state.history = []

# ---- earlier messages ----
for item in st.session_state.history:
    with st.chat_message(item["role"]):
        st.write(item["text"])
        if item.get("trace") and show_steps:
            with st.expander("How this was handled"):
                st.markdown(trace_lines(item["trace"]))
        if item.get("meta") and show_debug:
            st.caption(item["meta"])

# ---- new message ----
if prompt := st.chat_input("Describe a suspicious call, message, link or payment..."):
    # Only the redacted text is shown back and stored; the raw input is never logged.
    shown, _ = redact(prompt)
    with st.chat_message("user"):
        st.write(shown)

    with st.chat_message("assistant"):
        box = st.status("Checking your message…", expanded=show_steps)
        reply = None
        for ev in bot.ask_stream(prompt, phase, lang):
            if ev.kind == "step":
                box.write(f"{ICONS.get(ev.status, '🔹')} {ev.text}")
                if pace:
                    time.sleep(pace)
            else:
                reply = ev.reply
        box.update(label=f"Checked in {reply.latency_ms:.0f} ms", state="complete", expanded=False)

        st.write_stream(stream_words(reply.text, 0.03))

        meta = (f"{reply.status} | category={reply.category_id} | confidence={reply.confidence} | "
                f"language={reply.lang} | {reply.latency_ms:.0f} ms"
                + (f" | {'; '.join(reply.guardrail_events)}" if reply.guardrail_events else ""))
        entry = kb["by_id"].get(reply.category_id) if reply.category_id else None
        if entry and entry.get("source_ids"):
            meta += " | based on: " + ", ".join(entry["source_ids"])
        if show_debug:
            st.caption(meta)

    st.session_state.history.append({"role": "user", "text": shown})
    st.session_state.history.append({"role": "assistant", "text": reply.text, "meta": meta, "trace": reply.trace})
