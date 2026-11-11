"""Glue: input guardrails -> phase (retrieval | llm | hybrid) -> output guardrails, in English, Hindi or Kannada.

`ask_stream()` is a generator. It yields an Event for every real step as it happens (language detected,
sensitive data removed, model called, output checked, ...) and finally an Event with the Reply, so a UI can
show what the system is doing live. `ask()` runs the same generator and returns just the Reply.

Steps never contain the sensitive values themselves: only what kind of data was found. The text shown as
"what the model will see" is the already-redacted text.
"""
import logging
import time
from dataclasses import dataclass, field
from typing import Iterator, Optional

from .guardrails import check_input, check_output
from .knowledge import entry_answer, load_kb, message
from .language import EN, LANG_NAMES
from .retrieval import Retriever

log = logging.getLogger("scamspotter")

HYBRID_RETRIEVAL_CONFIDENCE = 0.45  # at or above this, hybrid trusts retrieval and skips the LLM


@dataclass
class Reply:
    text: str
    phase: str
    status: str                      # answered | fallback | off_topic | injection | refusal | invalid
    category_id: Optional[str] = None
    confidence: float = 0.0
    latency_ms: float = 0.0
    used_llm: bool = False
    guardrail_events: list = field(default_factory=list)
    lang: str = EN
    trace: list = field(default_factory=list)       # [(status, text), ...] in the order the steps ran


@dataclass
class Event:
    kind: str                        # "step" | "final"
    status: str = "info"             # step only: ok | info | warn | block
    text: str = ""                   # step only
    reply: Optional[Reply] = None    # final only


def _step(status: str, text: str) -> Event:
    return Event("step", status, text)


def _clip(text: str, n: int = 160) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def _describe_error(e: Exception) -> str:
    """A short, safe description for the UI. Never includes the error message itself (it can echo parts of a key)."""
    code = getattr(e, "status_code", None)
    hints = {
        401: "the API key was rejected: check the key in .env.",
        403: "access denied: check the key and that the model is allowed for it.",
        404: "model or URL not found: check LLM_MODEL and OPENAI_BASE_URL in .env.",
        413: "the request was too large for this model or plan.",
        429: "rate limit or quota reached: wait a bit, or check your plan.",
    }
    if code in hints:
        return f"{type(e).__name__} (HTTP {code}), {hints[code]}"
    if code:
        return f"{type(e).__name__} (HTTP {code}). See the server log."
    if isinstance(e, KeyError):
        return f"a setting is missing ({e}). Check .env."
    return f"{type(e).__name__}. If this is a connection error, check OPENAI_BASE_URL and your internet. See the server log."


class ScamSpotter:
    def __init__(self, llm=None, kb=None):
        self.kb = kb or load_kb()
        self.retriever = Retriever(self.kb)
        self.llm = llm  # None disables phases that need an LLM

    # ---- helpers ----
    def _category_name(self, cid) -> str:
        e = self.kb["by_id"].get(cid)
        return e["category"] if e else str(cid)

    def _blocked_reply(self, res, phase, lang) -> Reply:
        mapping = {
            "invalid": ("invalid_answer", "invalid"),
            "injection": ("injection_answer", "injection"),
            "harmful": ("refusal_answer", "refusal"),
            "off_topic": ("off_topic_answer", "off_topic"),
        }
        key, status = mapping[res.status]
        return Reply(message(self.kb, key, lang), phase, status, guardrail_events=list(res.reasons), lang=lang)

    def _finish(self, reply: Reply, res, t0) -> Reply:
        if res.sensitive_found:
            reply.text = message(self.kb, "sensitive_input_warning", reply.lang) + "\n\n" + reply.text
            reply.guardrail_events.append("sensitive data redacted")
        reply.latency_ms = (time.perf_counter() - t0) * 1000
        return reply

    # ---- phases (generators: they yield steps and return the Reply) ----
    def _retrieval_gen(self, clean, lang, phase="retrieval"):
        yield _step("info", "Searching the approved knowledge base (TF-IDF similarity, no AI model involved)")
        m = self.retriever.search(clean, lang)
        if m.answered:
            yield _step("ok", f"Best match: {self._category_name(m.entry_id)} "
                              f"(similarity {m.score:.2f}, ahead of the runner-up by {m.margin:.2f})")
        else:
            yield _step("warn", f"No category matched clearly enough (best similarity {m.score:.2f}), so I will not guess")
        status = "answered" if m.answered else "fallback"
        return Reply(self.retriever.answer(m, lang), phase, status, m.entry_id, m.score, lang=lang)

    def _llm_gen(self, clean, lang, phase="llm"):
        name = getattr(self.llm, "name", "model")
        yield _step("info", f"Sending the redacted text to the language model ({name}), asking for a reply in "
                            f"{LANG_NAMES[lang]}")
        yield _step("info", f"What the model sees: “{_clip(clean)}”")
        try:
            out = self.llm.classify_and_answer(clean, self.kb, lang)
        except Exception as e:           # bad key, wrong model name, rate limit, network...
            log.exception("LLM call failed")
            yield _step("block", "The model call failed: " + _describe_error(e) + " Showing the safe fallback instead.")
            reply = Reply(message(self.kb, "fallback_answer", lang), phase, "fallback", used_llm=True, lang=lang)
            reply.guardrail_events.append("model call failed")
            return reply
        cid, text = out.get("category_id"), (out.get("answer") or "").strip()
        reply = Reply("", phase, "fallback", used_llm=True, lang=lang)

        if cid in self.kb["by_id"]:
            yield _step("ok", f"Model matched: {self._category_name(cid)}")
        else:
            yield _step("warn", "Model did not match any known scam category")

        verdict = None
        if text:
            yield _step("info", "Checking the model's answer before showing it: no requests for secrets, no invented "
                                f"links or phone numbers, written in {LANG_NAMES[lang]}")
            verdict = check_output(text, lang)
            if verdict.ok:
                yield _step("ok", "Output check: passed")
            else:
                yield _step("block", "Output check: blocked (" + "; ".join(verdict.reasons) + ")")

        if not text or cid in (None, "none") or (verdict and not verdict.ok):
            if verdict and not verdict.ok:
                reply.guardrail_events += ["output blocked: " + r for r in verdict.reasons]
            reply.text = message(self.kb, "fallback_answer", lang)
            return reply
        reply.text, reply.status, reply.category_id = text, "answered", cid
        return reply

    def _run(self, query, phase, lang) -> Iterator[Event]:
        if phase not in ("retrieval", "llm", "hybrid"):
            raise ValueError(f"unknown phase: {phase}")
        t0 = time.perf_counter()

        res = check_input(query, lang)
        for s in res.trace:
            yield _step(s.status, s.text)
        L = res.lang

        if res.status != "ok":
            yield _step("info", "Replying with a safe, pre-approved message")
            yield Event("final", reply=self._finish(self._blocked_reply(res, phase, L), res, t0))
            return

        clean = res.clean_query
        if phase == "retrieval" or (phase == "llm" and not self.llm):
            reply = yield from self._retrieval_gen(clean, L, "retrieval" if phase == "retrieval" else phase)
        elif phase == "llm":
            reply = yield from self._llm_gen(clean, L, "llm")
        else:  # hybrid: trust confident retrieval, otherwise ask the model
            yield _step("info", "Hybrid: trying the approved knowledge base first")
            m = self.retriever.search(clean, L)
            if m.answered and m.score >= HYBRID_RETRIEVAL_CONFIDENCE:
                yield _step("ok", f"Confident match ({m.score:.2f}): {self._category_name(m.entry_id)}. "
                                  "No AI model needed")
                reply = Reply(self.retriever.answer(m, L), "hybrid", "answered", m.entry_id, m.score, lang=L)
            elif self.llm:
                yield _step("info", f"Not confident enough (best similarity {m.score:.2f}), so I am asking the model")
                reply = yield from self._llm_gen(clean, L, "hybrid")
            else:
                reply = yield from self._retrieval_gen(clean, L, "hybrid")

        yield _step("ok", "Reply ready")
        yield Event("final", reply=self._finish(reply, res, t0))

    # ---- public API ----
    def ask_stream(self, query: Optional[str], phase: str = "retrieval", lang: Optional[str] = None) -> Iterator[Event]:
        """Yield step Events as they happen, then one final Event carrying the Reply (with `reply.trace` filled)."""
        trace = []
        for ev in self._run(query, phase, lang):
            if ev.kind == "step":
                trace.append((ev.status, ev.text))
            else:
                ev.reply.trace = trace
            yield ev

    def ask(self, query: Optional[str], phase: str = "retrieval", lang: Optional[str] = None) -> Reply:
        reply = None
        for ev in self.ask_stream(query, phase, lang):
            if ev.kind == "final":
                reply = ev.reply
        return reply
