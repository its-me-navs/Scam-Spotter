"""Glue: input guardrails -> phase (retrieval | llm | hybrid) -> output guardrails."""
import time
from dataclasses import dataclass, field
from typing import Optional

from .guardrails import check_input, check_output
from .knowledge import load_kb
from .retrieval import Retriever

HYBRID_RETRIEVAL_CONFIDENCE = 0.45  # at or above this, hybrid trusts retrieval and skips the LLM


@dataclass
class Reply:
    text: str
    phase: str
    status: str                      # answered | fallback | off_topic | injection | refusal | sensitive | invalid
    category_id: Optional[str] = None
    confidence: float = 0.0
    latency_ms: float = 0.0
    used_llm: bool = False
    guardrail_events: list = field(default_factory=list)


class ScamSpotter:
    def __init__(self, llm=None, kb=None):
        self.kb = kb or load_kb()
        self.retriever = Retriever(self.kb)
        self.llm = llm  # None disables phases that need an LLM

    # ---- helpers ----
    def _blocked_reply(self, res, phase, t0):
        kb = self.kb
        mapping = {
            "invalid": ("Please type a question about a suspicious call, message, link or payment.", "invalid"),
            "injection": (kb["injection_answer"], "injection"),
            "harmful": (kb["refusal_answer"], "refusal"),
            "off_topic": (kb["off_topic_answer"], "off_topic"),
        }
        text, status = mapping[res.status]
        return Reply(text, phase, status, latency_ms=(time.perf_counter() - t0) * 1000,
                     guardrail_events=res.reasons)

    def _finish(self, reply: Reply, res, t0):
        if res.sensitive_found:
            reply.text = self.kb["sensitive_input_warning"] + "\n\n" + reply.text
            reply.guardrail_events.append("sensitive data redacted")
            if reply.status == "answered":
                reply.status = "answered"  # still helpful, warning is prepended
        reply.latency_ms = (time.perf_counter() - t0) * 1000
        return reply

    # ---- phases ----
    def _retrieval(self, query):
        m = self.retriever.search(query)
        status = "answered" if m.answered else "fallback"
        return Reply(self.retriever.answer(m), "retrieval", status, m.entry_id, m.score)

    def _llm(self, query):
        out = self.llm.classify_and_answer(query, self.kb)
        reply = Reply("", "llm", "fallback", used_llm=True)
        cid, text = out.get("category_id"), (out.get("answer") or "").strip()
        verdict = check_output(text) if text else None
        if not text or cid in (None, "none") or (verdict and not verdict.ok):
            if verdict and not verdict.ok:
                reply.guardrail_events += ["output blocked: " + r for r in verdict.reasons]
            reply.text = self.kb["fallback_answer"]
            return reply
        reply.text, reply.status, reply.category_id = text, "answered", cid
        return reply

    def ask(self, query: Optional[str], phase: str = "retrieval") -> Reply:
        t0 = time.perf_counter()
        res = check_input(query)
        if res.status != "ok":
            return self._finish(self._blocked_reply(res, phase, t0), res, t0)

        clean = res.clean_query
        if phase == "retrieval":
            reply = self._retrieval(clean)
        elif phase == "llm":
            reply = self._llm(clean) if self.llm else self._retrieval(clean)
        elif phase == "hybrid":
            m = self.retriever.search(clean)
            if m.answered and m.score >= HYBRID_RETRIEVAL_CONFIDENCE:
                reply = self._retrieval(clean)
                reply.phase = "hybrid"
            elif self.llm:
                reply = self._llm(clean)
                reply.phase = "hybrid"
            else:
                reply = self._retrieval(clean)
                reply.phase = "hybrid"
        else:
            raise ValueError(f"unknown phase: {phase}")
        return self._finish(reply, res, t0)
