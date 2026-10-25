"""Which phases are switched on for users (CLI and UI).

The project is shown in stages. Right now only Phase 1 (LLM) is enabled.
To enable Phase 2 later, either edit DEFAULT_PHASES below or set an environment variable:

    SCAMSPOTTER_PHASES=llm,retrieval          # both phases
    SCAMSPOTTER_PHASES=llm,retrieval,hybrid   # everything

The Phase 2 and hybrid code stays in the repo, it is just not exposed.
"""
import os

ALL_PHASES = ("llm", "retrieval", "hybrid")
DEFAULT_PHASES = ("llm",)

PHASE_LABELS = {
    "llm": "Phase 1: LLM chatbot",
    "retrieval": "Phase 2: retrieval only (no AI)",
    "hybrid": "Hybrid router",
}


def enabled_phases():
    raw = os.getenv("SCAMSPOTTER_PHASES", "")
    chosen = tuple(p.strip() for p in raw.split(",") if p.strip() in ALL_PHASES)
    return chosen or DEFAULT_PHASES
