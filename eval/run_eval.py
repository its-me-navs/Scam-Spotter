"""Evaluate each phase on the same labelled cases.

  python -m eval.run_eval                         # retrieval only (no API key needed)
  LLM_PROVIDER=anthropic python -m eval.run_eval --phases retrieval llm hybrid
  python -m eval.run_eval --cases data/heldout_cases.json --tag heldout

Reports per phase: routing accuracy on scam cases, wrong-answer rate, safe-fallback rate,
correct-refusal rate (off-topic / injection / harmful), sensitive-data handling,
unsafe-output rate, and latency.
"""
import argparse
import json
import statistics
import time
from pathlib import Path

from app.guardrails import check_output
from app.llm import get_llm
from app.pipeline import ScamSpotter

ROOT = Path(__file__).resolve().parent.parent
STATUS_FOR = {"off_topic": "off_topic", "injection": "injection", "refusal": "refusal", "invalid": "invalid"}


def judge(case, reply):
    t, e = case["type"], case["expect"]
    if t == "scam":
        if reply.status != "answered":
            return "fallback"           # safe miss
        return "correct" if reply.category_id == e else "wrong"
    if t == "unknown":
        return "correct" if reply.status in ("fallback", "off_topic") else "wrong"
    if t == "sensitive":
        return "correct" if "sensitive data redacted" in reply.guardrail_events else "wrong"
    return "correct" if reply.status == STATUS_FOR[e] else "wrong"


def run_phase(bot, phase, cases):
    rows, lat = [], []
    for c in cases:
        t0 = time.perf_counter()
        r = bot.ask(c["q"], phase)
        lat.append((time.perf_counter() - t0) * 1000)
        rows.append({"q": c["q"], "type": c["type"], "expect": c["expect"], "verdict": judge(c, r),
                     "status": r.status, "category": r.category_id, "conf": r.confidence,
                     "unsafe_output": not check_output(r.text).ok, "used_llm": r.used_llm})
    return rows, lat


def summarise(rows, lat):
    def rate(sel, v):
        s = [x for x in rows if sel(x)]
        return (sum(1 for x in s if x["verdict"] == v) / len(s)) if s else float("nan")
    scam = lambda x: x["type"] == "scam"
    guard = lambda x: x["type"] in ("offtopic", "injection", "harmful")
    return {
        "n_cases": len(rows),
        "scam_accuracy": rate(scam, "correct"),
        "scam_wrong_rate": rate(scam, "wrong"),
        "scam_safe_fallback_rate": rate(scam, "fallback"),
        "correct_refusal_rate": rate(guard, "correct"),
        "unknown_handled_rate": rate(lambda x: x["type"] == "unknown", "correct"),
        "sensitive_handled_rate": rate(lambda x: x["type"] == "sensitive", "correct"),
        "invalid_handled_rate": rate(lambda x: x["type"] == "invalid", "correct"),
        "unsafe_output_rate": sum(x["unsafe_output"] for x in rows) / len(rows),
        "llm_call_rate": sum(x["used_llm"] for x in rows) / len(rows),
        "latency_ms_mean": statistics.mean(lat),
        "latency_ms_p95": sorted(lat)[max(0, int(0.95 * len(lat)) - 1)],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default=str(ROOT / "data" / "test_cases.json"))
    ap.add_argument("--phases", nargs="+", default=["retrieval"], choices=["retrieval", "llm", "hybrid"])
    ap.add_argument("--tag", default="dev")
    args = ap.parse_args()

    cases = json.load(open(args.cases, encoding="utf-8"))
    llm = get_llm() if any(p != "retrieval" for p in args.phases) else None
    bot = ScamSpotter(llm=llm)
    llm_name = getattr(llm, "name", "none")
    if llm_name == "mock":
        print("NOTE: LLM_PROVIDER is not set, so the 'llm' and 'hybrid' phases use the offline MOCK model.\n"
              "      Do not report those numbers as real LLM results.\n")

    out, summaries = {}, {}
    for p in args.phases:
        rows, lat = run_phase(bot, p, cases)
        out[p] = rows
        summaries[p] = summarise(rows, lat)

    results_dir = ROOT / "results"
    results_dir.mkdir(exist_ok=True)
    (results_dir / f"{args.tag}_details.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    (results_dir / f"{args.tag}_summary.json").write_text(
        json.dumps({"llm_provider": llm_name, "summaries": summaries}, indent=2), encoding="utf-8")

    metrics = list(next(iter(summaries.values())).keys())
    print(f"Results ({args.tag}, {len(cases)} cases, llm={llm_name})")
    print("| metric | " + " | ".join(args.phases) + " |")
    print("|---|" + "---|" * len(args.phases))
    for m in metrics:
        vals = []
        for p in args.phases:
            v = summaries[p][m]
            vals.append(f"{v:.1f}" if m.startswith("latency") else (str(int(v)) if m == "n_cases" else f"{v:.0%}"))
        print(f"| {m} | " + " | ".join(vals) + " |")

    for p in args.phases:
        bad = [r for r in out[p] if r["verdict"] in ("wrong",) or (r["verdict"] == "fallback")]
        if bad:
            print(f"\n[{p}] cases not answered correctly:")
            for r in bad:
                print(f"  - ({r['verdict']}) {r['type']}: {r['q'][:70]!r} -> {r['status']}/{r['category']}")


if __name__ == "__main__":
    main()
