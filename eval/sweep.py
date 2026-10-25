"""Sweep the retrieval threshold/margin on the DEV cases to see the accuracy vs safety trade-off.

  python -m eval.sweep

Pick values here, then confirm on data/heldout_cases.json (which you must not tune on).
"""
import json
from pathlib import Path

from app.guardrails import check_input
from app.knowledge import load_kb
from app.retrieval import Retriever

ROOT = Path(__file__).resolve().parent.parent


def main(path=ROOT / "data" / "test_cases.json"):
    kb = load_kb()
    cases = [c for c in json.load(open(path, encoding="utf-8")) if c["type"] in ("scam", "unknown")]
    print("threshold margin | correct wrong fallback | unknown_answered")
    for th in (0.12, 0.14, 0.16, 0.18, 0.20, 0.22, 0.25):
        for mg in (0.0, 0.02, 0.03):
            r = Retriever(kb, th, mg)
            right = wrong = fb = unk = 0
            for c in cases:
                m = r.search(check_input(c["q"]).clean_query)
                if c["type"] == "scam":
                    if not m.answered:
                        fb += 1
                    elif m.entry_id == c["expect"]:
                        right += 1
                    else:
                        wrong += 1
                elif m.answered:
                    unk += 1
            print(f"{th:<9} {mg:<6} | {right:^7} {wrong:^5} {fb:^8} | {unk}")


if __name__ == "__main__":
    main()
