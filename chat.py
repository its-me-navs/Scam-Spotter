"""Command-line chat. Usage:  python chat.py   (only the phases enabled in app/config.py are available)"""
import argparse

from app.config import enabled_phases
from app.llm import get_llm
from app.pipeline import ScamSpotter


def main():
    ap = argparse.ArgumentParser()
    phases = enabled_phases()
    ap.add_argument("--phase", choices=list(phases), default=phases[0])
    args = ap.parse_args()
    llm = get_llm() if args.phase != "retrieval" else None
    bot = ScamSpotter(llm=llm)
    print(f"{bot.kb['app_name']} Scam Spotter ({args.phase}). {bot.kb['app_note']}")
    print("Type 'quit' to exit.\n")
    while True:
        try:
            q = input("you> ")
        except (EOFError, KeyboardInterrupt):
            break
        if q.strip().lower() in {"quit", "exit"}:
            break
        r = bot.ask(q, args.phase)
        print(f"\nbot> {r.text}")
        print(f"     [{r.status} | category={r.category_id} | conf={r.confidence} | {r.latency_ms:.0f} ms"
              f"{' | ' + '; '.join(r.guardrail_events) if r.guardrail_events else ''}]\n")


if __name__ == "__main__":
    main()
