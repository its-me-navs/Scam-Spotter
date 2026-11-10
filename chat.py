"""Command-line chat. Usage:  python chat.py [--lang auto|en|hi|kn] [--no-trace]
(only the phases enabled in app/config.py are available)"""
import argparse

from app.config import enabled_phases
from app.llm import get_llm
from app.pipeline import ScamSpotter

ICONS = {"ok": "[ok]  ", "info": "[..]  ", "warn": "[!]   ", "block": "[STOP]"}


def main():
    ap = argparse.ArgumentParser()
    phases = enabled_phases()
    ap.add_argument("--phase", choices=list(phases), default=phases[0])
    ap.add_argument("--lang", choices=["auto", "en", "hi", "kn"], default="auto", help="reply language")
    ap.add_argument("--no-trace", action="store_true", help="hide the step-by-step trace")
    args = ap.parse_args()
    lang = None if args.lang == "auto" else args.lang
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
        r = None
        for ev in bot.ask_stream(q, args.phase, lang):
            if ev.kind == "step" and not args.no_trace:
                print(f"     {ICONS.get(ev.status, '[..]  ')} {ev.text}", flush=True)
            elif ev.kind == "final":
                r = ev.reply
        print(f"\nbot> {r.text}")
        print(f"     [{r.status} | category={r.category_id} | conf={r.confidence} | lang={r.lang} | "
              f"{r.latency_ms:.0f} ms{' | ' + '; '.join(r.guardrail_events) if r.guardrail_events else ''}]\n")


if __name__ == "__main__":
    main()
