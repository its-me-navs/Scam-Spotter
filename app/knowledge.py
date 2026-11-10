"""Loads the approved knowledge base (single source of truth for all phases and languages).

English text lives at the top level (`answer`, `fallback_answer`, ...). Hindi and Kannada versions are
stored next to it: `answer_hi`, `answer_kn` on each entry, and `i18n.hi` / `i18n.kn` for the fixed messages.
Anything missing in a language falls back to the English text.
"""
import json
from pathlib import Path

KB_PATH = Path(__file__).resolve().parent.parent / "data" / "knowledge_base.json"


def load_kb(path: Path = KB_PATH) -> dict:
    with open(path, encoding="utf-8") as f:
        kb = json.load(f)
    kb["by_id"] = {e["id"]: e for e in kb["entries"]}
    return kb


def message(kb: dict, key: str, lang: str = "en") -> str:
    """A fixed message (fallback_answer, off_topic_answer, ...) in the requested language."""
    if lang != "en":
        text = kb.get("i18n", {}).get(lang, {}).get(key)
        if text:
            return text
    return kb[key]


def entry_answer(entry: dict, lang: str = "en") -> str:
    """The approved answer for one category in the requested language."""
    if lang != "en" and entry.get(f"answer_{lang}"):
        return entry[f"answer_{lang}"]
    return entry["answer"]


def entry_field(entry: dict, field: str, lang: str = "en") -> list:
    """Per-language lists such as example_queries / keywords ('example_queries_hi')."""
    if lang == "en":
        return entry.get(field, [])
    return entry.get(f"{field}_{lang}", [])
