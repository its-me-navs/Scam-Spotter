"""Loads the approved knowledge base (single source of truth for both phases)."""
import json
from pathlib import Path

KB_PATH = Path(__file__).resolve().parent.parent / "data" / "knowledge_base.json"


def load_kb(path: Path = KB_PATH) -> dict:
    with open(path, encoding="utf-8") as f:
        kb = json.load(f)
    kb["by_id"] = {e["id"]: e for e in kb["entries"]}
    return kb
