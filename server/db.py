"""SQLite storage (standard library only).

Privacy rule: only REDACTED text is ever stored. The user's message is passed through the same redaction
as the model path before it reaches this module, so a PIN/OTP/card number typed by a user is never written to disk.
"""
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(os.getenv("SCAMSPOTTER_DB") or Path(__file__).resolve().parent.parent / "data" / "scamspotter.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    session_id TEXT NOT NULL,
    phase TEXT NOT NULL,
    lang TEXT NOT NULL,
    user_text TEXT NOT NULL,          -- redacted
    reply_text TEXT NOT NULL,
    status TEXT NOT NULL,
    category_id TEXT,
    confidence REAL,
    latency_ms REAL,
    used_llm INTEGER NOT NULL DEFAULT 0,
    trace_json TEXT NOT NULL,
    feedback INTEGER                  -- 1 helpful, -1 not helpful, NULL no vote
);
CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, id);
CREATE TABLE IF NOT EXISTS eval_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    tag TEXT NOT NULL,
    llm_provider TEXT NOT NULL,
    phase TEXT NOT NULL,
    summary_json TEXT NOT NULL
);
"""


@contextmanager
def connect(path=None):
    con = sqlite3.connect(str(path or DB_PATH))
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init(path=None):
    p = Path(path or DB_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    with connect(p) as con:
        con.executescript(SCHEMA)


def save_message(session_id, phase, reply, user_text_redacted, path=None) -> int:
    with connect(path) as con:
        cur = con.execute(
            "INSERT INTO messages (ts, session_id, phase, lang, user_text, reply_text, status, category_id,"
            " confidence, latency_ms, used_llm, trace_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (time.time(), session_id, phase, reply.lang, user_text_redacted, reply.text, reply.status,
             reply.category_id, reply.confidence, reply.latency_ms, int(reply.used_llm),
             json.dumps(reply.trace, ensure_ascii=False)))
        return cur.lastrowid


def set_feedback(message_id: int, value: int, session_id: str, path=None) -> bool:
    with connect(path) as con:
        cur = con.execute("UPDATE messages SET feedback=? WHERE id=? AND session_id=?",
                          (value if value in (1, -1) else None, message_id, session_id))
        return cur.rowcount > 0


def history(session_id: str, limit: int = 50, path=None) -> list:
    with connect(path) as con:
        rows = con.execute("SELECT * FROM messages WHERE session_id=? ORDER BY id DESC LIMIT ?",
                           (session_id, limit)).fetchall()
    out = []
    for r in reversed(rows):
        d = dict(r)
        d["trace"] = json.loads(d.pop("trace_json"))
        out.append(d)
    return out


def clear_history(session_id: str, path=None) -> int:
    with connect(path) as con:
        return con.execute("DELETE FROM messages WHERE session_id=?", (session_id,)).rowcount


def stats(path=None) -> dict:
    with connect(path) as con:
        total = con.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        by_status = {r[0]: r[1] for r in con.execute("SELECT status, COUNT(*) FROM messages GROUP BY status")}
        by_lang = {r[0]: r[1] for r in con.execute("SELECT lang, COUNT(*) FROM messages GROUP BY lang")}
        fb = {r[0]: r[1] for r in con.execute(
            "SELECT feedback, COUNT(*) FROM messages WHERE feedback IS NOT NULL GROUP BY feedback")}
        lat = con.execute("SELECT AVG(latency_ms) FROM messages").fetchone()[0]
    return {"messages": total, "by_status": by_status, "by_language": by_lang,
            "helpful": fb.get(1, 0), "not_helpful": fb.get(-1, 0),
            "mean_latency_ms": round(lat, 1) if lat is not None else None}


def save_eval_run(tag, llm_provider, phase, summary: dict, path=None):
    with connect(path) as con:
        con.execute("INSERT INTO eval_runs (ts, tag, llm_provider, phase, summary_json) VALUES (?,?,?,?,?)",
                    (time.time(), tag, llm_provider, phase, json.dumps(summary)))
