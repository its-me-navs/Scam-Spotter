"""FastAPI backend.  Run from the project root:   uvicorn server.main:app --reload

  GET  /                  the chat page (static/index.html)
  GET  /api/config        app name, enabled phases, languages, whether a real LLM is configured
  POST /api/chat          Server-Sent Events: one `step` event per pipeline step as it happens,
                          then one `answer` event with the output-checked reply
  POST /api/feedback      thumbs up / down on a reply
  GET  /api/history       this session's past messages (redacted text only)
  DELETE /api/history     delete this session's messages
  GET  /api/stats         aggregate counts

The answer event is only sent after the output guardrails have passed it.
"""
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import iterate_in_threadpool

from app.config import PHASE_LABELS, enabled_phases
from app.guardrails import redact_detailed
from app.language import LANG_LABELS
from app.llm import get_llm
from app.pipeline import ScamSpotter

from . import db

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    app.state.bot = ScamSpotter(llm=get_llm())
    yield


app = FastAPI(title="Scam Spotter", lifespan=lifespan)


class ChatIn(BaseModel):
    message: str = Field(max_length=5000)
    session_id: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    phase: Optional[str] = None
    lang: Optional[str] = Field(default=None, pattern=r"^(auto|en|hi|kn)$")


class FeedbackIn(BaseModel):
    message_id: int
    session_id: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    value: int = Field(ge=-1, le=1)


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def _sources(bot, category_id):
    entry = bot.kb["by_id"].get(category_id) if category_id else None
    if not entry:
        return []
    known = {s["id"]: s for s in bot.kb.get("sources", [])}
    return [{"publisher": known[i]["publisher"], "title": known[i]["title"], "url": known[i]["url"],
             "date": known[i].get("date"), "status": known[i].get("status")}
            for i in entry.get("source_ids", []) if i in known]


@app.get("/api/config")
def config():
    bot = app.state.bot
    phases = enabled_phases()
    return {
        "app_name": bot.kb["app_name"],
        "app_note": bot.kb["app_note"],
        "phases": [{"id": p, "label": PHASE_LABELS[p]} for p in phases],
        "languages": [{"id": "auto", "label": "Auto-detect (from the script you type)"}]
                     + [{"id": k, "label": v} for k, v in LANG_LABELS.items()],
        "llm": getattr(bot.llm, "name", "mock") if bot.llm else "none",
        "mock_llm": (getattr(bot.llm, "name", "mock") == "mock") if bot.llm else False,
    }


@app.post("/api/chat")
async def chat(body: ChatIn):
    bot = app.state.bot
    phases = enabled_phases()
    phase = body.phase or phases[0]
    if phase not in phases:
        raise HTTPException(400, f"phase '{phase}' is not enabled")
    lang = None if body.lang in (None, "auto") else body.lang
    redacted, _ = redact_detailed(body.message)       # only this version is ever stored

    async def stream():
        reply = None
        try:
            async for ev in iterate_in_threadpool(bot.ask_stream(body.message, phase, lang)):
                if ev.kind == "step":
                    yield _sse("step", {"status": ev.status, "text": ev.text})
                else:
                    reply = ev.reply
        except Exception:                              # never leak internals to the browser
            yield _sse("error", {"message": "Something went wrong on the server. Please try again."})
            return
        mid = db.save_message(body.session_id, phase, reply, redacted)
        yield _sse("answer", {
            "message_id": mid, "text": reply.text, "status": reply.status, "category_id": reply.category_id,
            "confidence": reply.confidence, "lang": reply.lang, "latency_ms": round(reply.latency_ms, 1),
            "used_llm": reply.used_llm, "sources": _sources(bot, reply.category_id),
            "echo": redacted,
        })

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/feedback")
def feedback(body: FeedbackIn):
    if not db.set_feedback(body.message_id, body.value, body.session_id):
        raise HTTPException(404, "message not found")
    return {"ok": True}


@app.get("/api/history")
def get_history(session_id: str = Query(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")):
    return db.history(session_id)


@app.delete("/api/history")
def delete_history(session_id: str = Query(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")):
    return {"deleted": db.clear_history(session_id)}


@app.get("/api/stats")
def get_stats():
    return db.stats()


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
