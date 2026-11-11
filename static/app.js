"use strict";
/* Chat page. Talks to the FastAPI backend:
   POST /api/chat streams Server-Sent Events: "step" events as the pipeline runs, then one "answer" event. */

const $ = (id) => document.getElementById(id);
const ICONS = { ok: "✓", info: "•", warn: "!", block: "✕" };

// ---- small safe wrappers around localStorage (can throw in private windows) ----
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* ignore */ } },
};

function newId() {
  const a = new Uint8Array(16); crypto.getRandomValues(a);
  return Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");
}
const sessionId = newId();

const settings = {
  phase: store.get("phase", null),
  lang: store.get("lang", "auto"),
  pace: store.get("pace", 350),
  showSteps: store.get("showSteps", true),
  showDetails: store.get("showDetails", true),
};
let config = null;
let busy = false;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- settings drawer (collapsible) ----
function setDrawer(open) {
  $("drawer").classList.toggle("open", open);
  $("drawer").setAttribute("aria-hidden", String(!open));
  $("settingsBtn").setAttribute("aria-expanded", String(open));
  $("scrim").hidden = !open;
  if (open) $("closeBtn").focus(); else $("settingsBtn").focus();
}
$("settingsBtn").addEventListener("click", () => setDrawer(!$("drawer").classList.contains("open")));
$("closeBtn").addEventListener("click", () => setDrawer(false));
$("scrim").addEventListener("click", () => setDrawer(false));
document.addEventListener("keydown", (e) => { if (e.key === "Escape") setDrawer(false); });

function bindSettings() {
  $("lang").innerHTML = "";
  for (const l of config.languages) $("lang").add(new Option(l.label, l.id));
  $("lang").value = settings.lang;
  $("lang").addEventListener("change", () => { settings.lang = $("lang").value; store.set("lang", settings.lang); });

  const ids = config.phases.map((p) => p.id);
  if (!ids.includes(settings.phase)) settings.phase = ids[0];
  if (config.phases.length > 1) {
    $("phaseRow").hidden = false;
    for (const p of config.phases) $("phase").add(new Option(p.label, p.id));
    $("phase").value = settings.phase;
    $("phase").addEventListener("change", () => { settings.phase = $("phase").value; store.set("phase", settings.phase); updateBanner(); });
  } else {
    $("phaseFixed").hidden = false;
    $("phaseFixed").textContent = config.phases[0].label;
  }

  $("pace").value = settings.pace;
  const showPace = () => { $("paceVal").textContent = settings.pace ? `(${(settings.pace / 1000).toFixed(2)} s)` : "(instant)"; };
  showPace();
  $("pace").addEventListener("input", () => { settings.pace = Number($("pace").value); store.set("pace", settings.pace); showPace(); });

  $("showSteps").checked = settings.showSteps;
  $("showSteps").addEventListener("change", () => { settings.showSteps = $("showSteps").checked; store.set("showSteps", settings.showSteps); });
  $("showDetails").checked = settings.showDetails;
  $("showDetails").addEventListener("change", () => { settings.showDetails = $("showDetails").checked; store.set("showDetails", settings.showDetails); });

  $("clearBtn").addEventListener("click", async () => {
    if (!confirm("Delete all messages from this chat history?")) return;
    await fetch(`/api/history?session_id=${sessionId}`, { method: "DELETE" });
    renderEmpty();
    setDrawer(false);
  });
}

function updateBanner() {
  $("mockBanner").hidden = !(config.mock_llm && settings.phase !== "retrieval");
}

// ---- rendering helpers (all text goes through textContent, never innerHTML) ----
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}
function scrollDown() { const c = $("chat"); c.scrollTop = c.scrollHeight; }
function renderEmpty() {
  $("chat").replaceChildren(el("p", "empty", "Describe a suspicious call, message, link or payment, in English, हिन्दी or ಕನ್ನಡ."));
}
function clearEmpty() { const e = document.querySelector(".empty"); if (e) e.remove(); }

function addUser(text) { const m = el("div", "msg user"); m.append(el("div", "text", text)); $("chat").append(m); scrollDown(); }

function addTraceItem(ol, status, text) {
  const li = el("li", status);
  li.append(el("span", "ic", ICONS[status] || "•"), el("span", "", text));
  ol.append(li);
}

function metaLine(a) {
  const parts = [`${a.status}`, `category: ${a.category_id || "none"}`];
  if (a.status === "answered") parts.push(`confidence: ${a.confidence.toFixed(2)}`);
  parts.push(`language: ${a.lang}`, `${Math.round(a.latency_ms)} ms`);
  return parts.join(" | ");
}

function addSources(box, sources) {
  if (!sources || !sources.length) return;
  const d = el("div", "sources", "Based on: ");
  sources.forEach((s, i) => {
    const label = `${s.publisher}${s.date ? " (" + s.date + ")" : ""}`;
    if (typeof s.url === "string" && s.url.startsWith("https://")) {
      const a = el("a", "", label); a.href = s.url; a.target = "_blank"; a.rel = "noopener noreferrer"; a.title = s.title;
      d.append(a);
    } else d.append(label);
    if (i < sources.length - 1) d.append("; ");
  });
  box.append(d);
}

function addFeedback(container, messageId, current) {
  const wrap = el("span", "fb");
  const up = el("button", "", "👍"), down = el("button", "", "👎");
  up.type = down.type = "button";
  up.setAttribute("aria-label", "Helpful"); down.setAttribute("aria-label", "Not helpful");
  const paint = (v) => { up.setAttribute("aria-pressed", String(v === 1)); down.setAttribute("aria-pressed", String(v === -1)); };
  paint(current);
  const send = async (v) => {
    paint(v);
    try {
      await fetch("/api/feedback", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message_id: messageId, session_id: sessionId, value: v }) });
    } catch { /* ignore */ }
  };
  up.addEventListener("click", () => send(up.getAttribute("aria-pressed") === "true" ? 0 : 1));
  down.addEventListener("click", () => send(down.getAttribute("aria-pressed") === "true" ? 0 : -1));
  wrap.append(up, down);
  container.append(wrap);
}

async function typeOut(node, text) {
  const pieces = text.match(/\S+\s*|\n+/g) || [text];
  for (const p of pieces) { node.textContent += p; scrollDown(); await sleep(28); }
}

// ---- history ----
function renderHistoryItem(h) {
  addUser(h.user_text);
  const m = el("div", "msg bot");
  if (h.trace && h.trace.length && settings.showSteps) {
    const det = el("details", "trace"); det.append(el("summary", "", "How this was handled"));
    const ol = el("ol"); h.trace.forEach(([s, t]) => addTraceItem(ol, s, t)); det.append(ol); m.append(det);
  }
  m.append(el("div", "text", h.reply_text));
  if (settings.showDetails) {
    const meta = el("div", "meta", metaLine({ status: h.status, category_id: h.category_id, confidence: h.confidence, lang: h.lang, latency_ms: h.latency_ms }));
    addFeedback(meta, h.id, h.feedback);
    m.append(meta);
  }
  $("chat").append(m);
}
async function loadHistory() {
  try {
    const r = await fetch(`/api/history?session_id=${sessionId}`);
    const rows = await r.json();
    if (!rows.length) return renderEmpty();
    rows.forEach(renderHistoryItem); scrollDown();
  } catch { renderEmpty(); }
}

// ---- send a message and render the live stream ----
async function send(message) {
  busy = true; $("send").disabled = true;
  clearEmpty();
  const userBubble = el("div", "msg user"); const userText = el("div", "text", message);
  userBubble.append(userText); $("chat").append(userBubble);

  const bot = el("div", "msg bot");
  const det = el("details", "trace"); det.open = settings.showSteps;
  const sum = el("summary"); const spin = el("span", "spin"); sum.append(spin, document.createTextNode("Checking your message…"));
  det.append(sum);
  const ol = el("ol"); det.append(ol);
  if (settings.showSteps) bot.append(det);
  const answerBox = el("div", "text");
  bot.append(answerBox);
  $("chat").append(bot); scrollDown();

  const queue = [];          // events wait here so the step speed slider can pace what the user sees
  let finished = false, answer = null, failed = null;

  const consumer = (async () => {
    while (!finished || queue.length) {
      if (!queue.length) { await sleep(30); continue; }
      const ev = queue.shift();
      if (ev.type === "step") { addTraceItem(ol, ev.data.status, ev.data.text); scrollDown(); if (settings.pace) await sleep(settings.pace); }
      else if (ev.type === "answer") answer = ev.data;
      else if (ev.type === "error") failed = ev.data.message;
    }
  })();

  try {
    const resp = await fetch("/api/chat", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, session_id: sessionId, phase: settings.phase, lang: settings.lang }),
    });
    if (!resp.ok) throw new Error(`Server returned ${resp.status}`);
    const reader = resp.body.getReader(); const dec = new TextDecoder(); let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const block = buf.slice(0, i); buf = buf.slice(i + 2);
        let type = "message", data = "";
        for (const line of block.split("\n")) {
          if (line.startsWith("event: ")) type = line.slice(7);
          else if (line.startsWith("data: ")) data += line.slice(6);
        }
        if (data) queue.push({ type, data: JSON.parse(data) });
      }
    }
  } catch (e) {
    failed = "Could not reach the server. Is it running?";
  }
  finished = true; await consumer;

  spin.remove();
  if (failed || !answer) {
    sum.textContent = "Stopped"; bot.classList.add("error");
    answerBox.textContent = failed || "No reply received.";
  } else {
    sum.textContent = `Checked in ${Math.round(answer.latency_ms)} ms`;
    det.open = false;
    userText.textContent = answer.echo;          // show the redacted version of what was typed
    await typeOut(answerBox, answer.text);
    addSources(bot, answer.sources);
    if (settings.showDetails) {
      const meta = el("div", "meta", metaLine(answer)); addFeedback(meta, answer.message_id, 0); bot.append(meta);
    }
  }
  scrollDown();
  busy = false; $("send").disabled = false; $("input").focus();
}

// ---- composer ----
const input = $("input");
function autosize() { input.style.height = "auto"; input.style.height = Math.min(input.scrollHeight, 160) + "px"; }
input.addEventListener("input", autosize);
input.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); $("form").requestSubmit(); } });
$("form").addEventListener("submit", (e) => {
  e.preventDefault();
  const msg = input.value.trim();
  if (!msg || busy) return;
  input.value = ""; autosize();
  send(msg);
});

// ---- start ----
(async function init() {
  try {
    config = await (await fetch("/api/config")).json();
  } catch {
    $("chat").replaceChildren(el("p", "empty", "Could not reach the server. Start it with: uvicorn server.main:app"));
    return;
  }
  $("appTitle").textContent = `${config.app_name} Scam Spotter`;
  $("appNote").textContent = config.app_note;
  bindSettings(); updateBanner();
  await loadHistory();
  input.focus();

  bindSettings(); updateBanner();
  await loadHistory();      // ← remove this line
  renderEmpty();            // ← add this line
  input.focus();
})();
