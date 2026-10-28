"""Shared guardrail layer used by BOTH phases.

Input side:  validate -> redact sensitive data -> detect injection -> detect harmful
             requests -> scope check.
Output side: block unsafe LLM output (asks for secrets, invented contact details/links).

Keyword/regex rules are deliberately simple and are NOT a complete defence. The evaluation
harness exists to measure where they fail.
"""
import re
from dataclasses import dataclass, field
from typing import Optional

MAX_QUERY_CHARS = 1000

# ---------- sensitive data (redacted before anything reaches an LLM or a log) ----------
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_OTP_RE = re.compile(
    r"\b(?:otp|code|pin|cvv|password|passcode)\b[^0-9]{0,25}(\d{3,8})\b", re.I
)
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[- ]?)?[6-9]\d{9}(?!\d)")


def redact(text: str) -> tuple[str, bool]:
    """Replace card numbers, OTP/PIN-like codes and phone numbers. Returns (clean, found)."""
    found = False

    def _sub(pattern, repl, s):
        nonlocal found
        new, n = pattern.subn(repl, s)
        if n:
            found = True
        return new

    text = _sub(_CARD_RE, "[CARD]", text)
    text = _sub(_PHONE_RE, "[PHONE]", text)

    def _code(m):
        nonlocal found
        found = True
        return m.group(0).replace(m.group(1), "[CODE]")

    text = _OTP_RE.sub(_code, text)
    return text, found


# ---------- prompt injection ----------
_INJECTION_PATTERNS = [
    r"ignore (all |any |the )?(previous|prior|above|earlier) (instructions|rules|prompts?)",
    r"disregard (all |any |the )?(previous|prior|above|earlier|your)",
    r"forget (all |any |your |the )?(previous |prior )?(instructions|rules|prompt)",
    r"(system|hidden|secret|initial) (prompt|instructions?)",
    r"developer mode",
    r"jailbreak",
    r"\bdan\b mode",
    r"pretend (you|to) (have no|are not|aren't|are an?)",
    r"(act|behave) as (an? )?(unrestricted|unfiltered|different)",
    r"(disable|bypass|turn off|remove) (your )?(safety|guardrails?|rules|restrictions?|filters?)",
    r"reveal (your|the) (prompt|instructions|rules)",
    r"you are now",
    r"(instructions?|rules?|prompt) (you were|you have been|you are|i gave you|were) (given|told|using)",
    r"(show|print|display|tell|repeat|share) me (the |your )?(instructions?|prompt|rules)( you| that)?",
    r"(no|without) (rules|restrictions|limits|guardrails|filters)",
    r"from now on[, ]+(you|ignore|forget|act)",
    r"forget (the |all |your )?(previous|prior|earlier) (ones|rules|instructions)?",
    r"safety (filters?|rules|guardrails?)",
]
_INJECTION_RE = re.compile("|".join(_INJECTION_PATTERNS), re.I)

# ---------- harmful / offensive requests (helping commit fraud) ----------
_HARM_RE = re.compile(
    r"("
    r"\bhack\b.*\b(account|wallet|phone|someone)"
    r"|how (do|can|to) i (trick|fool|cheat|scam|steal|defraud)"
    r"|(write|create|make|draft|generate|design|build).{0,40}"
    r"(fake|phishing|scam|fraud|spoof|fraudulent).{0,40}(kyc|message|sms|page|site|website|link|email|call|script)"
    r"|(phishing|fake) (page|site|website).{0,40}(look|looks|like)"
    r"|(get|steal|collect|harvest).{0,25}(otp|pin|password|card details).{0,25}(from|of) (people|others|someone|victims?)"
    r"|trick people into (giving|sharing|telling).{0,20}(otp|pin|password)"
    r")",
    re.I,
)

# ---------- scope ----------
_SCOPE_TERMS = [
    "scam", "fraud", "fake", "phish", "otp", "pin", "password", "kyc", "refund", "cashback",
    "link", "upi", "qr", "scan", "payment", "pay", "paid", "money", "wallet", "account",
    "transaction", "debit", "deduct", "bank", "card", "cvv", "verify", "verification",
    "call", "caller", "message", "sms", "whatsapp", "telegram", "support", "customer care",
    "helpline", "agent", "suspicious", "prize", "lottery", "gift", "reward", "sent me",
    "invest", "job", "buyer", "seller", "request", "collect", "install", "app", "blocked",
    "suspend", "paynest", "balance", "credited", "debited", "transfer", "send", "receive",
    "aadhaar", "pan", "sender", "stranger", "code",
]
_SCOPE_RE = re.compile("|".join(re.escape(t) for t in _SCOPE_TERMS), re.I)


@dataclass
class InputResult:
    status: str                 # ok | invalid | injection | harmful | off_topic
    clean_query: str = ""
    sensitive_found: bool = False
    reasons: list = field(default_factory=list)


def check_input(query: Optional[str]) -> InputResult:
    if query is None or not query.strip():
        return InputResult("invalid", reasons=["empty query"])
    q = query.strip()
    if len(q) > MAX_QUERY_CHARS:
        q = q[:MAX_QUERY_CHARS]
    # Safety rules run on the original text first, then redaction protects anything downstream.
    clean, found = redact(q)
    if _INJECTION_RE.search(q):
        return InputResult("injection", clean, found, ["prompt-injection pattern"])
    if _HARM_RE.search(q):
        return InputResult("harmful", clean, found, ["request to facilitate fraud"])
    # People in distress who mention a code or card must still get help, not be blocked.
    if not _SCOPE_RE.search(clean):
        return InputResult("off_topic", clean, found, ["no payment-scam terms"])
    return InputResult("ok", clean, found)


# ---------- output guardrails (mainly for the LLM phase) ----------
_ASKS_SECRET_RE = re.compile(
    r"\b(share|send|provide|enter|tell me|give me|type|reply with|confirm|read out)\b[^.\n]{0,40}"
    r"\b(your|the)\b[^.\n]{0,15}\b(otp|pin|password|cvv|card number|passcode)\b",
    re.I,
)
# A sentence that warns or tells the user what to do after a leak is not a request for the secret.
_SAFE_CONTEXT_RE = re.compile(
    r"\b(never|do not|don't|dont|not|no one|nobody|should not|must not|change|reset|block|report|"
    r"already|if you|always sends|without)\b",
    re.I,
)
_SENT_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n+")
_URL_RE = re.compile(r"https?://|www\.", re.I)
_PHONE_OUT_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\- ]{7,}\d)(?!\d)")
_FORBIDDEN_CLAIMS_RE = re.compile(r"\b(guarantee|100% (safe|secure)|will definitely recover)\b", re.I)

# The only real-world contacts an answer may mention. They come from official sources listed in
# data/knowledge_base.json ("sources"). Anything else that looks like a domain or helpline number is
# treated as possibly invented and blocked.
VERIFIED_CONTACTS = {"cybercrime.gov.in", "1930"}
_DOMAIN_RE = re.compile(
    r"\b[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)*\.(?:com|in|org|net|gov|co|io|app|info|xyz|me)\b", re.I
)
_HELPLINE_RE = re.compile(
    r"\b(?:call|dial|helpline|toll[- ]free)\b[^.\n]{0,25}?(?<!\d)(\d{3,12})(?!\d)", re.I
)


@dataclass
class OutputResult:
    ok: bool
    reasons: list = field(default_factory=list)


def check_output(text: str) -> OutputResult:
    reasons = []
    for sent in _SENT_SPLIT_RE.split(text):
        if _ASKS_SECRET_RE.search(sent) and not _SAFE_CONTEXT_RE.search(sent):
            reasons.append("asks user for a secret")
            break
    if _URL_RE.search(text):
        reasons.append("contains a URL (could be invented)")
    if _PHONE_OUT_RE.search(text):
        reasons.append("contains a phone number (could be invented)")
    if any(m.group(0).lower() not in VERIFIED_CONTACTS for m in _DOMAIN_RE.finditer(text)):
        reasons.append("contains an unverified website (could be invented)")
    if any(m.group(1) not in VERIFIED_CONTACTS for m in _HELPLINE_RE.finditer(text)):
        reasons.append("contains an unverified helpline number (could be invented)")
    if _FORBIDDEN_CLAIMS_RE.search(text):
        reasons.append("makes an unverifiable guarantee")
    return OutputResult(not reasons, reasons)
