"""Shared guardrail layer used by ALL phases and ALL languages (English, Hindi, Kannada).

Input side:  validate -> detect language -> redact sensitive data -> detect injection ->
             detect harmful requests -> scope check.
Output side: block unsafe model output (asks for secrets, invented contact details/links,
             reply not in the requested language).

Every input check also records a short, human-readable step (InputResult.trace), so the UI can show
what the guardrails did, in order, for each message.

Keyword/regex rules are deliberately simple and are NOT a complete defence. Hindi and Kannada rules cover
common phrasings only. The evaluation harness exists to measure where they fail.
"""
import re
from dataclasses import dataclass, field
from typing import Optional

from .language import EN, HI, KN, LANG_NAMES, detect_language, fold, normalize_digits, script_ratio

MAX_QUERY_CHARS = 1000


@dataclass
class TraceStep:
    status: str      # ok | info | warn | block
    text: str


# ---------- sensitive data (redacted before anything reaches an LLM or a log) ----------
_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_CODE_WORDS = (
    r"(?:\b(?:otp|code|pin|cvv|password|passcode)\b"
    r"|ओटीपी|पिन|पासवर्ड|कोड|सीवीवी"
    r"|ಒಟಿಪಿ|ಪಿನ್|ಪಾಸ್‌?ವರ್ಡ್|ಕೋಡ್|ಸಿವಿವಿ)"
)
_OTP_RE = re.compile(_CODE_WORDS + r"[^0-9]{0,25}(\d{3,8})(?!\d)", re.I)
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[- ]?)?[6-9]\d{9}(?!\d)")


def redact_detailed(text: str) -> tuple[str, list]:
    """Replace card numbers, OTP/PIN-like codes and phone numbers (Indic digits are converted first).
    Returns (clean_text, kinds_found). The values themselves are never returned."""
    text = normalize_digits(text)
    kinds = []

    def _sub(pattern, repl, s, kind):
        new, n = pattern.subn(repl, s)
        if n and kind not in kinds:
            kinds.append(kind)
        return new

    text = _sub(_CARD_RE, "[CARD]", text, "card number")
    text = _sub(_PHONE_RE, "[PHONE]", text, "phone number")

    def _code(m):
        if "OTP / PIN / code" not in kinds:
            kinds.append("OTP / PIN / code")
        return m.group(0).replace(m.group(1), "[CODE]")

    text = _OTP_RE.sub(_code, text)
    return text, kinds


def redact(text: str) -> tuple[str, bool]:
    """Like redact_detailed, but returns (clean, found)."""
    clean, kinds = redact_detailed(text)
    return clean, bool(kinds)


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

# Hindi / Kannada patterns. Written in "folded" form (no nukta, no zero-width joiners); they are matched
# against fold(text), see language.fold.
_INJECTION_INDIC_PATTERNS = [
    # Hindi
    r"(पिछले|पिछली|ऊपर के|पहले के|सभी|सारे|अपने|तुम्हारे|आपके)\s*(सभी\s*)?(निर्देश|नियम|आदेश|प्रॉम्प्ट|प्रोम्प्ट)\S*\s*(को\s*)?"
    r"(अनदेख|नजरअंदाज|भूल|हटा|बंद|बताओ|बताएं|बताइए|दिखाओ|दिखाएं|प्रिंट)",
    r"सिस्टम\s*प्रॉम्प्ट|सिस्टम\s*प्रोम्प्ट|छिपे\s*(हुए\s*)?निर्देश|गुप्त\s*(निर्देश|सेटिंग)|छिपी\s*(हुई\s*)?सेटिंग",
    r"डेवलपर\s*मोड|जेलब्रेक",
    r"(सुरक्षा|सेफ्टी)\s*(नियम|फिल्टर|गार्डरेल)\S*\s*(को\s*)?(बंद|हटा|अक्षम|निष्क्रिय)",
    r"बिना\s*(किसी\s*)?(नियम|प्रतिबंध|रोक)",
    # Kannada
    r"(ಹಿಂದಿನ|ಮೇಲಿನ|ಎಲ್ಲಾ|ಎಲ್ಲ|ನಿಮ್ಮ|ನಿನ್ನ)\s*(ಎಲ್ಲಾ\s*)?(ಸೂಚನೆ|ನಿಯಮ|ಆದೇಶ|ಪ್ರಾಂಪ್ಟ್)\S*\s*(ಅನ್ನು\s*)?"
    r"(ನಿರ್ಲಕ್ಷಿಸ|ಮರೆತು\s*ಬಿಡ|ಮರೆತುಬಿಡ|ತೆಗೆದುಹಾಕ|ತೋರಿಸ|ಹೇಳ|ಬಹಿರಂಗ|ಪ್ರಿಂಟ್)",
    r"ಸಿಸ್ಟಮ್\s*ಪ್ರಾಂಪ್ಟ್|(ಗುಪ್ತ|ರಹಸ್ಯ)\s*(ಸೂಚನೆ|ಸೆಟ್ಟಿಂಗ್)|ಡೆವಲಪರ್\s*ಮೋಡ್|ಜೈಲ್ಬ್ರೇಕ್",
    r"(ಸುರಕ್ಷತಾ|ಸೇಫ್ಟಿ)\s*(ನಿಯಮ|ಫಿಲ್ಟರ್|ಗಾರ್ಡ್ರೇಲ್)\S*\s*(ಅನ್ನು\s*)?(ಆಫ್|ತೆಗೆದುಹಾಕ|ನಿಷ್ಕ್ರಿಯ|ಬಂದ್)",
    r"ಯಾವುದೇ\s*(ನಿಯಮ|ನಿರ್ಬಂಧ)\S*?\s*(ಗಳಿಲ್ಲದೆ|ಇಲ್ಲದೆ)",
]
_INJECTION_INDIC_RE = re.compile("|".join(fold(p) for p in _INJECTION_INDIC_PATTERNS))

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
# These target requests to do harm. Phrases a victim would use ("my account got hacked") must NOT match.
_HARM_INDIC_PATTERNS = [
    # Hindi
    r"हैक\s*कैसे|हैक\s*कर(ना|ने)\s*(का|की|के)?\s*(तरीका|तरीके|विधि)|हैक\s*करना\s*(है|चाहता|चाहती|सिखा)",
    r"(चुराने|निकलवाने|हासिल\s*करने)\s*(का|के)\s*(तरीका|तरीके|उपाय)",
    r"(लोगों|किसी|दूसरों)\s*(को|से)?\s*(ठगने|धोखा\s*देने|बेवकूफ\s*बनाने)\s*(का|के)?\s*(तरीका|तरीके|कैसे)",
    r"(नकली|फर्जी|फिशिंग).{0,30}(kyc|केवाईसी|मैसेज|संदेश|एसएमएस|लिंक|वेबसाइट|पेज|साइट)"
    r".{0,30}(बनाओ|बनाएं|बना\s*दो|लिखो|लिखें|लिख\s*दो|तैयार\s*करो|तैयार\s*करें)",
    # Kannada
    r"ಹ್ಯಾಕ್\s*ಮಾಡುವುದು\s*ಹೇಗೆ|ಹ್ಯಾಕ್\s*ಮಾಡಲು\s*(ಹೇಗೆ|ಮಾರ್ಗ|ವಿಧಾನ)",
    r"(ಇತರರ|ಬೇರೆಯವರ|ಯಾರದೋ)\s*(ಖಾತೆ|ವ್ಯಾಲೆಟ್|ಫೋನ್).{0,15}ಹ್ಯಾಕ್\s*ಮಾಡ(ು|ಲು)",
    r"(ಜನರನ್ನು|ಇತರರನ್ನು|ಜನರಿಗೆ)\s*(ಮೋಸ|ವಂಚಿಸ|ಮೋಸಗೊಳಿಸ).{0,20}(ಹೇಗೆ|ವಿಧಾನ|ಮಾರ್ಗ)",
    r"ಖಾತೆ\s*ಖಾಲಿ\s*ಮಾಡಲು",
    r"(otp|ಒಟಿಪಿ|ಪಿನ್|ಪಾಸ್ವರ್ಡ್).{0,20}(ಕದಿಯ|ಪಡೆಯುವ|ಹೊರತೆಗೆಯುವ).{0,15}(ಹೇಗೆ|ವಿಧಾನ|ಮಾರ್ಗ)",
    r"(ನಕಲಿ|ಫಿಶಿಂಗ್).{0,30}(kyc|ಸಂದೇಶ|ಮೆಸೇಜ್|ಲಿಂಕ್|ವೆಬ್ಸೈಟ್|ಪುಟ).{0,30}"
    r"(ಬರೆಯಿರಿ|ಬರೆದುಕೊಡಿ|ಬರೆಯುವುದು|ರಚಿಸಿ|ತಯಾರಿಸಿ|ಮಾಡಿಕೊಡಿ|ಮಾಡಿ\s*ಕೊಡಿ|ಮಾಡುವುದು|ಮಾಡಲು)",
]
_HARM_INDIC_RE = re.compile("|".join(fold(p) for p in _HARM_INDIC_PATTERNS), re.I)

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
    "police", "arrest", "cbi", "customs", "narcotics", "parcel", "courier", "warrant", "officer",
    "relative", "family", "accident", "hospital", "deepfake", "voice", "video call", "emergency",
]
_SCOPE_TERMS_HI = [
    "स्कैम", "धोखा", "ठग", "फ्रॉड", "फर्जी", "नकली", "ओटीपी", "पिन", "पासवर्ड", "केवाईसी", "रिफंड", "कैशबैक",
    "लिंक", "यूपीआई", "क्यूआर", "स्कैन", "पेमेंट", "भुगतान", "पैसे", "पैसा", "रुपय", "रुपए", "वॉलेट", "अकाउंट",
    "खाता", "खाते", "ट्रांजैक्शन", "लेनदेन", "कट गए", "कटे", "बैंक", "कार्ड", "कॉल", "फोन", "मैसेज", "संदेश",
    "एसएमएस", "व्हाट्सएप", "टेलीग्राम", "सपोर्ट", "कस्टमर केयर", "हेल्पलाइन", "लॉटरी", "इनाम", "पुरस्कार",
    "गिफ्ट", "निवेश", "नौकरी", "जॉब", "खरीदार", "अरेस्ट", "गिरफ्तार", "पुलिस", "सीबीआई", "पार्सल", "कूरियर",
    "ऐप", "ब्लॉक", "क्लिक", "इंस्टॉल", "आधार", "पैन", "अस्पताल", "एक्सीडेंट", "दुर्घटना", "आवाज", "डीपफेक",
    "रिश्तेदार", "वीडियो कॉल", "इमरजेंसी", "कोड", "बैलेंस", "ट्रांसफर",
]
_SCOPE_TERMS_KN = [
    "ಸ್ಕ್ಯಾಮ್", "ವಂಚನೆ", "ಮೋಸ", "ನಕಲಿ", "ಫ್ರಾಡ್", "ಒಟಿಪಿ", "ಪಿನ್", "ಪಾಸ್ವರ್ಡ್", "ಕೆವೈಸಿ", "ರೀಫಂಡ್",
    "ಕ್ಯಾಶ್ಬ್ಯಾಕ್", "ಲಿಂಕ್", "ಯುಪಿಐ", "ಕ್ಯೂಆರ್", "ಸ್ಕ್ಯಾನ್", "ಪಾವತಿ", "ಹಣ", "ರೂಪಾಯಿ", "ವ್ಯಾಲೆಟ್", "ಖಾತೆ",
    "ವಹಿವಾಟು", "ಕಡಿತ", "ಬ್ಯಾಂಕ್", "ಕಾರ್ಡ್", "ಕರೆ", "ಫೋನ್", "ಸಂದೇಶ", "ಮೆಸೇಜ್", "ಎಸ್ಎಂಎಸ್", "ವಾಟ್ಸಾಪ್",
    "ಟೆಲಿಗ್ರಾಮ್", "ಸಪೋರ್ಟ್", "ಬೆಂಬಲ", "ಗ್ರಾಹಕ ಸೇವೆ", "ಗ್ರಾಹಕ ಸೇವಾ", "ಸಹಾಯವಾಣಿ", "ಲಾಟರಿ", "ಬಹುಮಾನ",
    "ಉಡುಗೊರೆ", "ಹೂಡಿಕೆ", "ಉದ್ಯೋಗ", "ಕೆಲಸ", "ಖರೀದಿದಾರ", "ಅರೆಸ್ಟ್", "ಬಂಧನ", "ಪೊಲೀಸ್", "ಸಿಬಿಐ", "ಪಾರ್ಸೆಲ್",
    "ಕೊರಿಯರ್", "ಆ್ಯಪ್", "ಬ್ಲಾಕ್", "ಕ್ಲಿಕ್", "ಇನ್ಸ್ಟಾಲ್", "ಆಧಾರ್", "ಪ್ಯಾನ್", "ಆಸ್ಪತ್ರೆ", "ಅಪಘಾತ", "ಧ್ವನಿ",
    "ಡೀಪ್ಫೇಕ್", "ಸಂಬಂಧಿಕ", "ವೀಡಿಯೊ ಕರೆ", "ತುರ್ತು", "ಕೋಡ್", "ಬ್ಯಾಲೆನ್ಸ್", "ವರ್ಗಾವಣೆ",
]
_SCOPE_RE = re.compile(
    "|".join(re.escape(fold(t)) for t in _SCOPE_TERMS + _SCOPE_TERMS_HI + _SCOPE_TERMS_KN), re.I)


@dataclass
class InputResult:
    status: str                 # ok | invalid | injection | harmful | off_topic
    clean_query: str = ""
    sensitive_found: bool = False
    reasons: list = field(default_factory=list)
    lang: str = EN
    sensitive_kinds: list = field(default_factory=list)
    trace: list = field(default_factory=list)      # list[TraceStep], in the order the checks ran


def check_input(query: Optional[str], lang: Optional[str] = None) -> InputResult:
    """Run the input guardrails. `lang` forces the reply language; None detects it from the script."""
    if query is None or not query.strip():
        return InputResult("invalid", reasons=["empty query"], lang=lang or EN,
                           trace=[TraceStep("block", "Your message is empty")])
    q = query.strip()
    if len(q) > MAX_QUERY_CHARS:
        q = q[:MAX_QUERY_CHARS]
    trace = [TraceStep("ok", f"Received your message ({len(q)} characters)")]

    detected = detect_language(q)
    used = lang or detected
    how = "chosen by you" if lang and lang != detected else "detected from the script"
    trace.append(TraceStep("info", f"Language: {LANG_NAMES[used]} ({how})"))

    # Safety rules run on the original text first, then redaction protects anything downstream.
    clean, kinds = redact_detailed(q)
    if kinds:
        trace.append(TraceStep(
            "warn", "Sensitive data found (" + ", ".join(kinds) + "). Replaced with a placeholder before "
                    "anything else sees it. The real value is not stored or sent"))
    else:
        trace.append(TraceStep("ok", "Sensitive-data check: nothing to remove"))

    m = fold(q)
    if _INJECTION_RE.search(m) or _INJECTION_INDIC_RE.search(m):
        trace.append(TraceStep("block", "Prompt-injection check: this looks like an attempt to change my rules"))
        return InputResult("injection", clean, bool(kinds), ["prompt-injection pattern"], used, kinds, trace)
    trace.append(TraceStep("ok", "Prompt-injection check: passed"))

    if _HARM_RE.search(m) or _HARM_INDIC_RE.search(m):
        trace.append(TraceStep("block", "Harmful-request check: this asks for help to commit fraud"))
        return InputResult("harmful", clean, bool(kinds), ["request to facilitate fraud"], used, kinds, trace)
    trace.append(TraceStep("ok", "Harmful-request check: passed"))

    # People in distress who mention a code or card must still get help, not be blocked.
    if not _SCOPE_RE.search(fold(clean)):
        trace.append(TraceStep("block", "Scope check: this is not about a payment scam"))
        return InputResult("off_topic", clean, bool(kinds), ["no payment-scam terms"], used, kinds, trace)
    trace.append(TraceStep("ok", "Scope check: about payments or scams"))
    return InputResult("ok", clean, bool(kinds), [], used, kinds, trace)


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
_SENT_SPLIT_RE = re.compile(r"(?<=[.!?।])\s+|\n+")
_TOKEN_SPLIT_RE = re.compile(r"[\s,;:()\[\]\"'।.!?/\-–—]+")
_URL_RE = re.compile(r"https?://|www\.", re.I)
_PHONE_OUT_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\- ]{7,}\d)(?!\d)")
_FORBIDDEN_CLAIMS_RE = re.compile(r"\b(guarantee|100% (safe|secure)|will definitely recover)\b", re.I)

# The only real-world contacts an answer may mention. They come from official sources listed in
# data/knowledge_base.json ("sources"). Anything else that looks like a domain or helpline number is
# treated as possibly invented and blocked.
VERIFIED_CONTACTS = {"cybercrime.gov.in", "sancharsaathi.gov.in", "1930"}
_DOMAIN_RE = re.compile(
    r"\b[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)*\.(?:com|in|org|net|gov|co|io|app|info|xyz|me)\b", re.I
)
_HELPLINE_RE = re.compile(
    r"(?:\b(?:call|dial|helpline|toll[- ]free)\b|हेल्पलाइन|डायल|कॉल|ಸಹಾಯವಾಣಿ|ಡಯಲ್|ಕರೆ)"
    r"[^.\n]{0,25}?(?<!\d)(\d{3,12})(?!\d)", re.I
)

# Hindi / Kannada: does a sentence ask the user to hand over OTP / PIN / password / CVV?
_SECRET_TERM_RE = re.compile(
    r"\b(?:otp|pin|password|cvv)\b|" + "|".join(fold(t) for t in (
        "ओटीपी", "पिन", "पासवर्ड", "सीवीवी", "ಒಟಿಪಿ", "ಪಿನ್", "ಪಾಸ್ವರ್ಡ್", "ಸಿವಿವಿ")), re.I)
_REQUEST_TOKENS = {fold(t) for t in (
    # Hindi imperatives
    "बताएं", "बताइए", "बताओ", "भेजें", "भेजिए", "भेजो", "दें", "दीजिए", "दो", "दर्ज", "डालें", "डालिए",
    "डालो", "साझा", "शेयर", "सुनाएं", "बोलें", "भरें",
    # Kannada imperatives
    "ನಮೂದಿಸಿ", "ಹಂಚಿಕೊಳ್ಳಿ", "ಕೊಡಿ", "ನೀಡಿ", "ಹೇಳಿ", "ಕಳುಹಿಸಿ", "ತಿಳಿಸಿ", "ಬರೆಯಿರಿ", "ಓದಿ", "ಹೇಳು", "ಕೊಡು",
    "ಕಳುಹಿಸು")}
_SAFE_TOKENS = {fold(t) for t in ("न", "नहीं", "नही", "मत", "कभी", "ना", "अगर", "यदि", "पहले", "चुके", "चुकी", "चुका")}
_SAFE_PREFIXES = tuple(fold(t) for t in ("बदल", "रिपोर्ट", "ब्लॉक", "सूचित"))
_SAFE_SUBSTRINGS = tuple(fold(t) for t in (
    "ಬೇಡ", "ಎಂದಿಗೂ", "ಬಾರದು", "ಇಲ್ಲ", "ಈಗಾಗಲೇ", "ಬದಲಾಯಿಸಿ", "ವರದಿ", "ಬ್ಲಾಕ್", "ಒಂದು ವೇಳೆ"))


def _asks_secret_indic(sentence: str) -> bool:
    f = fold(sentence)
    if not _SECRET_TERM_RE.search(f):
        return False
    tokens = [t for t in _TOKEN_SPLIT_RE.split(f) if t]
    if not any(t in _REQUEST_TOKENS for t in tokens):
        return False
    if any(t in _SAFE_TOKENS or t.startswith(_SAFE_PREFIXES) for t in tokens):
        return False
    if any(s in f for s in _SAFE_SUBSTRINGS):
        return False
    return True


@dataclass
class OutputResult:
    ok: bool
    reasons: list = field(default_factory=list)


def check_output(text: str, lang: str = EN) -> OutputResult:
    """Validate a reply before it is shown. All checks run for every language; `lang` also requires the
    reply to be mostly in that language's script."""
    t = normalize_digits(text)
    reasons = []
    for sent in _SENT_SPLIT_RE.split(t):
        if (_ASKS_SECRET_RE.search(sent) and not _SAFE_CONTEXT_RE.search(sent)) or _asks_secret_indic(sent):
            reasons.append("asks user for a secret")
            break
    if _URL_RE.search(t):
        reasons.append("contains a URL (could be invented)")
    if _PHONE_OUT_RE.search(t):
        reasons.append("contains a phone number (could be invented)")
    if any(m.group(0).lower() not in VERIFIED_CONTACTS for m in _DOMAIN_RE.finditer(t)):
        reasons.append("contains an unverified website (could be invented)")
    if any(m.group(1) not in VERIFIED_CONTACTS for m in _HELPLINE_RE.finditer(t)):
        reasons.append("contains an unverified helpline number (could be invented)")
    if _FORBIDDEN_CLAIMS_RE.search(t):
        reasons.append("makes an unverifiable guarantee")
    if lang in (HI, KN) and script_ratio(t, lang) < 0.4:
        reasons.append(f"reply is not in {LANG_NAMES[lang]}")
    return OutputResult(not reasons, reasons)
