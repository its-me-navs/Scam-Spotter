"""Language support: English, Hindi (Devanagari) and Kannada.

Detection is by script, not by a model, so it is deterministic and works offline:
  * any Devanagari letters  -> Hindi
  * any Kannada letters     -> Kannada
  * otherwise               -> English

Limitation: Hindi or Kannada typed in Roman letters ("Hinglish") is detected as English.
For that, pick the reply language by hand (the UI has a selector; code can pass lang="hi" / "kn").
"""
import re
import unicodedata

EN, HI, KN = "en", "hi", "kn"
LANGUAGES = (EN, HI, KN)
LANG_NAMES = {EN: "English", HI: "Hindi", KN: "Kannada"}
LANG_LABELS = {EN: "English", HI: "हिन्दी (Hindi)", KN: "ಕನ್ನಡ (Kannada)"}

_DEVANAGARI = re.compile(r"[ऀ-ॿ]")
_KANNADA = re.compile(r"[ಀ-೿]")

# Devanagari digits U+0966..096F and Kannada digits U+0CE6..0CEF -> ASCII digits (1:1, same length)
_DIGITS = str.maketrans({chr(base + i): str(i) for base in (0x966, 0xCE6) for i in range(10)})
# For matching only: drop zero-width joiners, drop the Hindi nukta, unify chandrabindu with anusvara
_FOLD = str.maketrans({"‌": None, "‍": None, "़": None, "ँ": "ं"})

_TOKEN = re.compile(r"[a-z0-9ऀ-ॣ०-ॿಀ-೿]+")


def detect_language(text: str) -> str:
    dev = len(_DEVANAGARI.findall(text or ""))
    kan = len(_KANNADA.findall(text or ""))
    if dev == 0 and kan == 0:
        return EN
    return HI if dev >= kan else KN


def normalize_digits(text: str) -> str:
    """Indic digits to ASCII. Same length as the input, so it is safe to use on text shown back to the user."""
    return text.translate(_DIGITS)


def fold(text: str) -> str:
    """Normalise text for matching only (not for display)."""
    return unicodedata.normalize("NFC", normalize_digits(text)).translate(_FOLD)


def tokenize(text: str) -> list:
    """Lower-case word tokens that keep Hindi and Kannada vowel signs attached to their letters."""
    return _TOKEN.findall(fold(text).lower())


def script_ratio(text: str, lang: str) -> float:
    """Share of letters that are in the script of `lang` (Latin acronyms and domains count against it)."""
    if lang == HI:
        pat = _DEVANAGARI
    elif lang == KN:
        pat = _KANNADA
    else:
        return 1.0
    own = len(pat.findall(text))
    latin = len(re.findall(r"[A-Za-z]", text))
    return own / (own + latin) if (own + latin) else 0.0
