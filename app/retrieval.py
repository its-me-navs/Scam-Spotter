"""Phase 2: retrieval-only chatbot. No generative AI, no network, no API key.

Method: TF-IDF (word + character n-grams) over each entry's example queries and keywords,
cosine similarity, then two safety checks before an answer is returned:
  * absolute threshold  - the best match must be similar enough
  * margin              - the best match must clearly beat the runner-up
Otherwise the approved fallback is returned. Every answer is pre-approved text from the KB.

Languages: there is one separate index per language (English, Hindi, Kannada), built from that
language's example queries and keywords. A query is routed to the index for its detected language,
so the languages never affect each other's scores.
"""
from dataclasses import dataclass
import re

from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .knowledge import entry_answer, entry_field, message
from .language import EN, LANGUAGES, detect_language, fold

# Chosen from a threshold sweep (see eval/sweep.py); 0.18/0.02 gave no wrong answers on the dev set. Raise to be safer, lower to answer more.
DEFAULT_THRESHOLD = 0.18
DEFAULT_MARGIN = 0.02
KEYWORD_WEIGHT = 0.12   # bonus for domain keywords found in the query (long queries dilute TF-IDF cosine)

# The default word tokenizer drops Hindi/Kannada vowel signs, so Indic languages get their own pattern.
_INDIC_TOKEN_PATTERN = r"[a-z0-9ऀ-ॣ०-ॿಀ-೿]{2,}"


def _prep(text: str) -> str:
    return fold(text).lower()


@dataclass
class Match:
    entry_id: str | None
    score: float
    margin: float
    answered: bool
    lang: str = EN


class _Index:
    """TF-IDF index over one language's example queries and keywords."""

    def __init__(self, kb: dict, lang: str, keyword_weight: float):
        self.lang = lang
        self.keyword_weight = keyword_weight
        self.docs, self.doc_entry, self.kw_res = [], [], {}
        for e in kb["entries"]:
            queries = entry_field(e, "example_queries", lang)
            keywords = entry_field(e, "keywords", lang)
            for q in queries:
                self.docs.append(_prep(q))
                self.doc_entry.append(e["id"])
            if keywords:  # one extra doc made of the keywords, so short keyword-style queries still match
                self.docs.append(" ".join(_prep(k) for k in keywords))
                self.doc_entry.append(e["id"])
            self.kw_res[e["id"]] = [re.compile(r"\b" + re.escape(_prep(k)) + r"\w*") for k in keywords]
        self.ids = [e["id"] for e in kb["entries"]]
        self.empty = not self.docs
        if self.empty:
            return
        word_kwargs = {} if lang == EN else {"token_pattern": _INDIC_TOKEN_PATTERN}
        self.word = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, lowercase=True, **word_kwargs)
        self.char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, lowercase=True)
        self.X = hstack([self.word.fit_transform(self.docs), self.char.fit_transform(self.docs)]).tocsr()

    def scores(self, query: str) -> dict:
        query = _prep(query)
        qv = hstack([self.word.transform([query]), self.char.transform([query])]).tocsr()
        sims = cosine_similarity(qv, self.X)[0] / 2.0  # two blocks, each L2-normalised -> rescale to 0..1
        best = {i: 0.0 for i in self.ids}
        for s, eid in zip(sims, self.doc_entry):
            if s > best[eid]:
                best[eid] = float(s)
        for eid, pats in self.kw_res.items():
            hits = sum(1 for p in pats if p.search(query))
            best[eid] += self.keyword_weight * min(hits, 4) / 4
        return best


class Retriever:
    def __init__(self, kb: dict, threshold: float = DEFAULT_THRESHOLD, margin: float = DEFAULT_MARGIN,
                 keyword_weight: float = KEYWORD_WEIGHT):
        self.kb = kb
        self.threshold = threshold
        self.margin = margin
        self.indexes = {lang: _Index(kb, lang, keyword_weight) for lang in LANGUAGES}

    def _scores(self, query: str, lang: str | None = None) -> dict:
        lang = lang or detect_language(query)
        idx = self.indexes[lang]
        return {i: 0.0 for i in idx.ids} if idx.empty else idx.scores(query)

    def search(self, query: str, lang: str | None = None) -> Match:
        lang = lang or detect_language(query)
        idx = self.indexes[lang]
        if idx.empty:                      # no data for this language: never guess
            return Match(None, 0.0, 0.0, False, lang)
        best = idx.scores(query)
        ranked = sorted(best.items(), key=lambda kv: kv[1], reverse=True)
        (top_id, top), (_, second) = ranked[0], ranked[1]
        margin = top - second
        answered = top >= self.threshold and margin >= self.margin
        return Match(top_id if answered else None, round(top, 4), round(margin, 4), answered, lang)

    def answer(self, match: Match, lang: str | None = None) -> str:
        lang = lang or match.lang
        if not match.answered:
            return message(self.kb, "fallback_answer", lang)
        return entry_answer(self.kb["by_id"][match.entry_id], lang)
