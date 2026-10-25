"""Phase 2: retrieval-only chatbot. No generative AI, no network, no API key.

Method: TF-IDF (word + character n-grams) over each entry's example queries and keywords,
cosine similarity, then two safety checks before an answer is returned:
  * absolute threshold  - the best match must be similar enough
  * margin              - the best match must clearly beat the runner-up
Otherwise the approved fallback is returned. Every answer is pre-approved text from the KB.
"""
from dataclasses import dataclass
import re
import numpy as np
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# Chosen from a threshold sweep (see eval/sweep.py); 0.18/0.02 gave no wrong answers on the dev set. Raise to be safer, lower to answer more.
DEFAULT_THRESHOLD = 0.18
DEFAULT_MARGIN = 0.02
KEYWORD_WEIGHT = 0.12   # bonus for domain keywords found in the query (long queries dilute TF-IDF cosine)


@dataclass
class Match:
    entry_id: str | None
    score: float
    margin: float
    answered: bool


class Retriever:
    def __init__(self, kb: dict, threshold: float = DEFAULT_THRESHOLD, margin: float = DEFAULT_MARGIN,
                 keyword_weight: float = KEYWORD_WEIGHT):
        self.kb = kb
        self.keyword_weight = keyword_weight
        self.kw_res = {e['id']: [re.compile(r'\b' + re.escape(k.lower()) + r'\w*') for k in e['keywords']]
                       for e in kb['entries']}
        self.threshold = threshold
        self.margin = margin
        self.docs, self.doc_entry = [], []
        for e in kb["entries"]:
            for q in e["example_queries"]:
                self.docs.append(q)
                self.doc_entry.append(e["id"])
            # one extra doc made of the keywords, so short keyword-style queries still match
            self.docs.append(" ".join(e["keywords"]))
            self.doc_entry.append(e["id"])
        self.ids = [e["id"] for e in kb["entries"]]
        self.word = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, lowercase=True)
        self.char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, lowercase=True)
        self.X = hstack([self.word.fit_transform(self.docs), self.char.fit_transform(self.docs)]).tocsr()

    def _scores(self, query: str) -> dict:
        qv = hstack([self.word.transform([query]), self.char.transform([query])]).tocsr()
        sims = cosine_similarity(qv, self.X)[0] / 2.0  # two blocks, each L2-normalised -> rescale to 0..1
        best = {i: 0.0 for i in self.ids}
        for s, eid in zip(sims, self.doc_entry):
            if s > best[eid]:
                best[eid] = float(s)
        q = query.lower()
        for eid, pats in self.kw_res.items():
            hits = sum(1 for p in pats if p.search(q))
            best[eid] += self.keyword_weight * min(hits, 4) / 4
        return best

    def search(self, query: str) -> Match:
        best = self._scores(query)
        ranked = sorted(best.items(), key=lambda kv: kv[1], reverse=True)
        (top_id, top), (_, second) = ranked[0], ranked[1]
        margin = top - second
        answered = top >= self.threshold and margin >= self.margin
        return Match(top_id if answered else None, round(top, 4), round(margin, 4), answered)

    def answer(self, match: Match) -> str:
        if not match.answered:
            return self.kb["fallback_answer"]
        return self.kb["by_id"][match.entry_id]["answer"]
