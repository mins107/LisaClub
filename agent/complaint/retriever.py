"""BM25(한글 2-gram) + 선택적 밀집 임베딩(bge-m3 등) 하이브리드 검색."""
import re

import numpy as np
from rank_bm25 import BM25Okapi

_WORD = re.compile(r"[가-힣]+|[A-Za-z0-9]+")


def tokenize(text: str) -> list:
    out = []
    for w in _WORD.findall(text.lower()):
        if "가" <= w[0] <= "힣":
            out += [w] if len(w) == 1 else [w[i:i + 2] for i in range(len(w) - 1)]
        else:
            out.append(w)
    return out


class Retriever:
    def __init__(self, evidences, embed_fn=None):
        self.ev = evidences
        self.bm25 = BM25Okapi([tokenize(e.text) or ["_"] for e in evidences])
        self.embed_fn = embed_fn
        self.mat = None
        if embed_fn is not None:
            m = np.asarray(embed_fn([e.text for e in evidences]), dtype=float)
            self.mat = m / (np.linalg.norm(m, axis=1, keepdims=True) + 1e-9)

    def search(self, query: str, k: int = 3):
        s = np.asarray(self.bm25.get_scores(tokenize(query) or ["_"]))
        order = np.argsort(-s)
        if self.mat is None:
            return [(self.ev[i], float(s[i])) for i in order[:k] if s[i] > 0]
        q = np.asarray(self.embed_fn([query]), dtype=float)[0]
        q = q / (np.linalg.norm(q) + 1e-9)
        d = self.mat @ q
        rank = {}
        for r, i in enumerate(order[:50]):
            rank[i] = rank.get(i, 0) + 1 / (60 + r)
        for r, i in enumerate(np.argsort(-d)[:50]):
            rank[i] = rank.get(i, 0) + 1 / (60 + r)
        top = sorted(rank, key=rank.get, reverse=True)[:k]
        return [(self.ev[i], float(rank[i])) for i in top]
