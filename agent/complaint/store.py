"""민원 이력 DB(sqlite). 같은 민원인의 동일·유사 민원 반복 횟수를 센다."""
import os
import sqlite3
from datetime import datetime, timezone

from .retriever import tokenize


def _jaccard(a: str, b: str) -> float:
    A, B = set(tokenize(a)), set(tokenize(b))
    return len(A & B) / len(A | B) if A and B else 0.0


class Store:
    def __init__(self, path=":memory:"):
        if path != ":memory:":
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS complaints(id INTEGER PRIMARY KEY, complainant TEXT,"
            " text TEXT, created TEXT, route TEXT)")

    def similar_prior(self, complainant: str, text: str, threshold: float = 0.3):
        rows = self.db.execute(
            "SELECT id, text, route FROM complaints WHERE complainant=?", (complainant,)).fetchall()
        return [r for r in rows if _jaccard(r[1], text) >= threshold]

    def add(self, complainant: str, text: str, route: str):
        self.db.execute("INSERT INTO complaints(complainant,text,created,route) VALUES(?,?,?,?)",
                        (complainant, text, datetime.now(timezone.utc).isoformat(), route))
        self.db.commit()
