"""같은 학생의 민원끼리 내용이 얼마나 비슷한지 0~1 수치로 나타낸다.

LLM이 있으면 같은 쌍을 여러 번(samples) 물어 중앙값을 쓰고, 없거나 실패하면 낱말 겹침(자카드)으로 계산한다.
임계값(기본 0.8)은 임의 시작값이다. LLM 점수와 낱말 겹침은 척도가 달라서, LLM 없이는 0.8을 넘기는 쌍이 드물다."""
from statistics import median

from .llm import parse_json
from .retriever import tokenize

SYSTEM = ("두 학교 민원이 같은 요구·사안을 반복한 것인지 0~100점으로 평가한다. "
          "100은 표현만 다른 같은 민원, 0은 전혀 다른 민원이다. 새로운 사실이나 새 요구가 들어 있으면 점수를 낮춘다. "
          'JSON으로만 답한다: {"score": 0~100}')


def lexical(a: str, b: str) -> float:
    A, B = set(tokenize(a)), set(tokenize(b))
    return len(A & B) / len(A | B) if A and B else 0.0


def score(llm, a: str, b: str, samples: int = 3) -> tuple[float, str]:
    """(유사도 0~1, 방식 'llm'|'lexical'). LLM 응답이 하나도 쓸 수 없으면 낱말 겹침으로 대신한다."""
    if llm.available:
        vals = []
        for _ in range(max(1, samples)):
            try:
                v = float(parse_json(llm.chat(SYSTEM, f"[민원 A]\n{a}\n\n[민원 B]\n{b}", json_mode=True)).get("score"))
                if 0 <= v <= 100:
                    vals.append(v / 100)
            except Exception:  # noqa: BLE001
                continue
        if vals:
            return round(median(vals), 2), "llm"
    return round(lexical(a, b), 2), "lexical"
