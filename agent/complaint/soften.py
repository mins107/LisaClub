"""민원 원문 순화. 담당자가 폭언·욕설·협박 표현을 그대로 읽지 않도록, 화면에는 순화문을 먼저 보여 주고 원문은 [원문 보기]에서만 보여 준다.

- LLM이 있으면 요구 사항·사실관계는 그대로 두고 거친 표현만 중립적인 말로 바꾼다. 결과가 이상하면(비었거나 길이가 크게 다르거나
  거친 표현이 남아 있으면) 버리고 규칙 방식으로 대신한다.
- LLM이 없거나 실패하면 규칙으로 감지된 거친 표현(폭언·모욕·협박·성희롱·폭행)만 '[부적절한 표현]'으로 가리고 나머지는 그대로 둔다.
순화문은 보기 편하라고 만든 것이며 판정(분류·근거·이력)은 항상 원문으로 한다.
"""
from . import rules as R

MASK = "[부적절한 표현]"
MASK_KEYS = {"abuse", "insult", "threat", "sexual", "assault"}      # 가릴 유형(폭언·모욕·협박·성희롱·폭행 표현)
SENTENCE_KEYS = {"threat", "sexual", "assault"}      # 이 유형은 감지된 말만 가리면 뒷부분이 남아서 문장 끝까지 가린다
METHOD_LABEL = {"llm": "AI가 거친 표현을 다듬은 내용", "rules": "거친 표현만 규칙으로 가린 내용(AI 순화 아님)",
                "none": "거친 표현이 감지되지 않아 원문과 같은 내용"}
WORD_STOP = " \t\r\n.!?。,"
SENTENCE_STOP = ".!?。\n"


def _extend(text, end, to_sentence):
    """감지된 표현이 단어·문장 중간에서 끝나면 그 단어(또는 문장) 끝까지 늘린다('가만 안' + ' 둔다')."""
    stop = SENTENCE_STOP if to_sentence else WORD_STOP
    while end < len(text) and text[end] not in stop:
        end += 1
    return end


def mask_rough(text):
    """규칙으로 감지된 거친 표현을 MASK로 바꾼다. 반환: (바꾼 글, 바꾼 개수)."""
    spans = []
    for rule, sp, _ in R.detect_malicious(text):
        if rule.key in MASK_KEYS:
            spans += [(a, _extend(text, b, rule.key in SENTENCE_KEYS)) for a, b in sp]
    merged = []
    for a, b in sorted(spans):
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(b, merged[-1][1]))
        else:
            merged.append((a, b))
    out, pos = [], 0
    for a, b in merged:
        out += [text[pos:a], MASK]
        pos = b
    out.append(text[pos:])
    return "".join(out), len(merged)


def _llm_soften(llm, text):
    system = ("학교 민원 원문을 민원 담당자가 읽기 편하도록 순화한다. 욕설·비난·협박·모욕 같은 거친 표현은 중립적이고 정중한 말로 바꾼다. "
              "요구 사항, 사실관계, 날짜, 이름, 숫자는 그대로 두고 새로운 사실이나 판단을 덧붙이지 않는다. 폭언·협박이 있었으면 문장 끝에 "
              "'(거친 표현이 있었음)' 정도로만 표시한다. 한국어로 순화한 글만 출력한다.")
    return (llm.chat(system, text) or "").strip()


def soften(llm, text):
    """반환: (순화문, 방식). 방식: 'llm' / 'rules'(거친 표현만 가림) / 'none'(거친 표현이 없어 원문과 같음)."""
    masked, n = mask_rough(text)
    if llm is not None and getattr(llm, "available", False) and text.strip():
        try:
            out = _llm_soften(llm, text)
            if out and 0.3 * len(text) <= len(out) <= 3 * len(text) + 40:
                return mask_rough(out)[0], "llm"      # 순화문에도 거친 표현이 남아 있으면 마저 가린다
        except Exception:  # noqa: BLE001
            pass
    return masked, ("rules" if n else "none")
