"""구조도 흐름: 민원 -> (거부 가능?) -> (악성?) -> 분류/응대/이첩 문서.

LLM은 선택 요소이며, 근거(evidence)는 항상 매뉴얼 색인에서만 가져온다.
"""
import re
from dataclasses import dataclass

from . import rules as R
from .llm import parse_json

ROUTE_LABEL = {
    "REJECTABLE": "거부(종결) 가능 민원 - 근거와 답변 초안",
    "HANDLE": "거부 불가·비악성 - 대응팀 수준에서 처리",
    "ESCALATE": "악성(특이) 민원 의심 - 상위기관 이전 문서 제작",
}

ACTIONS = {
    "assault": ("즉시 경찰 신고와 관리자 호출, 피해 교직원 분리 및 응급조치", "폭행 발생 징후 즉시 주변에 도움 요청 담당자 현장에서 분리조치 경찰 신고"),
    "weapon": ("경찰·소방서 우선 신고, 침착하게 주변 동료에게 도움 요청", "위험물 소지 확인 시 경찰 소방서 우선 신고 조치"),
    "damage": ("민원인 진정 및 경고, 경찰 신고, 타 민원인 대피", "집기 또는 물품 등을 파손하는 경우 민원인 진정 및 경고 안전요원 경찰 동행"),
    "threat": ("녹음 확인, 법적 조치 가능성 고지 후 종료, 관리자 보고", "폭언 등을 계속하시면 정상적인 상담이 어렵고 관련 법령에 따라 처벌받을 수 있습니다"),
    "abuse": ("녹음 확인, 통화곤란 안내 후 종료, 관리자 보고 및 휴게시간 부여", "지속적인 폭언 등으로 더 이상 상담이 어렵습니다 통화를 종료하겠습니다"),
    "insult": ("녹음 확인, 통화곤란 안내 후 종료, 관리자 보고", "지속적인 폭언 등으로 더 이상 상담이 어렵습니다 통화를 종료하겠습니다"),
    "sexual": ("민원 상담 즉시 종료, 피해 교직원 분리, 관리자 보고 및 법적 대응 검토", "민원 상담 종료 폭언 성희롱 발생 시 민원 면담 종료 가능"),
    "stalking": ("교직원 접촉 차단(예약 면담, 관리자 면담, 서면·온라인 창구 전환)", "보호자 외부인의 특이민원에 대해서는 일시적 출입 면담 제한 예약 면담 학교관리자 면담"),
    "doxxing": ("게시물 증거 확보, 경고문 발송, 법적 조치 협의", "온라인 민원 경고공문 통지 법적조치 등을 취할 수 있다는 경고문구"),
}

PII = [(re.compile(r"01[016789][-\s]?\d{3,4}[-\s]?\d{4}"), "[전화번호]"),
       (re.compile(r"\b\d{6}[-\s]?[1-4]\d{6}\b"), "[주민번호]"),
       (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"), "[이메일]")]


def mask_pii(text):
    for p, r in PII:
        text = p.sub(r, text)
    return text


@dataclass
class Used:
    label: str
    ev: object
    role: str          # reject | malicious | procedure | reply
    reason: str
    score: float


class _Collector:
    def __init__(self, retr):
        self.retr, self.items = retr, []

    def add(self, anchor, role, reason, k=1):
        labels = []
        for ev, sc in self.retr.search(anchor, k):
            hit = next((u for u in self.items if u.ev.id == ev.id), None)
            if hit is None:
                hit = Used(f"E{len(self.items) + 1}", ev, role, reason, sc)
                self.items.append(hit)
            elif reason not in hit.reason:
                hit.reason += f" / {reason}"
            labels.append(hit.label)
        return labels


def _draft(llm, text, route, used, notes):
    snippets = "\n".join(f"[{u.label}] {u.ev.text}" for u in used[:6])
    if llm.available:
        try:
            sys = ("당신은 학교 민원대응팀 보조자다. 학교 안내문 어조로 정중하고 차분하게 답변 초안을 쓴다. "
                   "감정을 자극하는 표현과 단정적 비난을 피하고, 제공된 근거에 없는 규정은 말하지 않는다. "
                   "본문에 [E1] 같은 표기는 쓰지 말고 마지막 줄에 '근거: E1, E2' 형식으로만 적는다.")
            usr = f"[민원]\n{text}\n\n[처리 방향]\n{notes}\n\n[매뉴얼 근거]\n{snippets}"
            out = llm.chat(sys, usr).strip()
            cited = set(re.findall(r"E\d+", out.splitlines()[-1])) if out else set()
            valid = {u.label for u in used}
            if cited - valid:                       # 존재하지 않는 근거를 인용하면 폐기
                raise ValueError("근거 라벨 오류")
            return out
        except Exception:  # noqa: BLE001
            pass
    base = {
        "REJECTABLE": ("안녕하세요. 문의해 주셔서 감사합니다. 말씀하신 사항은 학교가 정한 공식 민원 접수 창구"
                       "(학교 대표번호·온라인 민원 창구)를 통해 접수해 주셔야 처리할 수 있습니다. "
                       "교직원 개인 연락처 등 다른 경로로는 민원을 받지 못하는 점 양해 부탁드립니다. "
                       "공식 창구로 접수해 주시면 확인 후 안내해 드리겠습니다."),
        "HANDLE": ("안녕하세요. 소중한 의견을 전해 주셔서 감사합니다. 접수된 내용을 확인하여 담당자와 협의한 뒤 "
                   "처리 기한 안에 안내해 드리겠습니다. 추가로 확인이 필요한 사항은 학교 대표번호로 연락드리겠습니다."),
        "ESCALATE": ("귀하께서 제기하신 민원 중 일부 표현은 관련 법령에 따라 처벌될 수 있습니다. "
                     "앞으로도 동일한 표현이 반복될 경우 학교는 법적 조치 등을 취할 수 있음을 알려 드리니 양지하여 주시기 바랍니다."),
    }[route]
    return base + "\n근거: " + ", ".join(u.label for u in used[:3])


def _judge(llm, text, retr):
    cands = retr.search(text, 6)
    if not (llm.available and cands):
        return {}
    try:
        ids = "\n".join(f"[{e.id}] {e.text}" for e, _ in cands)
        sys = ("학교 민원 분류 보조자다. 아래 [근거 후보]만 근거로 삼아 JSON으로 답한다. "
               '형식: {"malicious": true|false, "types": [문자열], "evidence_ids": [후보 id], "rationale": "한 문장"}. '
               "정당한 항의나 이의 제기는 악성으로 판단하지 않는다.")
        out = parse_json(llm.chat(sys, f"[민원]\n{text}\n\n[근거 후보]\n{ids}", json_mode=True))
        valid = {e.id for e, _ in cands}
        out["evidence_ids"] = [i for i in out.get("evidence_ids", []) if i in valid]
        return out
    except Exception:  # noqa: BLE001
        return {}


def run(text, complainant, retr, store, llm, *, received_at=None, call_minutes=None):
    text = mask_pii(text)
    prior = store.similar_prior(complainant, text)
    repeat = len(prior) + 1
    closed_before = any(":repeat" in p[2] for p in prior)

    mal = R.detect_malicious(text, repeat)
    rej = R.detect_reject(text, received_at, call_minutes, repeat)
    judge = _judge(llm, text, retr)
    if judge.get("malicious") and not any(r.severity >= 3 for r, _, _ in mal):
        mal.append((R.Rule("llm", "LLM 판단 악성 의심", "malicious", "",
                           "특이민원 처리 방향 위법행위 발생 시 녹음 녹화 진정 요청 및 법령 저촉사항 경고", 3, False),
                    [], "; ".join(judge.get("types", [])) or "LLM 판단"))

    escalate = any(r.severity >= 3 for r, _, _ in mal) or repeat >= 3 and closed_before
    route = "ESCALATE" if escalate else "REJECTABLE" if rej else "HANDLE"

    col = _Collector(retr)
    spans, hit_out, actions, notes = [], [], [], []

    for r, sp, matched in (rej if route != "ESCALATE" else []):
        labels = col.add(r.anchor, "reject", f"거부·종결 가능 사유: {r.label}")
        hit_out.append({"kind": "reject", "key": r.key, "label": r.label, "matched": matched,
                        "confident": r.confident, "evidence": labels})
        spans += [(a, b, "reject", labels[0] if labels else "") for a, b in sp]
    for r, sp, matched in mal:
        if r.severity < 3 and route != "ESCALATE":
            notes.append(f"{r.label} 가능성(맥락 확인 필요)")
            continue
        labels = col.add(r.anchor, "malicious", f"특이민원 유형: {r.label}")
        hit_out.append({"kind": "malicious", "key": r.key, "label": r.label, "severity": r.severity,
                        "matched": matched, "confident": r.confident, "evidence": labels})
        spans += [(a, b, "malicious", labels[0] if labels else "") for a, b in sp]
        if r.key in ACTIONS:
            act, anchor = ACTIONS[r.key]
            actions.append({"text": act, "evidence": col.add(anchor, "procedure", f"현장 대응: {r.label}")})

    score, level = R.excitement(text, mal)
    urg = R.urgency([h for h in mal if h[0].severity >= 3] if route == "ESCALATE" else [], level)
    dept, _ = R.department(text)

    if route == "REJECTABLE":
        col.add("공식 창구 외 경로로 학교민원을 신청하는 경우 접수창구를 민원인에게 안내 필요", "procedure", "공식 창구 안내")
        handler, deadline = "민원대응팀", "즉시 회신(종결 시 사유 통지)"
    elif route == "HANDLE":
        col.add("처리 담당자 또는 협조자 지정 단순 질의 또는 요청 사항 민원대응팀", "procedure", "담당자 지정")
        col.add("처리 기한 단순민원 즉시 복합민원 7일 이내 관리자 총괄 민원 14일", "procedure", "처리 기한")
        simple = dept == "기타" or not re.search(r"(확인|조사|사실관계|왜|이유)", text)
        handler = "민원대응팀" if simple else "담당(담임) 교사 협조 + 민원대응팀 총괄"
        deadline = "즉시" if simple else "7일 이내"
        if level == "고위험":
            handler, deadline = "학교장 총괄(관리자 면담)", "14일 이내(연장 가능)"
    else:
        handler, deadline = "관리자(교장·교감) 면담, 민원대응팀 공동 대응", "14일 이내(연장 가능)"

    criteria = {"met": [], "to_check": [
        "퇴거명령·민원 제한에도 불응하고 지속적으로 민원을 제기하는지",
        "학교에서 분쟁조정·법률지원을 받았음에도 자체 해결이 불가한지",
        "정상적인 교육활동에 심각한 지장을 초래하는지"]}
    transfer = None
    if route == "ESCALATE":
        if repeat >= 3 and closed_before:
            criteria["met"].append({"text": "합리적 답변 후 3회 이상 동일·유사 민원으로 종료했으나 지속",
                                    "evidence": col.add("지원 요청 및 이첩 기준 합리적인 답변을 하고 3회 이상 동일 유사한 민원을 제기하여 종료하였음에도 지속적으로 처리를 요구", "procedure", "이첩 기준")})
        if any(r.severity >= 4 for r, _, _ in mal):
            criteria["met"].append({"text": "위법 행위가 처벌 가능할 정도로 중대한 사안일 가능성",
                                    "evidence": col.add("위법 행위가 관련 법령에 따라 처벌이 가능할 정도로 중대 사안인 경우", "procedure", "이첩 기준")})
        col.add("특이민원 관련 지원 요청 보고서 서식 이첩 사유 교육 지원 청 요청사항", "procedure", "보고서 서식")
        if repeat >= 3 or any(r.key == "stalking" for r, _, _ in mal):
            col.add("목적이 정당하지 아니한 민원을 반복적으로 제기하는 행위 교육활동 침해행위 교원지위법", "procedure", "교육활동 침해 검토(반복 민원)")
        if any(r.key in ("abuse", "insult", "threat", "doxxing", "assault") for r, _, _ in mal):
            col.add("교육활동 침해행위 형법 협박의 죄 명예에 관한 죄 업무방해 범죄 행위", "procedure", "교육활동 침해 검토(범죄 행위)")

    used = col.items
    reply = _draft(llm, text, route, used, f"{ROUTE_LABEL[route]}. 담당: {handler}. {'; '.join(notes)}")

    if route == "ESCALATE":
        reasons = "\n".join(f"  - {c['text']} (근거 {', '.join(c['evidence'])})" for c in criteria["met"]) or "  - (자동 판정 가능한 기준 없음, 담당자 확인)"
        reqs = "\n".join(f"  - {a['text']} (근거 {', '.join(a['evidence'])})" for a in actions)
        transfer = (
            "# 특이민원 관련 지원 요청 보고서 (초안)\n\n"
            "| 항목 | 내용 |\n|---|---|\n| 학교명 | (담당자 입력) |\n"
            f"| 제기대상 분류 | {dept} |\n| 민원 관련 학생 성명·학급 | (담당자 입력) |\n"
            "| 보호자 성명·연락처 | (담당자 입력) |\n"
            f"| 민원 제기 및 처리 내용 | {text[:200]}{'…' if len(text) > 200 else ''} (동일·유사 민원 {repeat}회째) |\n\n"
            f"**이첩 사유(자동 판정)**\n{reasons}\n\n**교육(지원)청 요청사항(초안)**\n{reqs or '  - (담당자 입력)'}\n\n"
            f"**추가 확인 필요 기준**\n" + "\n".join(f"  - {c}" for c in criteria["to_check"]) +
            "\n\n※ 본 문서는 보조 도구가 만든 초안이며 학교장 확인 후 제출한다.")

    store.add(complainant, text, route + (":repeat" if any(r.key == "repeat" for r, _, _ in rej) else ""))

    result = {
        "route": route, "route_label": ROUTE_LABEL[route], "repeat_count": repeat,
        "reject": [h for h in hit_out if h["kind"] == "reject"],
        "malicious": [h for h in hit_out if h["kind"] == "malicious"],
        "excitement": {"score": score, "level": level}, "urgency": urg, "department": dept,
        "handler": handler, "deadline": deadline, "notes": notes, "actions": actions,
        "criteria": criteria, "reply_draft": reply, "transfer_doc": transfer,
        "llm_judge": judge or None, "llm_used": llm.available,
        "needs_human_review": route != "HANDLE" or any(not h["confident"] for h in hit_out),
        "text_masked": text,
        "spans": [{"start": a, "end": b, "kind": k, "label": l} for a, b, k, l in sorted(spans)],
        "evidence": [{"label": u.label, "id": u.ev.id, "page": u.ev.page, "printed_page": u.ev.printed_page,
                      "cite": u.ev.cite(), "text": u.ev.text, "role": u.role, "reason": u.reason}
                     for u in used],
    }
    return result, used
