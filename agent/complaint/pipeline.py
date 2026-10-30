"""구조도 흐름: 민원 -> (거부 가능?) -> (악성?) -> 분류/응대/이첩 문서.

LLM은 선택 요소이며, 근거(evidence)는 항상 매뉴얼 색인에서만 가져온다.
"""
import re
from dataclasses import dataclass
from datetime import datetime

from . import rules as R
from . import soften as SF
from . import schedule as SC
from . import tasks as TK
from . import notices as NT
from .llm import parse_json

ROUTE_LABEL = {
    "REJECTABLE": "거부(종결) 가능 민원 - 근거와 답변 초안",
    "HANDLE": "거부 불가·비악성 - 대응팀 수준에서 처리",
    "ESCALATE": "악성(특이) 민원 의심 - 상위기관 이전 문서 제작",
}

# 현장 조치를 한 단계씩 쪼개 둔다. 여러 악성 유형에서 같은 단계가 나오면 한 줄로 합쳐 보여 준다.
# 아래 순서가 화면에 보이는 순서다(안전 확보 -> 증거 확보 -> 응대 -> 보고 -> 후속 조치).
STEPS = {
    "police": ("안전 확보·신고", "경찰에 신고 (위험물이면 소방서에도)"),
    "help": ("안전 확보·신고", "관리자를 부르고 주변 동료에게 도움 요청"),
    "separate": ("안전 확보·신고", "피해 교직원을 현장에서 분리하고 응급조치"),
    "calm": ("안전 확보·신고", "민원인을 진정시키고 경고, 다른 민원인은 대피"),
    "record": ("증거 확보", "녹음·녹화 내용 확인"),
    "post_evidence": ("증거 확보", "게시물 증거 확보"),
    "warn": ("민원인 응대", "관련 법령에 따라 처벌받을 수 있음을 고지"),
    "end": ("민원인 응대", "상담이 어렵다고 안내하고 통화·면담 종료"),
    "recontact1": ("민원인 응대", "재접촉 1차 (과거 악성 이력): 진정되면 정상 응대하고, 폭언이 이어지면 통화 종료"),
    "recontact2": ("민원인 응대", "재접촉 2차 이상 (과거 악성 이력): 상급자(교감 등)가 응대해 불만을 듣고 경고한 뒤 종료"),
    "letter": ("민원인 응대", "법적 조치 가능성을 담은 경고문 발송"),
    "block": ("민원인 응대", "출입·면담 제한 등으로 교직원과의 접촉 차단 (예약 면담, 관리자 면담, 서면·온라인 창구로 전환)"),
    "report": ("보고·보호", "관리자에게 보고"),
    "rest": ("보고·보호", "피해 교직원에게 휴게시간 부여"),
    "legal": ("후속 조치", "법적 대응 검토·협의"),
}
# 악성 유형 -> (필요한 단계 목록, 매뉴얼에서 근거를 찾을 문구)
ACTIONS = {
    "assault": (["police", "help", "separate"], "폭행 발생 징후 즉시 주변에 도움 요청 담당자 현장에서 분리조치 경찰 신고"),
    "weapon": (["police", "help"], "위험물 소지 확인 시 경찰 소방서 우선 신고 조치"),
    "damage": (["calm", "police"], "집기 또는 물품 등을 파손하는 경우 민원인 진정 및 경고 안전요원 경찰 동행"),
    "threat": (["record", "warn", "end", "report"], "폭언 등을 계속하시면 정상적인 상담이 어렵고 관련 법령에 따라 처벌받을 수 있습니다"),
    "abuse": (["record", "end", "report", "rest"], "지속적인 폭언 등으로 더 이상 상담이 어렵습니다 통화를 종료하겠습니다"),
    "insult": (["record", "end", "report"], "지속적인 폭언 등으로 더 이상 상담이 어렵습니다 통화를 종료하겠습니다"),
    "sexual": (["end", "separate", "report", "legal"], "민원 상담 종료 폭언 성희롱 발생 시 민원 면담 종료 가능"),
    "stalking": (["block"], "보호자 외부인의 특이민원에 대해서는 일시적 출입 면담 제한 예약 면담 학교관리자 면담"),
    "doxxing": (["post_evidence", "letter", "legal"], "온라인 민원 경고공문 통지 법적조치 등을 취할 수 있다는 경고문구"),
}

# 같은 학생 민원에 과거 악성(특이) 이력이 있을 때의 재접촉 대응. 단계는 이력 건수(1건=1차, 2건 이상=2차).
RECONTACT_ANCHOR = {
    1: "동일 민원인과 재통화 시 1차 민원인이 진정된 경우 정상 응대하고 폭언을 지속할 경우 통화 종료",
    2: "2차 상급자가 응대하고 경고 후 통화 종료 민원인의 불만사항 등을 파악하고 폭언 등에 대한 경고 조치",
}
CONTACT_LIMIT_ANCHOR = "흉기 소지 폭언 폭행 반복적 민원 제기 등으로 공무 업무를 방해한 자에 대한 출입 제한 퇴거 조치 가능"


def _add_step(steps, sid, reason, labels):
    st = steps.setdefault(sid, {"reasons": [], "evidence": []})
    if reason not in st["reasons"]:
        st["reasons"].append(reason)
    for lb in labels:
        if lb not in st["evidence"]:
            st["evidence"].append(lb)


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


# 담임 교사에게 전달할 "필요한 행동"의 부서별 확인 사항은 rules.DEPARTMENTS의 check 문구다(권장 문구이며 매뉴얼 규정은 아니다).
DEPT_CHECK = {d["name"]: d["check"] for d in R.DEPARTMENTS}
DEPT_CHECK[R.UNASSIGNED] = "민원에서 말한 사실관계를 확인해 주세요"
for _n in R.GRADE_DEPTS + [R.GRADE_UNKNOWN]:
    DEPT_CHECK[_n] = next(d["check"] for d in R.DEPARTMENTS if d["name"] == R.GRADE_TEMPLATE)


def _summarize(llm, text):
    """담임 교사에게 보여 줄 요약. LLM이 있으면 두 문장 이내로, 없거나 실패하면 앞부분 문장을 잘라 쓴다."""
    if llm.available:
        try:
            out = llm.chat("학교 민원을 담임 교사가 바로 파악하도록 한국어 두 문장 이내로 요약한다. 요구 사항 중심으로 쓰고 "
                           "감정적 표현과 비난은 뺀다. 민원에 없는 내용은 쓰지 않는다.", text).strip()
            if out:
                return out[:300]
        except Exception:  # noqa: BLE001
            pass
    out = ""
    for part in re.split(r"(?<=[.!?。])\s+|\n+", text.strip()):
        if part and (not out or len(out) + len(part) <= 140):
            out += (" " if out else "") + part
        elif out:
            break
    return out[:140] + ("…" if len(out) > 140 else "")


def _homeroom_handoff(llm, text, student, dept, deadline, ev_assign, ev_due):
    """담당에 담임 교사가 들어가는 민원: 담임 교사에게 줄 요약과 필요한 행동, 복사해 보낼 전달문."""
    to = f"{student.class_no[0]}학년 {int(student.class_no[1:])}반 담임 교사" if student else "담임 교사 (학년반 미입력)"
    summary = _summarize(llm, text)
    actions = [
        {"text": DEPT_CHECK.get(dept, DEPT_CHECK[R.UNASSIGNED]), "evidence": ev_assign},
        {"text": f"확인한 내용을 민원대응팀에 알려 주세요 (처리 기한: {deadline})", "evidence": ev_due},
        {"text": "확인이 어렵거나 학부모 면담이 필요하면 민원대응팀에 먼저 알려 주세요", "evidence": []},
    ]
    name = student.display() if student else "학생 미상"
    message = "\n".join([f"[담임 교사 전달] {to}", f"학생: {name}", "", "■ 민원 요약", summary, "",
                         "■ 분류", f"일반 처리 · 담당 부서: {dept} · 처리 기한: {deadline}", "",
                         "■ 요청 사항", *[f"{i}. {a['text']}" for i, a in enumerate(actions, 1)], "",
                         "※ 자동 분류로 만든 초안입니다. 민원대응팀이 확인한 뒤 전달해 주세요."])
    return {"to": to, "student": name, "summary": summary, "department": dept, "deadline": deadline,
            "actions": actions, "message": message}


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


def run(text, student, retr, store, llm, *, received_at=None, call_minutes=None, save=True, calendar=None):
    """student는 store.Student(학생 이름 + 학년반) 또는 None. None이면 학생 기준 이력 판단은 하지 않고 '학생 미상'으로 저장한다.
    save=False면 DB에 저장하지 않는다(시험 입력). 이력 조회는 save와 상관없이 한다.

    이력 판단(매뉴얼 근거):
      - 동일·유사 민원 3회 이상 반복 -> 종결 가능 (PDF 11·16·58쪽)
      - 3회 이상 유사 민원을 종료했는데도 지속 -> 교육(지원)청 이첩 (PDF 16쪽)
      - 종결 민원 직후 재접촉 -> 거부 가능 (PDF 11쪽)
      - 과거 악성 이력이 있는 민원인의 재접촉 -> 1차·2차 대응 (PDF 49쪽), 반복 시 접촉 제한 검토 (PDF 26쪽)"""
    text = mask_pii(text)
    soft, soft_method = SF.soften(llm, text)       # 담당자 화면용 순화문. 판정은 원문(text)으로 한다
    history = store.find_history(student, text)
    prior = history["same_student"]
    repeat = len(prior) + 1
    closed_before = any(p["closed"] for p in prior)

    mal = R.detect_malicious(text, repeat)
    rej = R.detect_reject(text, received_at, call_minutes, repeat, recontact=bool(history["recent_closed"]))
    judge = _judge(llm, text, retr)
    if judge.get("malicious") and not any(r.severity >= 3 for r, _, _ in mal):
        mal.append((R.Rule("llm", "LLM 판단 악성 의심", "malicious", "",
                           "특이민원 처리 방향 위법행위 발생 시 녹음 녹화 진정 요청 및 법령 저촉사항 경고", 3, False),
                    [], "; ".join(judge.get("types", [])) or "LLM 판단"))

    escalate = any(r.severity >= 3 for r, _, _ in mal) or repeat >= 3 and closed_before
    route = "ESCALATE" if escalate else "REJECTABLE" if rej else "HANDLE"

    col = _Collector(retr)
    spans, hit_out, notes, steps = [], [], [], {}

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
            ids, anchor = ACTIONS[r.key]
            ev = col.add(anchor, "procedure", f"현장 대응: {r.label}")
            for sid in ids:
                _add_step(steps, sid, r.label, ev)

    pm = history["prior_malicious"]
    if pm:
        stage = min(pm, 2)
        notes.append(f"같은 학생 민원에 과거 악성(특이) 의심 이력 {pm}건 - 재접촉 {stage}차 대응 참고")
        _add_step(steps, f"recontact{stage}", "과거 악성 이력",
                  col.add(RECONTACT_ANCHOR[stage], "procedure", f"과거 악성 이력 재접촉 {stage}차 대응"))
        if route == "ESCALATE":
            _add_step(steps, "block", "악성 민원 반복", col.add(CONTACT_LIMIT_ANCHOR, "procedure", "반복 악성 민원 접촉 제한 검토"))
    actions = [{"phase": STEPS[sid][0], "text": STEPS[sid][1], "reasons": steps[sid]["reasons"],
                "evidence": steps[sid]["evidence"]} for sid in STEPS if sid in steps]

    urg = R.urgency([h for h in mal if h[0].severity >= 3] if route == "ESCALATE" else [])
    dinfo = R.classify_department(text, student.class_no if student else None)
    dept = dinfo["name"]

    homeroom, ev_assign, ev_due, ev_guide = None, [], [], []
    if route == "REJECTABLE":
        ev_guide = col.add("공식 창구 외 경로로 학교민원을 신청하는 경우 접수창구를 민원인에게 안내 필요", "procedure", "공식 창구 안내")
        handler, deadline = "민원대응팀", "즉시 회신(종결 시 사유 통지)"
    elif route == "HANDLE":
        ev_assign = col.add("처리 담당자 또는 협조자 지정 단순 질의 또는 요청 사항 민원대응팀", "procedure", "담당자 지정")
        ev_due = col.add("처리 기한 단순민원 즉시 복합민원 7일 이내 관리자 총괄 민원 14일", "procedure", "처리 기한")
        simple = dept == R.UNASSIGNED or not re.search(r"(확인|조사|사실관계|왜|이유)", text)
        handler = "민원대응팀" if simple else "담당(담임) 교사 협조 + 민원대응팀 총괄"
        deadline = "즉시" if simple else "7일 이내"
        if "담임" in handler:
            homeroom = _homeroom_handoff(llm, soft, student, dept, deadline, ev_assign, ev_due)
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
    sched = SC.answer(text, student, calendar) if route == "HANDLE" else None
    if sched and sched["status"] == "ok":       # 학사일정 문의: 일정 API 결과로 직접 답하는 초안
        reply = sched["reply"]
        notes.append("학사일정 문의 - 나이스 학사일정 API 조회 결과로 답변 초안 작성(발송 전 일정 확인)")
    first, last = TK.team_tasks(text, route, deadline, student, ev_assign, ev_due, ev_guide, bool(homeroom), sched, dept=dept,
                              grade_dept=R.grade_department(student.class_no) if student else None)
    notice_hits = []
    if route == "HANDLE" and hasattr(store, "list_notice_plans"):     # 지금이 가정통신문 전달 시기인 주제의 민원이면 함께 안내
        plans = store.list_notice_plans()
        sends = {p["id"]: {x["season_year"] for x in p["sends"]} for p in plans}
        notice_hits = NT.matching_plans(plans, dinfo["keywords"], datetime.now().date(), sends)
        for n in notice_hits:
            last.insert(0, {"phase": "민원인 응대", "text": f"가정통신문 '{n['title']}'({'전달함' if n['state'] == 'sent' else '아직 전달 전'})을 답변에 함께 안내",
                            "reasons": [f"이 시기에 '{n['keyword']}' 문의가 늘어남", "권장 안내"], "evidence": []})
    if homeroom and student:
        homeroom["grade_department"] = R.grade_department(student.class_no)
        homeroom["message"] = homeroom["message"].replace(
            "※ 자동 분류", f"※ 학년부 공유: {homeroom['grade_department']}\n※ 자동 분류")
    actions = first + actions + last          # 민원대응팀이 할 일: 담당자 문의 -> (악성 대응 조치) -> 회신

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

    result = {
        "route": route, "route_label": ROUTE_LABEL[route], "repeat_count": repeat,
        "student": student.display() if student else None,
        "reject": [h for h in hit_out if h["kind"] == "reject"],
        "malicious": [h for h in hit_out if h["kind"] == "malicious"],
        "urgency": urg, "department": dept, "department_reason": dinfo["reason"],
        "department_desc": R.DEPT_DESC.get(dept, ""), "department_candidates": dinfo["candidates"],
        "department_keywords": dinfo["matched"], "topic_keywords": dinfo["keywords"],
        "grade_department": R.grade_department(student.class_no) if student else None,
        "handler": handler, "deadline": deadline, "notes": notes, "actions": actions,
        "criteria": criteria, "reply_draft": reply, "transfer_doc": transfer, "homeroom": homeroom,
        "schedule": sched, "notices": notice_hits,
        "llm_judge": judge or None, "llm_used": llm.available,
        "needs_human_review": route != "HANDLE" or pm > 0 or any(not h["confident"] for h in hit_out),
        "text_masked": text, "text_soft": soft, "text_soft_method": soft_method,
        "history": {"student": history["student"], "same_student": prior, "similar_others": history["similar_others"],
                    "recent_closed": history["recent_closed"], "prior_malicious": pm},
        "complaint_id": None,
        "spans": [{"start": a, "end": b, "kind": k, "label": l} for a, b, k, l in sorted(spans)],
        "evidence": [{"label": u.label, "id": u.ev.id, "page": u.ev.page, "printed_page": u.ev.printed_page,
                      "cite": u.ev.cite(), "text": u.ev.text, "role": u.role, "reason": u.reason}
                     for u in used],
    }
    if save:
        result["complaint_id"] = store.save(result, student, received_at, call_minutes,
                                            closed_by_repeat=any(r.key == "repeat" for r, _, _ in rej))
    return result, used
