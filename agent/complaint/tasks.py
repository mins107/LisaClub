"""민원 내용을 읽어 민원대응팀이 지금 할 일(누구에게 무엇을 문의할지, 어떻게 회신할지)을 만든다.

이 문구는 권장 안내이며 매뉴얼 규정이 아니다(담당자 지정·처리 기한·공식 창구 근거만 매뉴얼에서 가져온다).
화면의 '지금 할 일'과 같은 형식 {phase, text, reasons, evidence}로 돌려준다.
"""
import re

from . import counter as CT
from .rules import DEPT_DESC, UNASSIGNED

SUBJECTS = ["국어", "수학", "영어", "과학", "사회", "한국사", "역사", "도덕", "윤리", "체육", "음악", "미술", "기술", "가정", "정보",
            "한문", "물리", "화학", "생명과학", "지구과학", "통합과학", "통합사회", "경제", "지리", "일본어", "중국어", "독일어", "프랑스어"]
_SUBJ_CTX = r"\s*(?:과목|교과|수업|수행평가|수행|시험|고사|점수|성적|선생|교사|숙제|과제|평가|서술형|발표|실기|쪽지)"
_GRADE = re.compile(r"(수행평가|수행|성적|점수|채점|등급|내신|서술형|지필|시험 문제|이의 ?신청|평가 기준)")

REASON_TAG = "권장 안내"
PHASE_ASK, PHASE_REPLY = "담당자 문의·확인", "민원인 응대"


def find_subject(text):
    """'국어 수행평가', '수학 선생님'처럼 과목 뒤에 수업·평가 말이 붙은 경우만 과목으로 본다('수학여행' 등 오탐 방지)."""
    for s in SUBJECTS:
        if re.search(rf"{s}{_SUBJ_CTX}", text):
            return s
    return None


def _a(phase, text, reasons, evidence=()):
    return {"phase": phase, "text": text, "reasons": [*reasons, REASON_TAG] if REASON_TAG not in reasons else list(reasons),
            "evidence": list(evidence)}


def team_tasks(text, route, deadline, student, ev_assign=(), ev_due=(), ev_guide=(), homeroom=False, schedule=None, dept=None, grade_dept=None):
    """반환: (먼저 할 일 목록, 마지막에 할 일 목록). 일반 처리·거부 가능 민원에만 만든다.
    ev_guide(공식 창구 안내 근거)는 개인 연락처를 묻는 민원에만 있다. 이 사이트가 공식 접수 창구라서 다른 거부 사유에는 창구 안내를 붙이지 않는다."""
    first, last = [], []
    if route == "REJECTABLE":
        if ev_guide:
            last.append(_a(PHASE_REPLY, f"교직원 개인 연락처는 안내할 수 없고 공식 접수 창구({CT.full_line()})로 문의하도록 안내",
                           ["교직원 개인 연락처 요구"], ev_guide))
        else:
            last.append(_a(PHASE_REPLY, "거부·종결 사유를 민원인에게 통지", ["거부·종결 가능 민원"], []))
        return first, last
    if route != "HANDLE":
        return first, last

    subj = find_subject(text)
    asked = False
    if dept and dept != UNASSIGNED:
        asked = True
        first.append(_a(PHASE_ASK, f"{dept}에 협조 요청: {DEPT_DESC[dept].split(', ')[0]} 업무 담당", [f"담당 부서: {dept}"], ev_assign))
    if _GRADE.search(text):
        asked = True
        if subj:
            first.append(_a(PHASE_ASK, f"{subj} 교과 교사에게 문의: 평가 기준·점수 산출 근거와 이의 신청 가능 여부 확인",
                            [f"민원에 '{subj}' 평가·성적 언급"], ev_assign))
        else:
            first.append(_a(PHASE_ASK, "민원인(또는 학생)에게 어느 과목·어떤 평가인지 확인한 뒤 해당 교과 교사에게 문의",
                            ["평가·성적 문의인데 과목이 적혀 있지 않음"], ev_assign))
    elif subj:
        asked = True
        first.append(_a(PHASE_ASK, f"{subj} 교과 교사에게 문의: 민원에서 말한 수업·과제 상황 확인", [f"민원에 '{subj}' 수업 언급"], ev_assign))
    if re.search(r"(출결|결석|지각|조퇴|결과|체험학습 신청|출석)", text):
        asked = True
        first.append(_a(PHASE_ASK, "담임 교사에게 문의: 출결 기록과 증빙 서류 확인", ["출결 관련 문의"], ev_assign))
    if re.search(r"(따돌림|왕따|괴롭|폭행|싸움|학교폭력|학폭|집단)", text):
        asked = True
        first.append(_a(PHASE_ASK, "학생생활안전부와 담임 교사에게 알리고 사안 여부 확인. 학교폭력이 의심되면 관련 절차에 따라 관리자에게 보고",
                        ["교우 관계·폭력 언급"], ev_assign))
    if re.search(r"(급식|식단|영양|알레르기|도시락)", text):
        asked = True
        first.append(_a(PHASE_ASK, "영양(교)사에게 문의: 식단·알레르기·위생 관련 사실 확인", ["급식 관련 문의"], ev_assign))
    if re.search(r"(시설|냉난방|에어컨|히터|화장실|고장|수리|통학버스|주차|CCTV|청소|소음)", text):
        asked = True
        first.append(_a(PHASE_ASK, "행정실(시설 담당)에 문의: 현장 확인과 조치 가능 여부", ["시설·환경 관련 문의"], ev_assign))
    if re.search(r"(방과후|진로|입시|생활기록부|생기부|세특|대입|진학|수시|정시)", text):
        asked = True
        first.append(_a(PHASE_ASK, "창의진로상담부(진로·진학)에 문의: 관련 안내 자료와 기준 확인", ["진로·학사 관련 문의"], ev_assign))
    if re.search(r"(교사|선생님|담임).{0,12}(태도|불친절|말투|차별|편애|수업 방식)", text):
        asked = True
        first.append(_a(PHASE_ASK, "해당 교사에게 사실 확인을 요청하고 교감에게 보고", ["교직원 대응에 대한 불만"], ev_assign))

    if schedule:
        if schedule.get("status") == "ok":
            first.append(_a(PHASE_ASK, "학사일정 API로 조회한 일정(초안에 반영됨)이 맞는지 한 번 확인", ["학사일정 문의"]))
        else:
            first.append(_a(PHASE_ASK, "교무기획부(학교행사·학사)에 해당 행사 일정 확인", ["학사일정 문의인데 API로 일정을 찾지 못함"], ev_assign))
        asked = True
    if homeroom:
        gd = f"{grade_dept}에 알리고 " if grade_dept and grade_dept != dept else ""
        first.append(_a(PHASE_ASK, f"{gd}아래 '담임 교사 전달' 카드의 전달문을 담임 교사에게 보내고 '전달함으로 표시'", ["담당에 담임 교사 포함"], ev_assign))
        asked = True
    if not asked:
        first.append(_a(PHASE_ASK, "민원 내용을 확인하고 처리 담당자(관련 부서·교사)를 정해 협조 요청", ["담당자 지정 필요"], ev_assign))

    last.append(_a(PHASE_REPLY, f"확인한 내용으로 답변 초안을 고쳐 민원인에게 회신 (처리 기한: {deadline})", ["기한 안에 회신"], ev_due))
    return first, last
