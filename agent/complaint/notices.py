"""시즌 키워드에 대한 가정통신문(공지사항) 전달 계획과, '지금 전달할 때인가'를 판단하는 로직.

흐름
  1) analytics.season_report가 달마다 늘어나는 키워드(시즌 키워드)와 같이 늘어나는 키워드를 찾는다.
  2) plans_from_report가 시즌 키워드마다 전달 계획 초안(제목·본문·시기)을 만든다. 계획은 DB(notice_plans)에 저장한다.
  3) 늘어나는 달의 LEAD_DAYS일 전부터 그 달 말까지가 전달 시기다. plan_state가 오늘 날짜로 '전달 필요/전달함/대기'를 판단한다.
  4) 담당자가 전달문을 복사해 보내고 '전달함으로 표시'하면 notice_sends에 (계획, 시즌 연도)로 기록한다. 같은 해에는 한 번만 센다.
이 프로그램이 학부모에게 직접 보내지는 않는다(민원 담임 전달과 같은 방식).
"""
import calendar
from datetime import date, timedelta

from .rules import DEPARTMENTS, GRADE_TEMPLATE, UNASSIGNED

LEAD_DAYS = 14           # 늘어나는 달이 시작하기 며칠 전부터 전달하는가(임의 시작값)


def keyword_department(keyword):
    """키워드가 걸리는 부서(문의 창구 안내용). 여러 부서에 걸리면 앞선 부서, 없으면 UNASSIGNED."""
    import re
    for d in DEPARTMENTS:
        if re.search(d["kw"], keyword):
            return "학년부" if d["name"] == GRADE_TEMPLATE else d["name"]
    return UNASSIGNED


def draft_plan(item, total_cases):
    """시즌 키워드 한 건 -> 가정통신문 계획 초안 {keyword, related, peak_month, lead_days, department, title, body, evidence}."""
    kw, m = item["keyword"], item["peak_month"]
    related = [r["keyword"] for r in item["related"]]
    dept = keyword_department(kw)
    pct = int(item["share"] * 100)
    body = "\n".join([
        "학부모님께", "",
        f"매년 {m}월에는 '{kw}' 관련 문의가 많이 접수됩니다. 문의 전에 아래 내용을 먼저 확인해 주시기 바랍니다.", "",
        f"■ 안내 주제: {kw}" + (f" (함께 문의가 많은 주제: {', '.join(related)})" if related else ""),
        "■ 안내 내용: (담당 부서가 일정·기준·신청 방법 등 구체적인 내용을 채워 주세요)",
        f"■ 문의: {dept if dept != UNASSIGNED else '학교 민원 접수 창구'} (학교 대표번호)", "",
        "※ 자동 분석으로 만든 초안입니다. 내용을 확인·보완한 뒤 발송해 주세요."])
    return {"keyword": kw, "related": related, "peak_month": m, "lead_days": LEAD_DAYS, "department": dept,
            "title": f"[가정통신문] {m}월 {kw} 관련 안내", "body": body,
            "evidence": f"{kw} 민원 {item['total']}건 중 {pct}%가 {m}월에 접수됨(전체 민원 중 {m}월 비중의 {item['lift']}배)"}


def plans_from_report(report):
    """시즌 키워드 -> 가정통신문 계획 초안 목록. 분석할 데이터가 부족하면 []."""
    if not report.get("enough"):
        return []
    return [draft_plan(i, report["total"]) for i in report.get("all_seasonal", [])]


def window(peak_month, year, lead_days=LEAD_DAYS):
    """year년 peak_month월 시즌의 전달 시기 (시작일, 마감일). 시작일은 그 달 1일의 lead_days일 전, 마감일은 그 달 말일."""
    first = date(year, peak_month, 1)
    return first - timedelta(days=lead_days), date(year, peak_month, calendar.monthrange(year, peak_month)[1])


def plan_state(plan, sent_years, today):
    """오늘 기준 이 계획의 상태. 반환: {state, season_year, start, end, sent}.
    state: 'due'(전달 시기인데 아직 안 보냄) / 'sent'(이번 시즌에 전달함) / 'waiting'(다음 시기를 기다림).
    sent_years: 이 계획을 전달한 시즌 연도 집합."""
    lead = plan.get("lead_days", LEAD_DAYS)
    wins = [(y, *window(plan["peak_month"], y, lead)) for y in (today.year - 1, today.year, today.year + 1)]
    for y, s, e in wins:
        if s <= today <= e:
            return {"state": "sent" if y in sent_years else "due", "season_year": y, "start": s, "end": e, "sent": y in sent_years}
    y, s, e = min((w for w in wins if w[1] > today), key=lambda w: w[1])
    return {"state": "waiting", "season_year": y, "start": s, "end": e, "sent": y in sent_years}


STATE_LABEL = {"due": "전달 필요", "sent": "전달함", "waiting": "대기"}


def matching_plans(plans, keywords, today, sends):
    """민원에서 찾은 키워드에 해당하는 계획 중 지금 전달 시기(전달 필요·전달함)인 것. 민원 답변에 가정통신문을 함께 안내하는 데 쓴다."""
    kws = set(keywords)
    out = []
    for p in plans:
        if not p.get("active", True) or not (kws & ({p["keyword"]} | set(p["related"]))):
            continue
        st = plan_state(p, sends.get(p["id"], set()), today)
        if st["state"] in ("due", "sent"):
            out.append({"id": p["id"], "title": p["title"], "state": st["state"], "keyword": p["keyword"]})
    return out


def status_list(plans, today=None):
    """계획 목록에 오늘 기준 상태(state, label, start, end, season_year)를 붙인다. 전달 필요가 맨 앞, 그다음 가까운 시기 순."""
    today = today or date.today()
    out = []
    for p in plans:
        st = plan_state(p, {x["season_year"] for x in p["sends"]}, today)
        out.append({**p, **st, "label": STATE_LABEL[st["state"]]})
    order = {"due": 0, "waiting": 1, "sent": 2}
    return sorted(out, key=lambda x: (order[x["state"]], x["start"]))
