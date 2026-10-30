"""부서별 민원 현황에서 '개선을 검토할 부서'와 그 이유를 뽑는다. 부서 개선 의사결정의 참고 자료다.

기준값은 학교가 정한 것이 아니라 임의로 둔 시작값이라 아래 상수를 고쳐 쓴다. 표본이 적으면 판단하지 않는다.
"""
MIN_DEPT_CASES = 3        # 부서 접수 건수가 이보다 적으면 판단하지 않는다
OVERDUE_RATE = 0.2        # (진행 중 기한 초과 + 기한 넘겨 끝낸 건) / 접수 건수
BACKLOG_RATE = 0.6        # 진행 중 건수 / 접수 건수 (처리가 쌓이는 정도)
REPEAT_RATE = 0.3         # 같은 학생의 동일·유사 민원이 반복된 비율
CONCENTRATION = 0.4       # 전체 민원 중 이 부서 몫 (전체가 MIN_TOTAL_CASES 이상일 때)
MIN_TOTAL_CASES = 10
UNASSIGNED_RATE = 0.2     # 미분류 비율(부서 체계가 민원을 못 담는 정도)

ADVICE = {
    "overdue": "처리 기한을 넘기는 건이 많습니다. 담당자 지정과 협조 요청이 늦어지는 단계를 점검하고 기한 임박 알림 방식을 검토하세요.",
    "backlog": "처리 중인 건이 쌓여 있습니다. 담당 인원·업무 분담과 다른 부서와의 협조 절차를 점검하세요.",
    "repeat": "같은 학생의 비슷한 민원이 되풀이됩니다. 첫 답변이 충분했는지, 사전 안내(공지·자주 묻는 질문)가 필요한지 점검하세요.",
    "concentration": "민원이 이 부서에 몰려 있습니다. 반복되는 주제를 사전 안내하거나 업무를 다른 부서와 나눌 수 있는지 검토하세요.",
    "unassigned": "어느 부서에도 맞지 않는 민원이 많습니다. 급식·시설 등 담당 부서가 없는 영역이 있는지 부서 체계를 검토하세요.",
}


def _pct(n, d):
    return f"{n * 100 // d}%" if d else "0%"


def department_insights(depts, total):
    """반환: [{dept, flags, facts, advice}] 개선 필요 정도가 큰 순. 판단 대상이 없으면 []."""
    out = []
    for name, d in depts.items():
        n = d["total"]
        if n < MIN_DEPT_CASES:
            continue
        late = d["overdue"] + d["late_done"]
        flags, facts = [], [f"접수 {n}건(전체의 {_pct(n, total)})"]
        if late / n >= OVERDUE_RATE:
            flags.append("overdue")
            facts.append(f"기한 초과 {d['overdue']}건·기한 넘겨 처리 {d['late_done']}건({_pct(late, n)})")
        if d["open"] / n >= BACKLOG_RATE and d["open"] >= MIN_DEPT_CASES:
            flags.append("backlog")
            facts.append(f"진행 중 {d['open']}건({_pct(d['open'], n)})")
        if d["repeat"] / n >= REPEAT_RATE and d["repeat"] >= 2:
            flags.append("repeat")
            facts.append(f"반복 민원 {d['repeat']}건({_pct(d['repeat'], n)})")
        if total >= MIN_TOTAL_CASES and n / total >= CONCENTRATION and not name.startswith("미분류"):
            flags.append("concentration")
        if name.startswith("미분류") and n / total >= UNASSIGNED_RATE:
            flags.append("unassigned")
        if flags:
            if d["avg_days"] is not None:
                facts.append(f"평균 처리 {d['avg_days']}일")
            if d["top_topics"]:
                facts.append("주요 주제: " + ", ".join(d["top_topics"]))
            out.append({"dept": name, "flags": flags, "facts": facts, "advice": [ADVICE[f] for f in flags]})
    return sorted(out, key=lambda x: -len(x["flags"]))
