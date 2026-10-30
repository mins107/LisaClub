"""분류 직후 도는 검토 루프(에이전트 루프). 규칙이 정한 분기는 바꾸지 않고, 사람이 볼 점과 약한 근거를 찾아 보강한다.

한 바퀴마다 (1) 판정↔이력 모순을 점검하고(첫 바퀴만), (2) 근거 충분성을 점검한다. 근거가 약하면 재검색해서 보강한다(근거 보강).
재검색어는 LLM이 있으면 LLM이 제안하고, 없으면 규칙 문구를 쪼개서 만든다. 근거는 어느 경우에도 매뉴얼 색인에서만 가져온다.
최대 MAX_ROUNDS바퀴를 돌고, 더 보강할 것이 없으면 일찍 멈춘다. 기준값(COVER_MIN 등)은 임의 시작값이다.
"""
from .llm import parse_json
from .retriever import tokenize

MAX_ROUNDS = 3
COVER_MIN = 0.35        # 규칙 문구(anchor)의 낱말 중 근거 문장이 담은 비율이 이보다 낮으면 근거가 약하다고 본다
COVER_GAIN = 0.1        # 재검색 결과가 기존보다 이만큼 더 잘 맞아야 근거로 추가한다
NEAR_GAP = 0.1          # 특이 반복 유사도가 임계값보다 이만큼 이내로 낮으면 '경계'로 본다


def coverage(anchor, text):
    """anchor 문구의 낱말(2글자 단위) 중 근거 문장에 들어 있는 비율(0~1). 검색 방식과 무관한 척도다."""
    a = set(tokenize(anchor))
    return len(a & set(tokenize(text))) / len(a) if a else 1.0


def history_findings(*, route, history, mal_repeat, near_items, student, sim_threshold):
    """규칙 판정과 이력이 서로 어긋나 보이는 곳을 찾는다. 모두 '사람이 확인' 요청이며 분기는 바꾸지 않는다."""
    out = []
    if student is None and route == "ESCALATE":
        out.append("학생 정보가 없어 같은 학생의 이력(반복·과거 특이)을 보지 못했습니다. 학생을 확인한 뒤 이력을 다시 확인하세요.")
    if near_items:
        out.append(f"같은 학생의 미해결 특이 민원 특성 민원 {len(near_items)}건이 유사도 임계값({int(sim_threshold * 100)}%) 바로 아래입니다. "
                   f"같은 사안인지 확인하세요(같으면 이번이 특이 반복 {mal_repeat + len(near_items)}회째).")
    if mal_repeat == 2 and route != "ESCALATE":
        out.append("특이 민원 특성이 있는 비슷한 민원이 이번까지 2회입니다. 한 번 더 반복되면 특이 민원 의심으로 분류됩니다.")
    if route == "HANDLE" and history.get("prior_malicious"):
        out.append(f"같은 학생의 과거 특이 민원 의심 민원이 {history['prior_malicious']}건 있는데 이번에는 일반 처리로 분류했습니다. 응대 단계를 확인하세요.")
    if route == "HANDLE" and history.get("recent_closed"):
        out.append(f"종결한 민원(#{history['recent_closed']['id']}) 직후의 재연락인데 일반 처리로 분류했습니다. 종결 사유와 이번 내용이 다른지 확인하세요.")
    return out


def _variants(anchor, n):
    """LLM 없이 만드는 재검색어. 바퀴마다 다르게: 1바퀴=앞뒤 절반, 2바퀴=긴 낱말들, 3바퀴=낱말 두 개씩."""
    w = anchor.split()
    if len(w) < 2:
        return [anchor]
    if n == 1:
        h = len(w) // 2
        return [" ".join(w[:h]), " ".join(w[h:])]
    if n == 2:
        return [" ".join(sorted(set(w), key=len, reverse=True)[:4])]
    return [" ".join(w[i:i + 2]) for i in range(0, len(w) - 1, 2)][:3]


def _llm_queries(llm, text, anchor, reason, tried):
    """LLM이 매뉴얼 표현에 가까운 검색어 2~3개를 제안한다. LLM은 검색어만 만들고 근거는 색인에서 나온다."""
    try:
        out = parse_json(llm.chat(
            "학교 민원 처리 매뉴얼에서 근거 문장을 찾기 위한 검색어를 만든다. 매뉴얼 표현에 가까운 짧은 한국어 구절 2~3개를 JSON으로만 답한다: "
            '{"queries": ["...", "..."]}. 이미 시도한 검색어와 다르게 쓰고, 민원인의 감정 표현은 넣지 않는다.',
            f"[민원]\n{text[:600]}\n\n[찾는 내용]\n{reason}\n[기존 검색문]\n{anchor}\n[이미 시도]\n{'; '.join(tried) or '없음'}", json_mode=True))
        qs = [q.strip()[:80] for q in out.get("queries", []) if isinstance(q, str) and q.strip()]
        return qs[:3]
    except Exception:  # noqa: BLE001
        return []


def _best(col, labels, anchor):
    by = {u.label: u for u in col.items}
    return max([coverage(anchor, by[l].ev.text) for l in labels if l in by], default=0.0)


def run(llm, retr, col, hit_out, *, text, route, history, mal_repeat, near_items, student, sim_threshold, max_rounds=MAX_ROUNDS):
    """반환: {"findings": [...], "rounds": [...], "added_evidence": [라벨...], "llm_used", "max_rounds"}.
    col은 pipeline의 _Collector다(근거 추가가 여기로 들어간다). hit_out의 해당 규칙 근거 목록에도 추가된 번호를 붙인다."""
    findings = [{"kind": "history", "text": t} for t in history_findings(
        route=route, history=history, mal_repeat=mal_repeat, near_items=near_items, student=student, sim_threshold=sim_threshold)]
    rounds, added_all = [], []
    entries = [dict(e, tried=[], done=False) for e in col.log if e["labels"]]       # 근거가 붙은 규칙 문구만 점검한다
    for n in range(1, max_rounds + 1):
        weak = [e for e in entries if not e["done"] and _best(col, e["labels"], e["anchor"]) < COVER_MIN]
        rec = {"round": n, "checked": len([e for e in entries if not e["done"]]), "weak": len(weak), "added": [], "queries": []}
        if n == 1 and findings:
            rec["history_findings"] = len(findings)
        if not weak:
            rec["note"] = "근거 점검 통과" if n == 1 else "보강 완료"
            rounds.append(rec)
            break
        progress = False
        for e in weak:
            qs = (_llm_queries(llm, text, e["anchor"], e["reason"], e["tried"]) if llm.available else []) or _variants(e["anchor"], n)
            e["tried"] += qs
            rec["queries"] += qs
            cur = _best(col, e["labels"], e["anchor"])
            known = {u.ev.id for u in col.items}
            cands = {}
            for q in qs:
                for ev, sc in retr.search(q, 3):
                    if ev.id not in known:
                        cands[ev.id] = (coverage(e["anchor"], ev.text), ev, sc)
            if cands:
                cov, ev, sc = max(cands.values(), key=lambda x: x[0])
                if cov >= cur + COVER_GAIN:
                    lab = col.add_evidence(ev, sc, e["role"], f"{e['reason']} / 검토에서 보강")
                    e["labels"].append(lab)
                    for h in hit_out:
                        if set(h.get("evidence", [])) & set(e["labels"][:-1]):
                            h["evidence"].append(lab)
                    rec["added"].append(lab)
                    added_all.append(lab)
                    progress = True
            if _best(col, e["labels"], e["anchor"]) >= COVER_MIN:
                e["done"] = True
        rounds.append(rec)
        if not progress:
            rec["note"] = "더 나은 근거를 찾지 못해 멈춤"
            break
    for e in entries:
        if not e["done"] and _best(col, e["labels"], e["anchor"]) < COVER_MIN:
            findings.append({"kind": "evidence", "text": f"'{e['reason']}'의 매뉴얼 근거가 약합니다(규칙 문구와 근거 문장이 많이 다름). 근거 문장과 PDF를 직접 확인하세요."})
    return {"findings": findings, "rounds": rounds, "added_evidence": added_all, "llm_used": bool(llm.available), "max_rounds": max_rounds}
