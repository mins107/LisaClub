"""상위기관(교육(지원)청) 이첩용 '특이민원 관련 지원 요청 보고서'(매뉴얼 55쪽 서식, 한글 .hwpx)와 '이첩 기준 체크리스트'(매뉴얼 12쪽)를 만든다.

- 서식 항목: 학교명 / 제기대상 분류 / 민원관련 학생(성명·학급정보) / 보호자(성명·연락처) / 민원 제기 및 처리내용 /
  이첩 사유(학교 자체 해결 노력 포함) / 교육(지원)청 요청사항.
- 체크리스트: 매뉴얼 12쪽 '지원 요청 및 이첩 기준(안)' 5개 중 어느 것에 해당하는지를 민원 내용·이력으로 자동 판단한다.
  판단은 후보 제시용이며, 학교에서 한 조치(퇴거명령, 분쟁조정 등)처럼 시스템이 모르는 사항은 '확인 필요'로 남긴다.
- 쪽 번호는 매뉴얼에 인쇄된 번호(12쪽=PDF 16쪽, 55쪽=PDF 59쪽)다.
"""
import re

CRITERIA = [   # 매뉴얼 12쪽 '지원 요청 및 이첩 기준(안)' 원문
    "합리적인 답변을 하고 3회 이상 동일･유사한 민원을 제기하여 종료하였음에도 지속적으로 처리를 요구(자체 종결처리 가능)하거나 위력을 행사하는 경우",
    "위법･부당한 행위로 학교장이 퇴거명령, 민원 제한 등의 조치를 했음에도 불응하고 학교 및 상급기관에 지속적으로 민원을 제기하는 경우",
    "위법 행위가 관련 법령에 따라 처벌이 가능할 정도로 중대 사안인 경우",
    "학교에서 분쟁조정, 중재, 법률지원 등을 받았음에도 자체적으로 해결이 불가한 경우",
    "기타 학교의 정상적인 교육활동에 심각한 지장을 초래하는 경우",
]
CRITERIA_SHORT = [   # 화면·보고서에서 번호 대신 쓰는 기준 요약
    "같은 민원을 3회 이상 반복하거나 위력을 행사함",
    "퇴거명령·민원 제한에도 따르지 않고 계속 민원을 제기함",
    "처벌이 가능할 정도의 중대한 위법 행위",
    "분쟁조정·중재·법률지원을 받아도 학교에서 해결하기 어려움",
    "학교의 정상적인 교육활동에 심각한 지장을 줌",
]
FORM_CATEGORIES = ["교무/학사", "학부모/교직원 소통", "기타", "생활지도/상담", "학교 운영"]    # 서식의 제기대상 분류(서식 순서)
# 담당 부서 -> 서식의 제기대상 분류. 서식은 5분류라 부서 체계와 1:1이 아니며 자동 제안일 뿐이다.
DEPT_TO_FORM = {"교무기획부": "교무/학사", "교수학습지원부": "교무/학사", "고교학점제운영부": "교무/학사",
                "학생생활안전부": "생활지도/상담", "창의진로상담부": "생활지도/상담", "보건실": "생활지도/상담",
                "1학년부": "학부모/교직원 소통", "2학년부": "학부모/교직원 소통", "3학년부": "학부모/교직원 소통",
                "학년부(학년 확인 필요)": "학부모/교직원 소통",
                "행정실": "학교 운영", "급식실": "학교 운영", "교육정보부": "학교 운영", "예체능교육부": "학교 운영",
                "자연과학교육부": "학교 운영", "인문사회교육부": "학교 운영"}
FORCE_KEYS = {"assault", "weapon", "threat", "damage", "stalking"}      # '위력을 행사하는 경우'에 걸릴 수 있는 유형
GRAVE_SEVERITY = 4                                                        # 처벌 가능할 정도의 중대 사안 후보로 보는 심각도
STATE_MARK = {"해당": "■", "해당 가능": "▲", "확인 필요": "□", "해당 없음": "－"}
INPUT = "(담당자 입력)"


def _sentences(result, h):
    """규칙이 잡은 표현이 들어 있는 원문 문장 전체(문장 부호·줄바꿈 기준). 못 찾으면 감지된 표현만."""
    text = result.get("text_masked", "")
    m = h.get("matched") or ""
    pieces = m if isinstance(m, list) else [x.strip() for x in m.split(";")]
    out = []
    for piece in pieces:
        i = text.find(piece) if piece else -1
        if i < 0:
            continue
        a = max(text.rfind(c, 0, i) for c in ".!?。\n") + 1
        ends = [e for e in (text.find(c, i + len(piece)) for c in ".!?。\n") if e >= 0]
        sent = " ".join(text[a:(min(ends) + 1) if ends else len(text)].split())
        if sent and sent not in out:
            out.append(sent)
    return out or ["".join(pieces) or "-"]


def _quoted(result, h):
    return " / ".join(f"'{x}'" for x in _sentences(result, h))


def _hits(result):
    return [h for h in result.get("malicious", []) if h.get("severity", 0) >= 3]


def checklist(result):
    """5개 이첩 기준마다 {no, text, state, reasons[]}. state: 해당 / 해당 가능 / 확인 필요 / 해당 없음."""
    repeat = result.get("repeat_count", 1)
    hist = result.get("history") or {}
    prior = hist.get("same_student") or []
    closed_before = any(p.get("closed") for p in prior)
    hits = _hits(result)
    force = [h for h in hits if h["key"] in FORCE_KEYS]
    grave = [h for h in hits if h.get("severity", 0) >= GRAVE_SEVERITY]
    out = []

    # 1) 3회 이상 반복 후 종료했는데도 지속 / 위력 행사
    reasons, state = [], "해당 없음"
    if repeat >= 3 and closed_before:
        state = "해당"
        ids = ", ".join(f"#{p['id']}" for p in prior if p.get("closed")) or "이전 민원"
        reasons.append(f"같은 학생의 동일·유사 민원이 이번까지 {repeat}회째이고, 이전에 종결(거부·종료)한 민원({ids})이 있는데도 다시 제기됨")
    elif repeat >= 3:
        state = "해당 가능"
        reasons.append(f"동일·유사 민원이 이번까지 {repeat}회째입니다. 이전 민원에 합리적인 답변을 하고 종료했는지 확인이 필요합니다")
    if force:
        state = state if state == "해당" else "해당 가능"
        reasons.append("위력 행사 가능성: " + "; ".join(f"{h['label']} - 감지된 문장 {_quoted(result, h)}" for h in force))
    out.append((state, reasons or ["3회 이상 반복·위력 행사에 해당하는 자동 감지 결과가 없습니다"]))

    # 2) 퇴거명령·민원 제한에도 불응하고 지속 제기 (학교가 한 조치는 시스템이 모른다)
    pm = hist.get("prior_malicious", 0)
    r2 = ["학교장의 퇴거명령·민원 제한 조치 여부와 그 이후의 불응·지속 제기는 시스템에 기록이 없어 담당자가 확인해야 합니다"]
    if pm:
        r2.append(f"참고: 같은 학생의 과거 특이 민원 의심 민원이 {pm}건 있습니다")
    out.append(("확인 필요", r2))

    # 3) 처벌 가능한 중대 사안
    if grave:
        sure = all(h.get("confident", True) for h in grave)
        out.append(("해당" if sure else "해당 가능",
                    [f"{h['label']}(심각도 {h['severity']}) - 감지된 문장 {_quoted(result, h)}" for h in grave]
                    + ["처벌 가능 여부와 적용 법령은 교육(지원)청·법률 검토로 확정해야 합니다"]))
    else:
        out.append(("해당 없음", ["처벌 가능한 중대 사안으로 볼 만한 유형(심각도 4 이상)이 감지되지 않았습니다"]))

    # 4) 분쟁조정·중재·법률지원을 받았는데도 해결 불가
    out.append(("확인 필요", ["학교가 분쟁조정·중재·법률지원을 받았는지는 시스템에 기록이 없어 담당자가 확인해야 합니다"]))

    # 5) 정상적인 교육활동에 심각한 지장
    r5, st5 = [], "확인 필요"
    if any(h["key"] == "stalking" for h in hits):
        st5 = "해당 가능"
        r5.append("스토킹 유형이 감지되어 교직원 업무·교육활동에 지장을 줄 가능성이 있습니다")
    if repeat >= 3:
        st5 = "해당 가능"
        r5.append(f"동일·유사 민원이 {repeat}회째 반복되어 담당 교직원의 업무에 지장을 줄 가능성이 있습니다")
    r5.append("실제로 교육활동에 심각한 지장이 있었는지는 담당자가 사실을 확인해야 합니다")
    out.append((st5, r5))
    return [{"no": i + 1, "text": CRITERIA[i], "short": CRITERIA_SHORT[i], "state": s, "reasons": r} for i, (s, r) in enumerate(out)]


def _ymd(created):
    """'2026-10-29 06:06' -> '2026. 10. 29.' (서식의 날짜 표기). 형식이 다르면 그대로."""
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", created or "")
    return f"{m.group(1)}. {int(m.group(2))}. {int(m.group(3))}." if m else (created or "")


def _target(result):
    """서식의 '제기대상'(민원이 향한 대상). 민원에 담임·교사·관리자가 나오면 그 대상, 아니면 담당 부서."""
    text, dept = result.get("text_masked", ""), result.get("department", "")
    who = ("담임 교사" if "담임" in text else "관리자(교장·교감)" if re.search(r"교장|교감", text)
           else "교사" if re.search(r"선생님|교사", text) else "")
    return f"{who} ({dept})" if who and dept else (who or dept)


def _short(text, n=120):
    text = " ".join((text or "").split())
    return text[:n] + ("…" if len(text) > n else "")


def build_transfer(result, complaint=None, school_name="", prior_texts=None):
    """보고서 내용. result는 분류 결과, complaint는 store.get_complaint 결과(있으면 처리 경과·접수일을 쓴다)."""
    cl = checklist(result)
    chosen = [c for c in cl if c["state"] in ("해당", "해당 가능")]
    dept = result.get("department", "")
    form_cat = DEPT_TO_FORM.get(dept, "기타")
    student = result.get("student")
    m = re.match(r"(.+)\((\d{3})\)$", student or "")
    name, cls = (m.group(1), m.group(2)) if m else ("", "")
    klass = f"{cls[0]}학년 {int(cls[1:])}반({cls})" if cls else ""
    hist = result.get("history") or {}
    created = (complaint or {}).get("created_at") or "접수 시각 미기록"

    # 민원 제기 및 처리내용: 과거 같은 학생의 유사 민원 -> 이번 민원 순. 내용은 원문 그대로(개인정보 마스킹만 적용)를 쓴다.
    lines, rows = [], []
    prior_texts = prior_texts or {}
    for p in sorted(hist.get("same_student") or [], key=lambda p: p["id"]):
        outcome = "종결(거부·종료) 처리" if p.get("closed") else "접수·처리"
        body = _short(prior_texts.get(p["id"]) or p.get("snippet_raw") or p["snippet"], 400)
        lines.append(f"{p['created_at'][:10]} · 민원 #{p['id']}: {body} → {outcome}")
        rows.append((_ymd(p["created_at"]), [f"· {body}", f"   → {outcome}"]))
    cid = result.get("complaint_id")
    treated = [e["note"] for e in (complaint or {}).get("events", []) if e.get("note")]
    now_out = " / ".join(treated[:3]) if treated else f"{result.get('route_label', '')}, 담당 {result.get('handler', '')}"
    now_body = _short(result.get("text_masked"), 600)
    lines.append(f"{created[:10]} · 이번 민원{f' #{cid}' if cid else ''}: {now_body} → {now_out}")
    rows.append((_ymd(created), [f"· {now_body}", f"   → {now_out}"]))

    # 이첩 사유 (작성예시 문형을 따르고, 해당 기준 번호를 적는다)
    if chosen:
        why = ["매뉴얼 12쪽 '지원 요청 및 이첩 기준(안)' 중 다음에 해당합니다."]
        why += [f"- {c['short']} [{c['state']}]: {'; '.join(c['reasons'][:2])}" for c in chosen]
        todo = [c["short"] for c in cl if c["state"] == "확인 필요"]
        if todo:
            why.append("※ 학교 기록으로 담당자가 확인할 사항: " + " / ".join(todo))
        if result.get("repeat_count", 1) >= 3:
            why.append(f"(작성예시 문형) 합리적인 답변을 했음에도 불구하고 3회 이상 동일·유사한 민원을 지속 제기하여 처리를 요구하거나 "
                       f"위력을 행사하였기에 이첩 및 지원 요청합니다 (동일·유사 민원 {result.get('repeat_count')}회째).")
    else:
        why = ["현재 자동 판단으로는 이첩 기준에 해당하는 항목이 없습니다. 이첩이 필요하다고 판단한 사유를 담당자가 직접 적어 주세요."]
    effort = [f"[{e['created_at']}] {e['kind']}{' · ' + e['status'] if e.get('status') else ''}{': ' + e['note'] if e.get('note') else ''}"
              for e in (complaint or {}).get("events", []) if e["kind"] != "접수"]
    efforts = effort or [INPUT + " (학교 자체 해결 노력: 답변·면담·경고문 발송 등)"]
    asks = []       # 교육(지원)청에 요청할 사항(초안): 선택된 기준과 대응 단계에서 끌어온다
    if 1 in [c["no"] for c in chosen]:
        asks.append("동일·유사 민원 반복 및 위력 행사 우려에 대한 이첩 접수와 향후 민원 처리 방향 협의")
    if 3 in [c["no"] for c in chosen]:
        asks.append("고소·고발 등 법적 조치 협의 및 법률 지원 (매뉴얼 50쪽 '학교장 대응' 단계: 교육(지원)청 관련 부서와 협의)")
    if 5 in [c["no"] for c in chosen]:
        asks.append("피해 교직원 보호조치와 교육활동 침해행위 해당 여부 검토 지원")
    if any("출입·면담 제한" in a["text"] for a in result.get("actions", [])):
        asks.append("출입·면담 제한 등 접촉 차단 방안 검토")
    requests = [f"- {x}" for x in asks] + ["(위 내용은 선택된 기준으로 만든 초안입니다. 학교 상황에 맞게 고쳐 주세요)"] if asks else [INPUT]
    return {"school": school_name or INPUT, "category": form_cat, "target": _target(result), "history_rows": rows, "form_categories": FORM_CATEGORIES,
            "dept": dept, "student_name": name or INPUT, "class_info": klass or INPUT,
            "guardian_name": INPUT, "guardian_contact": INPUT, "history_lines": lines,
            "reason_lines": why, "effort_lines": efforts, "request_lines": requests,
            "checklist": cl, "chosen": [c["no"] for c in chosen]}


# ---- 서식 파일(data/특이민원_지원요청보고서_서식.hwpx)을 채우는 방식 ----
# HWPX는 zip 안의 XML이다. Contents/section0.xml의 표 칸(hp:tc)에서 글만 바꾸고 나머지 파일은 그대로 복사한다.
TEMPLATE_PATH = "data/특이민원_지원요청보고서_서식.hwpx"
HP = "http://www.hancom.co.kr/hwpml/2011/paragraph"
HISTORY_ROW_FIRST, HISTORY_SLOTS = 4, 7                # 서식의 '민원제기 및 처리내용' 줄(4행부터 7줄)
MAX_HISTORY_ROWS = 14                                  # 이보다 많으면 최근 것만 쓴다


def _q(tag):
    return f"{{{HP}}}{tag}"


def _cell(tbl, row, col):
    for tc in tbl.iter(_q("tc")):
        a = tc.find(_q("cellAddr"))
        if a.get("rowAddr") == str(row) and a.get("colAddr") == str(col):
            return tc
    raise KeyError((row, col))


def _set_p(p, text):
    """문단의 글을 text로 바꾼다. 글자 모양(첫 run)은 그대로 쓰고, 줄 나눔 캐시(linesegarray)는 지워 한글이 다시 계산하게 한다."""
    from lxml import etree
    for la in p.findall(_q("linesegarray")):
        p.remove(la)
    runs = p.findall(_q("run"))
    run = runs[0]
    for r in runs[1:]:
        p.remove(r)
    for t in run.findall(_q("t")):
        run.remove(t)
    if text:
        etree.SubElement(run, _q("t")).text = text


def _set_cell(tc, lines):
    """칸의 글을 lines(문자열 또는 목록)로 바꾼다. 첫 문단을 복사해 문단을 늘리므로 글꼴·간격이 유지된다."""
    import copy
    lines = [x for ln in (lines if isinstance(lines, list) else [lines]) for x in str(ln).split("\n")] or [""]
    sub = tc.find(_q("subList"))
    paras = sub.findall(_q("p"))
    proto = copy.deepcopy(paras[0])
    for p in paras[1:]:
        sub.remove(p)
    _set_p(paras[0], lines[0])
    prev = paras[0]
    for ln in lines[1:]:
        p = copy.deepcopy(proto)
        _set_p(p, ln)
        prev.addnext(p)
        prev = p


def _check_category(tc, category):
    """제기대상 분류 칸에서 해당 분류의 '□'를 '■'로 바꾼다."""
    for p in tc.iter(_q("p")):
        for t in p.iter(_q("t")):
            if t.text and f"□ {category}" in t.text:
                t.text = t.text.replace(f"□ {category}", f"■ {category}")
                for la in p.findall(_q("linesegarray")):
                    p.remove(la)


def _add_history_rows(tbl, extra):
    """'민원제기 및 처리내용' 줄이 서식의 7줄보다 많으면 마지막 줄을 복사해 늘린다(아래 줄의 행 번호·병합 칸도 함께 조정)."""
    import copy
    if extra <= 0:
        return
    trs = tbl.findall(_q("tr"))
    last_row = HISTORY_ROW_FIRST + HISTORY_SLOTS - 1
    tr = next(t for t in trs if any(tc.find(_q("cellAddr")).get("rowAddr") == str(last_row) for tc in t.findall(_q("tc"))))
    for tc in (c for t in trs for c in t.findall(_q("tc"))):          # 아래 줄의 행 번호를 밀어 둔다
        a = tc.find(_q("cellAddr"))
        if int(a.get("rowAddr")) > last_row:
            a.set("rowAddr", str(int(a.get("rowAddr")) + extra))
    prev = tr
    for k in range(extra):
        clone = copy.deepcopy(tr)
        for tc in clone.findall(_q("tc")):
            tc.find(_q("cellAddr")).set("rowAddr", str(last_row + 1 + k))
        prev.addnext(clone)
        prev = clone
    label = _cell(tbl, HISTORY_ROW_FIRST, 0).find(_q("cellSpan"))        # '민원제기 및 처리내용' 세로 병합 칸
    label.set("rowSpan", str(int(label.get("rowSpan")) + extra))
    tbl.set("rowCnt", str(int(tbl.get("rowCnt")) + extra))


def fill_hwpx(t, template, path):
    """한글 서식 파일(.hwpx)의 빈칸만 채워 저장한다(표·글꼴·안내 문구 유지, '(작성예시)'·예시 민원은 지운다)."""
    import zipfile

    from lxml import etree
    with zipfile.ZipFile(template) as zin:
        root = etree.fromstring(zin.read("Contents/section0.xml"))
        tbl = next(root.iter(_q("tbl")))
        hist = t["history_rows"][-MAX_HISTORY_ROWS:]
        extra = max(len(hist) - HISTORY_SLOTS, 0)
        _add_history_rows(tbl, extra)
        _set_cell(_cell(tbl, 0, 2), t["school"])
        _set_cell(_cell(tbl, 1, 2), t["target"])
        _check_category(_cell(tbl, 1, 5), t["category"])
        _set_cell(_cell(tbl, 2, 2), t["student_name"])
        _set_cell(_cell(tbl, 2, 5), t["class_info"])
        _set_cell(_cell(tbl, 3, 2), t["guardian_name"])
        _set_cell(_cell(tbl, 3, 5), t["guardian_contact"])
        for k in range(HISTORY_SLOTS + extra):
            date, body = hist[k] if k < len(hist) else ("", [""])
            _set_cell(_cell(tbl, HISTORY_ROW_FIRST + k, 2), date)
            _set_cell(_cell(tbl, HISTORY_ROW_FIRST + k, 3), body)
        _set_cell(_cell(tbl, 11 + extra, 2), t["reason_lines"] + ["", "학교 자체 해결 노력:"] + t["effort_lines"])
        _set_cell(_cell(tbl, 12 + extra, 2), t["request_lines"])
        section = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)
        with zipfile.ZipFile(path, "w") as zout:                          # mimetype을 맨 앞에 압축 없이(원본과 같은 순서·방식)
            for info in zin.infolist():
                data = section if info.filename == "Contents/section0.xml" else zin.read(info.filename)
                zi = zipfile.ZipInfo(info.filename, info.date_time)
                zi.compress_type = info.compress_type
                zout.writestr(zi, data)
    return path


def to_hwpx(t, path, template=None):
    """보고서를 한글 파일(.hwpx)로 쓴다. 서식 파일(기본 data/특이민원_지원요청보고서_서식.hwpx)이 없으면 FileNotFoundError."""
    import os
    tpl = template or TEMPLATE_PATH
    if not os.path.isfile(tpl):
        raise FileNotFoundError(f"이첩 보고서 서식 파일이 없습니다: {tpl}")
    return fill_hwpx(t, tpl, path)
