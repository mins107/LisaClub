"""근거를 PDF에 형광펜으로 칠하고, 분류 결과 HTML 화면(리포트)을 만든다."""
import html
import os

import pymupdf

COLORS = {"reject": (1, 0.9, 0.2), "malicious": (1, 0.55, 0.55),
          "procedure": (0.6, 0.95, 0.6), "reply": (0.65, 0.8, 1)}
CSS = {"reject": "#ffe94d", "malicious": "#ff9c9c", "procedure": "#a6f2a6", "reply": "#a6ccff"}
ROLE_NAME = {"reject": "거부·종결 사유", "malicious": "특이민원 유형", "procedure": "처리 절차", "reply": "답변"}
# 매뉴얼 근거를 두 묶음으로 나눈다: 민원이 어떤 유형인지(판정 근거) / 어떻게 처리하는지(절차 근거)
EV_GROUP = {"reject": "type", "malicious": "type", "procedure": "proc", "reply": "proc"}


def annotate(pdf_path, used, out_dir):
    """근거가 있는 쪽만 골라 형광펜과 근거 번호(E1…)를 칠한 PDF를 만든다. 반환: pdf 경로."""
    os.makedirs(out_dir, exist_ok=True)
    doc = pymupdf.open(pdf_path)
    for u in used:
        page = doc[u.ev.page - 1]
        for r in u.ev.rects:
            a = page.add_highlight_annot(pymupdf.Rect(r))
            a.set_colors(stroke=COLORS[u.role])
            a.set_info(title=u.label, content=u.reason)
            a.update()
        x0, y0 = min(((r[0], r[1]) for r in u.ev.rects), key=lambda t: (round(t[1] / 6), t[0]))
        bx = max(2, x0 - 26)
        badge = pymupdf.Rect(bx, y0 - 1, bx + 24, y0 + 12)
        page.draw_rect(badge, color=None, fill=(0.75, 0.1, 0.1))
        page.insert_text((bx + 3, y0 + 9), u.label, fontsize=7.5, color=(1, 1, 1), fontname="helv")
    out_pdf = os.path.join(out_dir, "evidence_highlighted.pdf")
    doc.select(sorted({u.ev.page - 1 for u in used}))
    doc.save(out_pdf)
    return out_pdf


ROUTE_SHORT = {"REJECTABLE": "거부·종결 가능", "HANDLE": "일반 처리", "ESCALATE": "악성 의심 · 이첩 검토"}
ROUTE_COLOR = {"REJECTABLE": "var(--amber)", "HANDLE": "var(--green)", "ESCALATE": "var(--red)"}
URGENCY_CLASS = {"낮음": "low", "보통": "mid", "높음": "high", "긴급": "crit"}

STYLE = """
:root{--bg:#f4f5f7;--card:#fff;--text:#1f2937;--muted:#6b7280;--border:#e5e7eb;--soft:#f9fafb;--primary:#2563eb;
--amber:#b45309;--green:#15803d;--red:#b91c1c;--blue:#1d4ed8;--on-c:#fff;--warn-bg:#fffbeb;--warn-text:#92400e;
--err-bg:#fef2f2;--err-text:#991b1b}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#181b22;--text:#e5e7eb;--muted:#9ca3af;--border:#2b303b;
--soft:#1f232c;--primary:#3b82f6;--amber:#f59e0b;--green:#4ade80;--red:#f87171;--blue:#60a5fa;--on-c:#111;
--warn-bg:#3a2f12;--warn-text:#fcd34d;--err-bg:#3b1618;--err-text:#fca5a5}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);line-height:1.55;
font-family:'Pretendard','Malgun Gothic','Apple SD Gothic Neo',sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:0 16px} main.wrap{padding-top:16px;padding-bottom:48px}
.topbar{background:var(--card);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:5}
.topbar .wrap{display:flex;align-items:baseline;gap:12px;padding-top:11px;padding-bottom:11px}
.topbar b{font-size:1.1em;white-space:nowrap} .topbar span{color:var(--muted);font-size:.85em}
.topbar .btn{white-space:nowrap} @media(max-width:600px){.topbar span{display:none}}
.box,.summary{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px 18px;margin-bottom:14px}
h2{margin:0 0 10px;font-size:1.02em} h3{margin:0 0 10px;font-size:.98em}
.sec-title{font-size:.78em;color:var(--muted);font-weight:700;margin:0 0 6px}
.muted,small{color:var(--muted)} pre{white-space:pre-wrap;margin:0;font-family:inherit;word-break:break-word}
mark{padding:1px 3px;border-radius:4px;color:#111} sup{font-size:.65em;color:#b91c1c;font-weight:700}
/* 요약 */
.summary{border-left:8px solid var(--c)} .sum-head{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px}
.badge{display:inline-block;color:var(--on-c);background:var(--c);border-radius:18px;padding:4px 16px;font-weight:800;font-size:1.12em}
.sum-label{font-weight:600} .banner{margin-top:12px;padding:8px 12px;border-radius:8px;background:var(--warn-bg);color:var(--warn-text);font-size:.92em}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(138px,1fr));gap:10px;margin-top:14px}
.tile{background:var(--soft);border:1px solid var(--border);border-radius:10px;padding:8px 12px}
.tile dt{font-size:.75em;color:var(--muted)} .tile dd{margin:2px 0 0;font-weight:700}
.pill{display:inline-block;border-radius:12px;padding:1px 10px;font-weight:800;font-size:.92em;color:var(--on-c)}
.low{background:var(--green)} .mid{background:var(--blue)} .high{background:var(--amber)} .crit{background:var(--red)}
/* 지금 할 일: 단계별 체크리스트 */
.phases{list-style:none;margin:0;padding:0;display:grid;gap:10px}
.phase{border:1px solid var(--border);border-radius:10px;padding:8px 12px;background:var(--soft)}
.phase-name{font-size:.8em;font-weight:800;color:var(--muted);margin-bottom:2px}
.phase-name i{font-style:normal;display:inline-block;width:20px;height:20px;line-height:20px;text-align:center;border-radius:50%;
background:var(--text);color:var(--card);margin-right:6px;font-size:.95em}
.steps{list-style:none;margin:0;padding:0} .steps li{padding:4px 0;border-top:1px dashed var(--border)} .steps li:first-child{border-top:0}
.steps label{display:flex;flex-wrap:wrap;align-items:baseline;gap:2px 8px;cursor:pointer}
.steps input{margin:0 2px 0 0;align-self:center} .steps input:checked+.st-text{text-decoration:line-through;color:var(--muted)}
.st-text{font-weight:600} .why{font-size:.78em;color:var(--muted)}
.tag{font-size:.72em;background:var(--card);border:1px solid var(--border);border-radius:6px;padding:0 6px;margin-left:2px;
color:var(--muted);font-weight:700;vertical-align:1px;text-decoration:none} a.tag:hover{border-color:var(--primary);color:var(--primary)}
/* 사유 칩 */
.chip{display:inline-block;padding:2px 11px;border-radius:14px;font-size:.88em;font-weight:700;margin:0 6px 6px 0;
background:color-mix(in srgb,var(--k) 15%,transparent);color:var(--k);border:1px solid color-mix(in srgb,var(--k) 35%,transparent)}
.chip.reject{--k:var(--amber)} .chip.mal{--k:var(--red)} .chip.note{--k:var(--muted)}
.rrow{margin-bottom:8px} .legend span{margin-right:12px;font-size:.82em;color:var(--muted)}
.orig{font-size:1.02em;line-height:1.8}
/* 과거 이력 */
.warn{margin:8px 0;padding:7px 12px;border-radius:8px;background:var(--warn-bg);color:var(--warn-text);font-size:.9em}
.tbl{overflow-x:auto;margin-top:8px} .tbl table{width:100%;border-collapse:collapse;font-size:.86em}
.tbl th{text-align:left;color:var(--muted);font-weight:600} .tbl th,.tbl td{padding:5px 8px;border-bottom:1px solid var(--border);white-space:nowrap}
.tbl td:last-child{white-space:normal;min-width:160px}
/* 매뉴얼 근거: 민원 유형 / 처리 절차 */
.cols{display:flex;gap:16px;align-items:flex-start} .col{flex:1;min-width:0} .col.side{flex:0 0 42%}
@media(min-width:901px){.sticky{position:sticky;top:60px;max-height:calc(100vh - 76px);overflow-y:auto;padding-right:2px}}
@media(max-width:900px){.cols{flex-direction:column}.col.side{flex:1;width:100%}}
.ev-tabs{display:flex;gap:6px;margin:0 0 10px;position:sticky;top:0;z-index:2;background:var(--bg);padding:2px 0 6px}
.ev-tab{flex:1;border:1px solid var(--border);background:var(--card);color:var(--text);border-radius:10px;padding:7px 8px;
font:inherit;font-size:.88em;font-weight:700;cursor:pointer} .ev-tab b{margin-left:4px}
.ev-tab.on{border-color:var(--primary);color:var(--primary);box-shadow:inset 0 -3px 0 var(--primary)}
.ev-group{margin-bottom:14px;border-radius:12px;border:1px solid var(--border);background:var(--card);overflow:hidden}
.ev-group>header{padding:9px 14px;border-bottom:1px solid var(--border);border-top:5px solid var(--g)}
.ev-group.type{--g:var(--red)} .ev-group.proc{--g:var(--green)}
.ev-group>header b{display:block;font-size:.98em} .ev-group>header span{font-size:.8em;color:var(--muted)}
.ev-group>.ev-body{padding:10px 10px 2px}
.ev{background:var(--soft);border:1px solid var(--border);border-left:6px solid var(--r);border-radius:10px;padding:9px 13px;margin-bottom:10px;scroll-margin-top:50px}
.ev header{display:flex;flex-wrap:wrap;gap:4px 8px;align-items:center;font-size:.88em}
.ev-label{font-weight:800;background:var(--r);color:#111;border-radius:6px;padding:0 7px}
.ev .role{font-weight:800} .ev .why2{margin:6px 0 4px;font-size:.84em;color:var(--muted)}
.ev blockquote{margin:6px 0 2px;padding:6px 10px;background:var(--card);border-radius:6px;font-size:.9em}
/* 공통 부품 */
details.drawer{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:12px 18px;margin-bottom:14px}
details.drawer>summary{cursor:pointer;font-weight:700} .drawer-body{margin-top:10px}
.btn{display:inline-block;border:1px solid var(--border);background:var(--soft);color:var(--text);border-radius:8px;
padding:4px 12px;font:inherit;font-size:.85em;cursor:pointer;text-decoration:none} .btn:hover{border-color:var(--primary)}
.foot{font-size:.82em;color:var(--muted);margin:4px 0 0}
@media print{.topbar,form,.btn,.noprint,.ev-tabs{display:none!important} body{background:#fff}.sticky{position:static;max-height:none}
.ev-group{display:block!important}}
"""

PAGE_SCRIPT = """
document.addEventListener('click',function(e){
var b=e.target.closest('[data-copy]');
if(b){var el=document.getElementById(b.dataset.copy);if(el&&navigator.clipboard){navigator.clipboard.writeText(el.innerText).then(function(){
var o=b.textContent;b.textContent='복사됨';setTimeout(function(){b.textContent=o},1500)}).catch(function(){})}return}
var tab=e.target.closest('[data-tab]');
if(tab){showTab(tab.dataset.tab);return}
if(e.target.closest('a.tag')){showTab('all')}});
function showTab(name){document.querySelectorAll('[data-tab]').forEach(function(t){t.classList.toggle('on',t.dataset.tab===name)});
document.querySelectorAll('[data-group]').forEach(function(g){g.style.display=(name==='all'||g.dataset.group===name)?'':'none'})}
"""


def _marked_text(result):
    text = result["text_masked"]
    parts, pos = [], 0
    for s in result["spans"]:
        if s["start"] < pos:
            continue
        parts.append(html.escape(text[pos:s["start"]]))
        parts.append(f'<mark style="background:{CSS[s["kind"]]}">{html.escape(text[s["start"]:s["end"]])}'
                     f'<sup>{s["label"]}</sup></mark>')
        pos = s["end"]
    parts.append(html.escape(text[pos:]))
    return "".join(parts)


def _tags(labels):
    """근거 번호. 누르면 오른쪽 매뉴얼 근거 카드로 이동한다."""
    return "".join(f'<a class="tag" href="#ev-{html.escape(l)}">{html.escape(l)}</a>' for l in labels or [])


def _chips(items, cls, with_severity=False):
    out = []
    for i in items:
        sev = f' · 심각도 {i["severity"]}' if with_severity and i.get("severity") else ""
        hint = f' title="감지된 표현: {html.escape(str(i["matched"]))}"' if i.get("matched") else ""
        out.append(f'<span class="chip {cls}"{hint}>{html.escape(i["label"])}{sev}{_tags(i.get("evidence"))}</span>')
    return "".join(out) or '<span class="muted">해당 없음</span>'


def _todo(result):
    """지금 할 일: 안전 확보 -> 증거 확보 -> 응대 -> 보고 -> 후속 조치 순서의 체크리스트. 겹치는 조치는 한 줄로 합쳐져 있다."""
    phases = []
    for a in result["actions"]:
        if not phases or phases[-1][0] != a["phase"]:
            phases.append((a["phase"], []))
        phases[-1][1].append(a)
    if not phases:
        return (f'<p style="margin:0">특별한 현장 조치는 없습니다. <b>{html.escape(result["handler"])}</b>이(가) '
                f'<b>{html.escape(result["deadline"])}</b>에 일반 절차로 처리하세요.</p>')
    out = []
    for n, (name, items) in enumerate(phases, 1):
        steps = "".join(
            f'<li><label><input type="checkbox"><span class="st-text">{html.escape(a["text"])}</span>'
            f'<span class="why">{html.escape(" · ".join(a["reasons"]))}</span>{_tags(a.get("evidence"))}</label></li>'
            for a in items)
        out.append(f'<li class="phase"><div class="phase-name"><i>{n}</i>{html.escape(name)}</div><ul class="steps">{steps}</ul></li>')
    return f'<ol class="phases">{"".join(out)}</ol>'


def _history_box(result):
    """같은 학생의 과거 민원 요약과, 내용이 비슷한 과거 민원 목록."""
    h = result.get("history") or {}
    a = h.get("student")
    head = (f'<b>{html.escape(a["name"])}({html.escape(a["class_no"])})</b> 학생의 이전 민원 {a["total"]}건 '
            f'(악성 의심 {a["escalated"]}건, 최근 {html.escape(a["last_at"] or "-")})') if a else \
        '<span class="muted">이 학생의 이전 민원이 없습니다 (처음 접수했거나 학생 이름·학년반을 입력하지 않았습니다)</span>'
    rows = [(x, "같은 학생") for x in h.get("same_student", [])] + [(x, "다른 학생") for x in h.get("similar_others", [])]
    body = "".join(
        f'<tr><td>#{x["id"]}</td><td>{x["created_at"]}</td><td>{html.escape(x["student"] or "학생 미상")} · {kind}</td>'
        f'<td>{html.escape(ROUTE_SHORT.get(x["route"], x["route"]))}</td><td>{x["similarity"]:.0%}</td>'
        f'<td>{html.escape(x["snippet"])}</td></tr>' for x, kind in rows)
    table = (f'<div class="tbl"><table><tr><th>번호</th><th>접수일</th><th>학생</th><th>당시 분류</th>'
             f'<th>유사도</th><th>내용</th></tr>{body}</table></div>') if rows else ""
    flags = []
    if h.get("recent_closed"):
        rc = h["recent_closed"]
        flags.append(f'종결 직후 재접촉: #{rc["id"]}번 민원({rc["created_at"]})을 종결한 뒤 바로 다시 연락함')
    if h.get("prior_malicious"):
        flags.append(f'과거 악성(특이) 의심 민원 {h["prior_malicious"]}건 이력 (기간 내)')
    flag_html = "".join(f'<div class="warn">{html.escape(f)}</div>' for f in flags)
    return f'<div class="box"><h3>과거 이력</h3>{head}{flag_html}{table}</div>'


def _evidence(result, pdf_href):
    """매뉴얼 근거를 '민원 유형 근거'와 '처리 절차 근거' 두 묶음으로 나눠 보여 준다."""
    groups = {"type": [], "proc": []}
    for e in result["evidence"]:
        groups[EV_GROUP[e["role"]]].append(e)
    meta = {"type": ("민원 유형 근거", "이 민원이 어떤 유형인지(거부·종결 가능, 특이민원) 판단한 근거입니다."),
            "proc": ("처리 절차 근거", "이 민원을 어떻게 처리해야 하는지 알려 주는 매뉴얼 절차입니다.")}
    secs = []
    for g in ("type", "proc"):
        cards = "".join(
            f'<article class="ev" id="ev-{e["label"]}" style="--r:{CSS[e["role"]]}"><header><span class="ev-label">{e["label"]}</span>'
            f'<span class="role">{html.escape(ROLE_NAME[e["role"]])}</span><span class="muted">{html.escape(e["cite"])}</span></header>'
            f'<p class="why2">연결된 판정: {html.escape(e["reason"])}</p><blockquote>{html.escape(e["text"])}</blockquote></article>'
            for e in groups[g]) or '<p class="muted" style="margin:0 0 10px">해당하는 근거가 없습니다.</p>'
        secs.append(f'<section class="ev-group {g}" data-group="{g}"><header><b>{meta[g][0]} ({len(groups[g])})</b>'
                    f'<span>{meta[g][1]}</span></header><div class="ev-body">{cards}</div></section>')
    n = len(result["evidence"])
    tabs = (f'<div class="ev-tabs" role="tablist"><button type="button" class="ev-tab on" data-tab="all">전체<b>{n}</b></button>'
            f'<button type="button" class="ev-tab" data-tab="type">민원 유형<b>{len(groups["type"])}</b></button>'
            f'<button type="button" class="ev-tab" data-tab="proc">처리 절차<b>{len(groups["proc"])}</b></button></div>')
    pdf = (f'<p style="margin:0 0 10px"><a class="btn" href="{html.escape(pdf_href)}" target="_blank">'
           f'형광펜 표시된 매뉴얼 PDF 열기</a></p>') if pdf_href else ""
    return f'<h3>매뉴얼 근거 ({n})</h3>{pdf}{tabs}{"".join(secs)}' if n else '<h3>매뉴얼 근거</h3><p class="muted">검색된 근거가 없습니다.</p>'


def render_body(result, pdf_href=None):
    """분류 결과 화면: 요약 -> 지금 할 일 -> (원문·사유·이력·초안 | 매뉴얼 근거). 웹 페이지와 report.html이 함께 쓴다."""
    route, color = result["route"], ROUTE_COLOR[result["route"]]
    urg = result["urgency"]
    tiles = [("긴급도", f'<span class="pill {URGENCY_CLASS.get(urg, "mid")}">{html.escape(urg)}</span>'),
             ("민원 대상 학생", html.escape(result.get("student") or "학생 미상")),
             ("분류 (담당 부서)", html.escape(result["department"])), ("처리 담당", html.escape(result["handler"])),
             ("처리 기한", html.escape(result["deadline"])), ("동일·유사 민원", f"{result['repeat_count']}회째"),
             ("민원 번호", f"#{result['complaint_id']}" if result.get("complaint_id") else "저장 안 함")]
    dl = "".join(f'<div class="tile"><dt>{k}</dt><dd>{v}</dd></div>' for k, v in tiles)
    review = ('<div class="banner"><b>사람 확인 필요</b> · 자동 판정이 확실하지 않거나 상위 조치가 필요한 건입니다. '
              '아래 사유와 매뉴얼 근거를 확인한 뒤 처리하세요.</div>') if result["needs_human_review"] else ""
    notes = "".join(f'<span class="chip note">{html.escape(n)}</span>' for n in result["notes"])
    legend = "".join(f'<span><mark style="background:{CSS[k]}">&nbsp;&nbsp;&nbsp;</mark> {n}</span>'
                     for k, n in ROLE_NAME.items() if k in ("reject", "malicious"))
    copy = lambda i: f'<button type="button" class="btn" data-copy="{i}">복사</button>'  # noqa: E731
    transfer = (f'<details class="drawer"><summary>교육(지원)청 이첩 보고서 초안</summary><div class="drawer-body">'
                f'{copy("transfer-text")}<pre id="transfer-text" style="margin-top:8px">{html.escape(result["transfer_doc"])}'
                f'</pre></div></details>') if result["transfer_doc"] else ""
    return f"""
<section class="summary" id="result" style="--c:{color}"><div class="sum-head"><span class="badge">{ROUTE_SHORT[route]}</span>
<span class="sum-label">{html.escape(result['route_label'])}</span></div>{review}
<dl class="tiles" style="margin-bottom:0">{dl}</dl></section>
<div class="box"><h2>지금 할 일 <small>(해 둔 항목은 체크하세요)</small></h2>{_todo(result)}</div>
<div class="cols"><div class="col">
<div class="box"><h3>민원 원문 <small>(개인정보 마스킹)</small></h3><pre class="orig">{_marked_text(result)}</pre>
<div class="legend" style="margin-top:10px">{legend}</div></div>
<div class="box"><h3>분류 사유</h3>
<div class="rrow"><div class="sec-title">거부·종결 가능 사유</div>{_chips(result['reject'], 'reject')}</div>
<div class="rrow"><div class="sec-title">특이민원 유형</div>{_chips(result['malicious'], 'mal', True)}</div>
{f'<div class="rrow"><div class="sec-title">참고 (맥락 확인 필요)</div>{notes}</div>' if notes else ''}
<div class="foot">칩에 마우스를 올리면 감지된 표현이 보이고, E1·E2 같은 번호를 누르면 오른쪽 매뉴얼 근거로 이동합니다.</div></div>
{_history_box(result)}
<details class="drawer"><summary>답변·경고 초안</summary><div class="drawer-body">{copy("reply-text")}
<pre id="reply-text" style="margin-top:8px">{html.escape(result['reply_draft'])}</pre></div></details>
{transfer}
<p class="foot">※ 자동 판정은 후보 제시용이며 최종 판단은 학교장(민원대응팀)이 한다.</p></div>
<div class="col side"><div class="sticky">{_evidence(result, pdf_href)}</div></div></div>"""


def render_page(result, pdf_href=None):
    return (f'<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>민원 분류 결과</title><style>{STYLE}</style>'
            f'<header class="topbar"><div class="wrap"><b>학교 민원 분류 결과</b></div></header>'
            f'<main class="wrap">{render_body(result, pdf_href)}</main><script>{PAGE_SCRIPT}</script>')


def render_html(result, out_path, pdf_href=None):
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(render_page(result, pdf_href))
