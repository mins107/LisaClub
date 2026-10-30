"""근거를 PDF에 형광펜으로 칠하고, 카피킬러식 HTML 리포트를 만든다."""
import base64
import html
import os

import pymupdf

from .rules import EXCITE_CAUTION, EXCITE_HIGH

COLORS = {"reject": (1, 0.9, 0.2), "malicious": (1, 0.55, 0.55),
          "procedure": (0.6, 0.95, 0.6), "reply": (0.65, 0.8, 1)}
CSS = {"reject": "#ffe94d", "malicious": "#ff9c9c", "procedure": "#a6f2a6", "reply": "#a6ccff"}
ROLE_NAME = {"reject": "거부·종결 사유", "malicious": "특이민원 유형", "procedure": "처리 절차", "reply": "답변"}


def annotate(pdf_path, used, out_dir):
    """형광펜 PDF(근거 쪽만)와 근거별 확대 이미지를 만든다. 반환: (pdf경로, {label: png bytes})."""
    os.makedirs(out_dir, exist_ok=True)
    doc = pymupdf.open(pdf_path)
    snippets = {}
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
    for u in used:
        page = doc[u.ev.page - 1]
        ys = [r[1] for r in u.ev.rects] + [r[3] for r in u.ev.rects]
        clip = pymupdf.Rect(20, max(0, min(ys) - 40), page.rect.width - 20, min(page.rect.height, max(ys) + 40))
        snippets[u.label] = page.get_pixmap(clip=clip, matrix=pymupdf.Matrix(1.6, 1.6), annots=True).tobytes("png")
    out_pdf = os.path.join(out_dir, "evidence_highlighted.pdf")
    doc.select(sorted({u.ev.page - 1 for u in used}))
    doc.save(out_pdf)
    return out_pdf, snippets


ROUTE_SHORT = {"REJECTABLE": "거부·종결 가능", "HANDLE": "일반 처리", "ESCALATE": "악성 의심 · 이첩 검토"}
ROUTE_COLOR = {"REJECTABLE": "var(--amber)", "HANDLE": "var(--green)", "ESCALATE": "var(--red)"}
URGENCY_CLASS = {"낮음": "low", "보통": "mid", "높음": "high", "긴급": "crit"}
LEVEL_CLASS = {"낮음": "low", "주의": "mid", "고위험": "crit"}

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
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:14px}
.tile{background:var(--soft);border:1px solid var(--border);border-radius:10px;padding:8px 12px}
.tile dt{font-size:.75em;color:var(--muted)} .tile dd{margin:2px 0 0;font-weight:700}
.pill{display:inline-block;border-radius:12px;padding:1px 10px;font-weight:800;font-size:.92em;color:var(--on-c)}
.low{background:var(--green)} .mid{background:var(--blue)} .high{background:var(--amber)} .crit{background:var(--red)}
.excite{margin-top:12px;padding:10px 12px;background:var(--soft);border:1px solid var(--border);border-radius:10px}
.excite-head{display:flex;justify-content:space-between;align-items:center;gap:8px;font-weight:700}
.gauge{position:relative;height:10px;border-radius:6px;background:var(--border);margin:8px 0 4px;overflow:hidden}
.gauge-fill{height:100%;border-radius:6px} .gauge i{position:absolute;top:0;bottom:0;width:2px;background:var(--card)}
.gauge-note{font-size:.78em;color:var(--muted)} .excite details{margin-top:6px;font-size:.88em}
.excite summary{cursor:pointer;color:var(--primary)}
/* 지금 할 일 */
.todo{margin:0;padding-left:22px} .todo li{margin:4px 0}
/* 사유 칩 */
.chip{display:inline-block;padding:2px 11px;border-radius:14px;font-size:.88em;font-weight:700;margin:0 6px 6px 0;
background:color-mix(in srgb,var(--k) 15%,transparent);color:var(--k);border:1px solid color-mix(in srgb,var(--k) 35%,transparent)}
.chip.reject{--k:var(--amber)} .chip.mal{--k:var(--red)} .chip.note{--k:var(--muted)}
.tag{font-size:.72em;background:var(--soft);border:1px solid var(--border);border-radius:6px;padding:0 6px;margin-left:5px;
color:var(--muted);font-weight:600;vertical-align:1px}
.rrow{margin-bottom:8px} .legend span{margin-right:12px;font-size:.82em;color:var(--muted)}
.orig{font-size:1.02em;line-height:1.8}
/* 과거 이력 */
.warn{margin:8px 0;padding:7px 12px;border-radius:8px;background:var(--warn-bg);color:var(--warn-text);font-size:.9em}
.tbl{overflow-x:auto;margin-top:8px} .tbl table{width:100%;border-collapse:collapse;font-size:.86em}
.tbl th{text-align:left;color:var(--muted);font-weight:600} .tbl th,.tbl td{padding:5px 8px;border-bottom:1px solid var(--border);white-space:nowrap}
.tbl td:last-child{white-space:normal;min-width:160px}
/* 근거 카드 */
.cols{display:flex;gap:16px;align-items:flex-start} .col{flex:1;min-width:0} .col.side{flex:0 0 42%}
@media(min-width:901px){.sticky{position:sticky;top:60px;max-height:calc(100vh - 76px);overflow-y:auto;padding-right:2px}}
@media(max-width:900px){.cols{flex-direction:column}.col.side{flex:1;width:100%}}
.ev{background:var(--card);border:1px solid var(--border);border-left:6px solid var(--r);border-radius:10px;padding:10px 14px;margin-bottom:10px}
.ev header{display:flex;flex-wrap:wrap;gap:4px 8px;align-items:center;font-size:.88em}
.ev-label{font-weight:800;background:var(--r);color:#111;border-radius:6px;padding:0 7px}
.ev .why{margin:6px 0 4px;font-size:.88em;color:var(--muted)} .ev blockquote{margin:6px 0;padding:6px 10px;background:var(--soft);
border-radius:6px;font-size:.9em} .ev details{margin-top:6px} .ev summary{cursor:pointer;font-size:.86em;color:var(--primary)}
.ev img{width:100%;margin-top:6px;border-radius:6px}
/* 공통 부품 */
details.drawer{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:12px 18px;margin-bottom:14px}
details.drawer>summary{cursor:pointer;font-weight:700} .drawer-body{margin-top:10px}
.btn{display:inline-block;border:1px solid var(--border);background:var(--soft);color:var(--text);border-radius:8px;
padding:4px 12px;font:inherit;font-size:.85em;cursor:pointer;text-decoration:none} .btn:hover{border-color:var(--primary)}
.foot{font-size:.82em;color:var(--muted);margin:4px 0 0}
@media print{.topbar,form,.btn,.noprint{display:none!important} body{background:#fff}.sticky{position:static;max-height:none}}
"""

PAGE_SCRIPT = """
document.addEventListener('click',function(e){var b=e.target.closest('[data-copy]');if(!b)return;
var el=document.getElementById(b.dataset.copy);if(!el||!navigator.clipboard)return;
navigator.clipboard.writeText(el.innerText).then(function(){var o=b.textContent;b.textContent='복사됨';
setTimeout(function(){b.textContent=o},1500)}).catch(function(){})});
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
    return "".join(f'<span class="tag">{html.escape(l)}</span>' for l in labels or [])


def _chips(items, cls, with_severity=False):
    out = []
    for i in items:
        sev = f' · 심각도 {i["severity"]}' if with_severity and i.get("severity") else ""
        hint = f' title="감지된 표현: {html.escape(str(i["matched"]))}"' if i.get("matched") else ""
        out.append(f'<span class="chip {cls}"{hint}>{html.escape(i["label"])}{sev}{_tags(i.get("evidence"))}</span>')
    return "".join(out) or '<span class="muted">해당 없음</span>'


def _excite(result):
    ex = result["excitement"]
    cls = LEVEL_CLASS[ex["level"]]
    factors = "".join(f'<li>{html.escape(f["label"])} ×{f["count"]} = +{f["points"]}점</li>' for f in ex.get("factors", []))
    why = (f'<details><summary>점수가 이렇게 나온 이유</summary><ul style="margin:6px 0 0;padding-left:20px">{factors}</ul></details>'
           if factors else '<div class="gauge-note">격한 표현, 느낌표, 욕설 등이 감지되지 않았습니다.</div>')
    return (f'<div class="excite"><div class="excite-head"><span>흥분도 {ex["score"]}점</span>'
            f'<span class="pill {cls}">{html.escape(ex["level"])}</span></div>'
            f'<div class="gauge"><div class="gauge-fill {cls}" style="width:{ex["score"]}%"></div>'
            f'<i style="left:{EXCITE_CAUTION}%"></i><i style="left:{EXCITE_HIGH}%"></i></div>'
            f'<div class="gauge-note">{EXCITE_CAUTION}점 이상 주의 · {EXCITE_HIGH}점 이상 고위험 (문장 표현만으로 계산한 참고 지표)</div>{why}</div>')


def _history_box(result):
    """같은 작성자의 과거 민원 요약과, 내용이 비슷한 과거 민원 목록."""
    h = result.get("history") or {}
    a = h.get("author")
    head = (f'<b>{html.escape(a["name"])}(끝 {html.escape(a["last4"])})</b> 님의 이전 민원 {a["total"]}건 '
            f'(악성 의심 {a["escalated"]}건, 최근 {html.escape(a["last_at"] or "-")})') if a else \
        '<span class="muted">작성자 이력 없음 (처음 접수했거나 이름·연락처 끝자리를 입력하지 않았습니다)</span>'
    rows = [(x, "같은 작성자") for x in h.get("same_author", [])] + [(x, "다른 작성자") for x in h.get("similar_others", [])]
    body = "".join(
        f'<tr><td>#{x["id"]}</td><td>{x["created_at"]}</td><td>{kind}</td>'
        f'<td>{html.escape(ROUTE_SHORT.get(x["route"], x["route"]))}</td><td>{x["similarity"]:.0%}</td>'
        f'<td>{html.escape(x["snippet"])}</td></tr>' for x, kind in rows)
    table = (f'<div class="tbl"><table><tr><th>번호</th><th>접수일</th><th>작성자</th><th>당시 분류</th>'
             f'<th>유사도</th><th>내용</th></tr>{body}</table></div>') if rows else ""
    flags = []
    if h.get("recent_closed"):
        rc = h["recent_closed"]
        flags.append(f'종결 직후 재접촉: #{rc["id"]}번 민원({rc["created_at"]})을 종결한 뒤 바로 다시 연락함')
    if h.get("prior_malicious"):
        flags.append(f'과거 악성(특이) 의심 민원 {h["prior_malicious"]}건 이력 (기간 내)')
    flag_html = "".join(f'<div class="warn">{html.escape(f)}</div>' for f in flags)
    return f'<div class="box"><h3>과거 이력</h3>{head}{flag_html}{table}</div>'


def render_body(result, snippets, pdf_href=None):
    """분류 결과 화면: 요약 -> 지금 할 일 -> (원문·사유·이력·초안 | 매뉴얼 근거). 웹 페이지와 report.html이 함께 쓴다."""
    route, color = result["route"], ROUTE_COLOR[result["route"]]
    urg = result["urgency"]
    tiles = [("긴급도", f'<span class="pill {URGENCY_CLASS.get(urg, "mid")}">{html.escape(urg)}</span>'),
             ("분류 (담당 부서)", html.escape(result["department"])), ("처리 담당", html.escape(result["handler"])),
             ("처리 기한", html.escape(result["deadline"])), ("동일·유사 민원", f"{result['repeat_count']}회째"),
             ("민원 번호", f"#{result['complaint_id']}" if result.get("complaint_id") else "저장 안 함")]
    dl = "".join(f'<div class="tile"><dt>{k}</dt><dd>{v}</dd></div>' for k, v in tiles)
    review = ('<div class="banner"><b>사람 확인 필요</b> · 자동 판정이 확실하지 않거나 상위 조치가 필요한 건입니다. '
              '아래 사유와 매뉴얼 근거를 확인한 뒤 처리하세요.</div>') if result["needs_human_review"] else ""

    acts = "".join(f'<li>{html.escape(a["text"])}{_tags(a.get("evidence"))}</li>' for a in result["actions"])
    todo = (f'<ol class="todo">{acts}</ol>' if acts else
            f'<p style="margin:0">특별한 현장 조치는 없습니다. <b>{html.escape(result["handler"])}</b>이(가) '
            f'<b>{html.escape(result["deadline"])}</b>에 일반 절차로 처리하세요.</p>')

    cards = []
    for e in result["evidence"]:
        img = base64.b64encode(snippets[e["label"]]).decode()
        cards.append(
            f'<article class="ev" style="--r:{CSS[e["role"]]}"><header><span class="ev-label">{e["label"]}</span>'
            f'<b>{html.escape(ROLE_NAME[e["role"]])}</b><span class="muted">{html.escape(e["cite"])}</span></header>'
            f'<p class="why">{html.escape(e["reason"])}</p><blockquote>{html.escape(e["text"])}</blockquote>'
            f'<details><summary>매뉴얼 원본 화면 보기</summary><img alt="{e["label"]} 매뉴얼 원본" '
            f'src="data:image/png;base64,{img}"></details></article>')
    pdf = (f'<p style="margin:0 0 10px"><a class="btn" href="{html.escape(pdf_href)}" target="_blank">'
           f'형광펜 표시된 매뉴얼 PDF 열기</a></p>') if pdf_href else ""
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
<dl class="tiles" style="margin-bottom:0">{dl}</dl>{_excite(result)}</section>
<div class="box"><h2>지금 할 일</h2>{todo}</div>
<div class="cols"><div class="col">
<div class="box"><h3>민원 원문 <small>(개인정보 마스킹)</small></h3><pre class="orig">{_marked_text(result)}</pre>
<div class="legend" style="margin-top:10px">{legend}</div></div>
<div class="box"><h3>분류 사유</h3>
<div class="rrow"><div class="sec-title">거부·종결 가능 사유</div>{_chips(result['reject'], 'reject')}</div>
<div class="rrow"><div class="sec-title">특이민원 유형</div>{_chips(result['malicious'], 'mal', True)}</div>
{f'<div class="rrow"><div class="sec-title">참고 (맥락 확인 필요)</div>{notes}</div>' if notes else ''}
<div class="foot">칩에 마우스를 올리면 감지된 표현이 보입니다. E1, E2는 오른쪽 매뉴얼 근거 번호입니다.</div></div>
{_history_box(result)}
<details class="drawer"><summary>답변·경고 초안</summary><div class="drawer-body">{copy("reply-text")}
<pre id="reply-text" style="margin-top:8px">{html.escape(result['reply_draft'])}</pre></div></details>
{transfer}
<p class="foot">※ 자동 판정은 후보 제시용이며 최종 판단은 학교장(민원대응팀)이 한다.</p></div>
<div class="col side"><div class="sticky"><h3>매뉴얼 근거 ({len(result['evidence'])})</h3>{pdf}
{''.join(cards) or '<p class="muted">검색된 근거가 없습니다.</p>'}</div></div></div>"""


def render_page(result, snippets, pdf_href=None):
    return (f'<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>민원 분류 결과</title><style>{STYLE}</style>'
            f'<header class="topbar"><div class="wrap"><b>학교 민원 분류 결과</b></div></header>'
            f'<main class="wrap">{render_body(result, snippets, pdf_href)}</main><script>{PAGE_SCRIPT}</script>')


def render_html(result, snippets, out_path):
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(render_page(result, snippets))
