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


ROUTE_SHORT = {"REJECTABLE": "거부·종결 가능", "HANDLE": "일반 처리", "ESCALATE": "특이 민원 의심 · 이첩 검토"}
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
/* 담임 교사 전달 */
.homeroom{border-left:6px solid var(--blue)} .hr-sum{margin:0 0 10px} .hr-act{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px;margin-top:10px}
.hr-msg{margin-top:10px;padding:10px 12px;border:1px dashed var(--border);border-radius:8px;background:var(--soft);font-size:.9em}
/* 공통 부품 */
details.drawer{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:12px 18px;margin-bottom:14px}
details.drawer>summary{cursor:pointer;font-weight:700} .drawer-body{margin-top:10px}
.btn{display:inline-block;border:1px solid var(--border);background:var(--soft);color:var(--text);border-radius:8px;
padding:4px 12px;font:inherit;font-size:.85em;cursor:pointer;text-decoration:none} .btn:hover{border-color:var(--primary)}
.foot{font-size:.82em;color:var(--muted);margin:4px 0 0}

/* 근거 번호 말풍선 */
.tag[data-tip]{position:relative;cursor:help}
.tag[data-tip]:hover::after,.tag[data-tip]:focus::after{content:attr(data-tip);position:absolute;left:0;bottom:calc(100% + 8px);z-index:30;
width:max-content;max-width:min(340px,80vw);white-space:normal;text-align:left;background:#111827;color:#f9fafb;padding:9px 12px;border-radius:10px;
font-size:.86rem;font-weight:400;line-height:1.55;box-shadow:0 8px 24px rgba(0,0,0,.25)}
.tag[data-tip=""]:hover::after,.tag[data-tip=""]:focus::after{display:none}
/* 매뉴얼 근거(간소화) */
.ev2-wrap{display:grid;grid-template-columns:1fr 1fr;gap:14px} @media(max-width:700px){.ev2-wrap{grid-template-columns:1fr}}
.ev2{border-radius:12px;background:var(--soft);padding:12px 14px;border-top:4px solid var(--g)} .ev2.type{--g:var(--red)} .ev2.proc{--g:var(--green)}
.ev2 h4{margin:0 0 8px;font-size:.92em} .ev2 ul{list-style:none;margin:0;padding:0}
.ev2 li{padding:8px 0;border-top:1px solid var(--border);font-size:.9em;line-height:1.6} .ev2 li:first-child{border-top:0}
.ev2 .ev-label{display:inline-block;font-weight:800;font-size:.8em;background:var(--card);border:1px solid var(--border);border-radius:6px;padding:0 6px;margin-right:6px}
.cd-note{border-left:4px solid var(--blue)} .cd-note p{margin:0 0 6px;line-height:1.7}
/* ---- 민원 상세(cd-*): 왼쪽 내용, 오른쪽 처리 정보 ---- */
.cd{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:20px;align-items:start}
.cd-main,.cd-side{display:flex;flex-direction:column;gap:16px;min-width:0}
@media(max-width:900px){.cd{display:flex;flex-direction:column;align-items:stretch}.cd-main,.cd-side{display:contents}
.o1{order:1}.o2{order:2}.o3{order:3}.o4{order:4}.o5{order:5}.o6{order:6}.o7{order:7}.o8{order:8}.o9{order:9}}
.cd-card{background:var(--card);border-radius:16px;padding:20px 22px;box-shadow:0 1px 2px rgba(15,23,42,.05),0 6px 20px rgba(15,23,42,.05)}
@media(prefers-color-scheme:dark){.cd-card{box-shadow:none;border:1px solid var(--border)}}
.cd-label{display:flex;align-items:center;gap:8px;font-size:.78em;font-weight:700;letter-spacing:.02em;color:var(--muted);margin:0 0 12px}
.cd-label .cd-act{margin-left:auto}
.cd-text{font-size:1.08em;line-height:1.85;margin:0;white-space:pre-wrap;word-break:break-word}
.cd-reply{font-size:1em;line-height:1.8;padding:14px 16px;border-radius:12px;background:var(--soft)}
.cd-tag{display:inline-block;font-size:.85em;font-weight:600;color:var(--muted);background:var(--soft);border-radius:20px;padding:1px 9px}
.cd-btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;border:1px solid var(--border);background:var(--card);color:var(--text);
border-radius:10px;padding:6px 14px;font:inherit;font-size:.86em;font-weight:600;cursor:pointer;text-decoration:none}
.cd-btn:hover{border-color:var(--primary);color:var(--primary)}
.cd-btn.solid{background:var(--primary);border-color:var(--primary);color:#fff}.cd-btn.solid:hover{color:#fff;filter:brightness(1.08)}
.cd-btn.danger{background:var(--red);border-color:var(--red);color:#fff}.cd-btn.wide{width:100%;padding:10px 14px}
details.cd-orig{margin-top:14px} details.cd-orig>summary{cursor:pointer;font-size:.86em;color:var(--muted);font-weight:600;list-style:none}
details.cd-orig>summary::before{content:"▸ "} details.cd-orig[open]>summary::before{content:"▾ "}
details.cd-orig pre{margin-top:10px;padding:12px 14px;border-radius:12px;background:var(--soft);font-size:.95em;line-height:1.8}
/* 오른쪽: 처리 정보 */
.cd-facts{border-top:4px solid var(--c)}
.cd-route{font-size:1.08em;font-weight:800;color:var(--c);margin:0 0 4px}
.cd-review{font-size:.84em;color:var(--warn-text);background:var(--warn-bg);border-radius:8px;padding:5px 10px;margin:8px 0 2px}
.cd-dl{margin:12px 0 0;display:grid;grid-template-columns:auto 1fr;gap:10px 14px;font-size:.95em}
.cd-dl dt{color:var(--muted)} .cd-dl dd{margin:0;font-weight:700;text-align:right}
.cd-dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:1px;background:var(--k)}
.cd-due{display:block;font-size:.82em;font-weight:600;color:var(--muted)} .cd-due.over{color:var(--red)}
.cd-pattern{display:flex;gap:10px;align-items:flex-start;font-weight:700;line-height:1.5}
.cd-pattern i{font-style:normal;flex:0 0 auto;width:24px;height:24px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;
font-size:.8em;color:#fff;background:var(--k)}
.cd-sub{font-size:.84em;color:var(--muted);margin:8px 0 0}
.cd-list{list-style:none;margin:12px 0 0;padding:0;font-size:.88em}
.cd-list li{padding:8px 0;border-top:1px solid var(--border)} .cd-list .m{color:var(--muted);font-size:.9em}
.cd-flag{margin:10px 0 0;padding:7px 10px;border-radius:8px;background:var(--warn-bg);color:var(--warn-text);font-size:.85em}
.cd-esc{border-top:4px solid var(--red)} .cd-esc h4{margin:0 0 4px;font-size:.98em}
.cd-crit{list-style:none;margin:10px 0 14px;padding:0}
.cd-crit li{padding:10px 12px;border-radius:10px;background:color-mix(in srgb,var(--red) 8%,transparent);margin-bottom:8px}
.cd-crit b{display:block;font-size:.92em} .cd-crit span{display:block;font-size:.82em;color:var(--muted);margin-top:3px}
.cd-crit em{font-style:normal;font-size:.75em;font-weight:800;color:var(--red);margin-left:4px}
.cd-check{font-size:.84em;color:var(--muted);margin:0 0 14px;padding-left:18px}
.cd-form{display:grid;gap:8px} .cd-form select,.cd-form input,.cd-form textarea{width:100%;padding:8px 10px;font:inherit;font-size:.9rem;
color:var(--text);background:var(--soft);border:1px solid var(--border);border-radius:10px} .cd-form textarea{min-height:64px;resize:vertical}
.cd-last{font-size:.8em;color:var(--muted);margin:10px 0 0}
details.cd-more{background:var(--card);border-radius:16px;padding:16px 22px;box-shadow:0 1px 2px rgba(15,23,42,.05)}
details.cd-more>summary{cursor:pointer;font-weight:700} details.cd-more>summary small{font-weight:400;margin-left:6px}
details.cd-more .box{box-shadow:none;margin:14px 0 0}
.cd-foot{font-size:.76em;color:var(--muted);text-align:center;margin:4px 0 0}
@media print{.topbar,form,.btn,.cd-btn,.noprint,.ev-tabs{display:none!important} body{background:#fff}.sticky{position:static;max-height:none}
.ev-group{display:block!important}}
"""

PAGE_SCRIPT = """
document.addEventListener('click',function(e){
var b=e.target.closest('[data-copy]');
if(b){var el=document.getElementById(b.dataset.copy);if(el&&navigator.clipboard){navigator.clipboard.writeText(el.innerText).then(function(){
var o=b.textContent;b.textContent='복사됨';setTimeout(function(){b.textContent=o},1500)}).catch(function(){})}return}
});
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


def _tips(result):
    """근거 번호 -> 매뉴얼 문장(말풍선에 쓴다)."""
    return {e["label"]: e["text"] for e in result.get("evidence", [])}


def _tags(labels, tips=None):
    """근거 번호. 마우스를 올리거나(휴대폰은 누르면) 매뉴얼 문장이 말풍선으로 보인다."""
    tips = tips or {}
    return "".join(f'<span class="tag" tabindex="0" data-tip="{html.escape(tips.get(l, ""), quote=True)}">{html.escape(l)}</span>'
                   for l in labels or [])


def _chips(items, cls, with_severity=False, tips=None):
    out = []
    for i in items:
        sev = f' · 심각도 {i["severity"]}' if with_severity and i.get("severity") else ""
        hint = f' title="감지된 표현: {html.escape(str(i["matched"]))}"' if i.get("matched") else ""
        out.append(f'<span class="chip {cls}"{hint}>{html.escape(i["label"])}{sev}{_tags(i.get("evidence"), tips)}</span>')
    return "".join(out) or '<span class="muted">해당 없음</span>'


def _todo(result):
    """지금 할 일: 안전 확보 -> 증거 확보 -> 응대 -> 보고 -> 후속 조치 순서의 체크리스트. 겹치는 조치는 한 줄로 합쳐져 있다."""
    phases = []
    for a in result["actions"]:
        if not phases or phases[-1][0] != a["phase"]:
            phases.append((a["phase"], []))
        phases[-1][1].append(a)
    if not phases:
        return (f'<p style="margin:0">특별한 현장 조치는 없습니다. 담당·기한에 따라 일반 절차로 처리하세요 '
                f'(담당: <b>{html.escape(result["handler"])}</b> · 기한: <b>{html.escape(result["deadline"])}</b>).</p>')
    out = []
    for n, (name, items) in enumerate(phases, 1):
        steps = "".join(
            f'<li><label><input type="checkbox"><span class="st-text">{html.escape(a["text"])}</span>'
            f'<span class="why">{html.escape(" · ".join(a["reasons"]))}</span></label></li>'
            for a in items)
        out.append(f'<li class="phase"><div class="phase-name"><i>{n}</i>{html.escape(name)}</div><ul class="steps">{steps}</ul></li>')
    return f'<ol class="phases">{"".join(out)}</ol>'


def _schedule_note(sc):
    """학사일정 문의 안내 한 줄. 일정 API로 만든 초안인지, 왜 못 만들었는지 알려 준다."""
    if not sc:
        return ""
    ok = sc["status"] == "ok"
    head = "학사일정 API로 만든 답변 초안입니다. 보내기 전에 일정을 한 번 확인하세요." if ok else "학사일정 문의로 보이지만 일정 답변은 만들지 못했습니다."
    return (f'<p class="foot" style="margin:0 0 8px"><b>{head}</b> {html.escape(sc.get("message") or "")}</p>')


def _pattern_line(result):
    """같은 학생의 반복 패턴 한 줄(제목 줄). 반복 횟수와 이전 종결 여부로 정한다."""
    h = result.get("history") or {}
    n = result.get("repeat_count", 1)
    closed_before = any(p.get("closed") for p in h.get("same_student", []))
    if n >= 3 and closed_before:
        return "warn", f"반복 패턴: 같은 학생의 동일·유사 민원 {n}회째이고, 이전에 종결한 민원이 있는데 다시 제기됨 → 이첩 검토"
    if n >= 3:
        return "warn", f"반복 패턴: 같은 학생의 동일·유사 민원 {n}회째 (3회 이상 → 종결 가능 검토)"
    if n == 2:
        return "note", "같은 학생의 동일·유사 민원이 2회째입니다"
    return "", "반복 패턴 없음 (처음 접수한 내용입니다)"


def _evidence(result, pdf_href):
    """매뉴얼 근거: '민원 유형 근거'와 '처리 절차 근거'를 나란히 보여 준다(근거 번호와 매뉴얼 문장만)."""
    groups = {"type": [], "proc": []}
    for e in result["evidence"]:
        groups[EV_GROUP[e["role"]]].append(e)
    names = {"type": "민원 유형 근거", "proc": "처리 절차 근거"}
    secs = []
    for g in ("type", "proc"):
        cards = "".join(f'<li id="ev-{e["label"]}"><span class="ev-label">{e["label"]}</span>{html.escape(e["text"])}</li>'
                        for e in groups[g]) or '<li class="muted">해당하는 근거가 없습니다.</li>'
        secs.append(f'<section class="ev2 {g}"><h4>{names[g]} <small>{len(groups[g])}</small></h4><ul>{cards}</ul></section>')
    n = len(result["evidence"])
    pdf = (f'<a class="cd-btn" href="{html.escape(pdf_href)}" target="_blank">매뉴얼 PDF 열기 (근거 형광펜 표시)</a>') if pdf_href else ""
    head = f'<h3 style="display:flex;align-items:center;gap:10px">매뉴얼 근거 <small>{n}</small><span style="margin-left:auto">{pdf}</span></h3>'
    return head + (f'<div class="ev2-wrap">{"".join(secs)}</div>' if n else '<p class="muted">검색된 근거가 없습니다.</p>')


SOFT_TAG = {"llm": "AI 순화", "rules": "거친 표현 가림", "none": "원문과 같음"}
URG_COLOR = {"낮음": "var(--green)", "보통": "var(--blue)", "높음": "var(--amber)", "긴급": "var(--red)"}


def _content_card(result):
    """민원 내용: 순화문을 크게, 원문은 접힌 '원문 보기' 안에."""
    soft = result.get("text_soft") or result["text_masked"]
    tag = SOFT_TAG.get(result.get("text_soft_method", "none"), "")
    return (f'<section class="cd-card o2"><div class="cd-label">민원 내용 <span class="cd-tag">{tag}</span></div>'
            f'<p class="cd-text">{html.escape(soft)}</p>'
            f'<details class="cd-orig"><summary>원문 보기 (폭언·욕설이 포함될 수 있습니다)</summary><pre>{_marked_text(result)}</pre></details></section>')


def _reply_card(result):
    note = (result.get("reply_staff_note") or "").strip()
    finds = [f["text"] for f in (result.get("review") or {}).get("findings", [])]
    body = (f"<p>{html.escape(note)}</p>" if note else "") + "".join(f'<p class="cd-find">· {html.escape(t)}</p>' for t in finds)
    note_card = (f'<section class="cd-card cd-note o3"><div class="cd-label">담당자 참고</div>{body}</section>' if body else "")
    return note_card + (f'<section class="cd-card o3"><div class="cd-label">답변 초안'
            f'<button type="button" class="cd-btn cd-act" data-copy="reply-text">복사</button></div>'
            f'{_schedule_note(result.get("schedule"))}<pre id="reply-text" class="cd-reply">{html.escape(result["reply_draft"])}</pre></section>')


def _review_box(result):
    """검토 기록(접힌 참고 자료 안): 검토 루프가 몇 바퀴 돌며 무엇을 점검·보강했는지."""
    rv = result.get("review")
    if not rv or not rv.get("rounds"):
        return ""
    rows = []
    for r in rv["rounds"]:
        bits = [f'근거 점검 {r["checked"]}건 중 약한 것 {r["weak"]}건']
        if r.get("history_findings"):
            bits.append(f'이력 점검에서 확인할 점 {r["history_findings"]}건')
        if r.get("queries"):
            bits.append("재검색어: " + " / ".join(r["queries"]))
        if r.get("added"):
            bits.append("추가된 근거: " + ", ".join(r["added"]))
        if r.get("note"):
            bits.append(r["note"])
        rows.append(f'<li><b>{r["round"]}바퀴</b> {html.escape(" · ".join(bits))}</li>')
    how = "LLM이 재검색어를 제안" if rv.get("llm_used") else "규칙으로 재검색어를 만듦(LLM 없음)"
    return (f'<div class="box"><h3>검토 기록 <small>(최대 {rv["max_rounds"]}바퀴 · {how})</small></h3>'
            f'<ol class="cd-check">{"".join(rows)}</ol></div>')


def _facts_card(result, deadline_note):
    route, urg = result["route"], result["urgency"]
    review = '<div class="cd-review">자동 판정이 확실하지 않아 사람이 확인해야 합니다</div>' if result["needs_human_review"] else ""
    rows = [("긴급도", f'<span class="cd-dot" style="--k:{URG_COLOR.get(urg, "var(--muted)")}"></span>{html.escape(urg)}'),
            ("담당 부서", html.escape(result["department"])), ("처리 담당", html.escape(result["handler"])),
            ("처리 기한", html.escape(result["deadline"]) + (f'<span class="cd-due">{deadline_note}</span>' if deadline_note else ""))]
    dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows)
    return (f'<section class="cd-card cd-facts o1" style="--c:{ROUTE_COLOR[route]}"><div class="cd-route">{ROUTE_SHORT[route]}</div>'
            f'{review}<dl class="cd-dl">{dl}</dl></section>')


def _history_card(result):
    """과거 이력: 반복 패턴 한 줄 + 같은 학생의 이전 민원(최근 4건) + 경고."""
    h = result.get("history") or {}
    kind, pattern = _pattern_line(result)
    icon, color = {"warn": ("!", "var(--red)"), "note": ("2", "var(--amber)")}.get(kind, ("✓", "var(--green)"))
    a = h.get("student")
    sub = (f'{html.escape(a["name"])}({html.escape(a["class_no"])}) 학생의 이전 민원 {a["total"]}건 · 특이 민원 의심 {a["escalated"]}건' if a else
           (f'{html.escape(result["student"])} 학생의 이전 민원 없음' if result.get("student") else "학생 정보가 없어 학생 기준 이력은 보지 않았습니다"))
    items = "".join(f'<li>{html.escape(x["snippet"])}<div class="m">#{x["id"]} · {x["created_at"][:10]} · '
                    f'{html.escape(ROUTE_SHORT.get(x["route"], x["route"]))}</div></li>' for x in h.get("same_student", [])[:4])
    flags = []
    if h.get("recent_closed"):
        rc = h["recent_closed"]
        flags.append(f'종결한 민원(#{rc["id"]}) 직후 다시 연락함')
    if h.get("prior_malicious"):
        flags.append(f'과거 특이 민원 의심 민원 {h["prior_malicious"]}건')
    return (f'<section class="cd-card o5"><div class="cd-label">과거 이력</div>'
            f'<div class="cd-pattern"><i style="--k:{color}">{icon}</i><span>{html.escape(pattern)}</span></div>'
            f'<p class="cd-sub">{sub}</p>{"".join(f"<div class=cd-flag>{html.escape(f)}</div>" for f in flags)}'
            f'{f"<ul class=cd-list>{items}</ul>" if items else ""}</section>')


def _transfer_card(result, href):
    """상위기관 이첩: 해당하는 기준을 번호 대신 요약 문구와 근거로 보여 주고, 보고서(.hwpx)를 내려받는다."""
    from .transfer import checklist
    cl = checklist(result)
    chosen = [c for c in cl if c["state"] in ("해당", "해당 가능")]
    todo = [c["short"] for c in cl if c["state"] == "확인 필요"]
    items = "".join(f'<li><b>{html.escape(c["short"])}<em>{"해당" if c["state"] == "해당" else "해당 가능"}</em></b>'
                    f'<span>{html.escape(c["reasons"][0])}</span></li>' for c in chosen)
    body = (f'<ul class="cd-crit">{items}</ul>' if chosen else
            '<p class="cd-sub" style="margin:8px 0 14px">자동 판단으로는 해당하는 이첩 기준이 없습니다. 이첩이 필요하면 보고서에 사유를 직접 적어 주세요.</p>')
    check = (f'<div class="cd-sub" style="margin:0 0 4px">학교 기록으로 확인할 사항</div>'
             f'<ul class="cd-check">{"".join(f"<li>{html.escape(t)}</li>" for t in todo)}</ul>') if todo else ""
    link = (f'<a class="cd-btn danger wide" href="{html.escape(href)}">이첩 보고서 내려받기 (.hwpx)</a>' if href else
            '<p class="cd-sub">저장된 민원의 상세 화면에서 보고서를 내려받을 수 있습니다.</p>')
    return (f'<section class="cd-card cd-esc o4"><div class="cd-label">상위기관 이첩</div>'
            f'<h4>교육(지원)청 이첩을 검토하세요</h4>{body}{check}{link}</section>')


def _homeroom_card(result, footer):
    """담임 교사 전달(해당 민원만): 받는 사람, 전달문 복사, 전달함 표시. 내용은 접어 둔다."""
    h = result.get("homeroom")
    if not h:
        return ""
    acts = "".join(f'<li>{html.escape(a["text"])}</li>' for a in h["actions"])
    return (f'<section class="cd-card o7"><div class="cd-label">담임 교사 전달'
            f'<button type="button" class="cd-btn cd-act" data-copy="hr-msg">전달문 복사</button></div>'
            f'<div style="font-weight:700">{html.escape(h["to"])}</div><p class="cd-sub">{html.escape(h["summary"])}</p>'
            f'<details class="cd-orig"><summary>요청할 행동·전달문 보기</summary><ol class="cd-check" style="margin-top:8px">{acts}</ol>'
            f'<pre id="hr-msg">{html.escape(h["message"])}</pre></details><div style="margin-top:12px">{footer}</div></section>')


def render_body(result, pdf_href=None, homeroom_footer="", transfer_href="", deadline_note="", status_html="", timeline_html=""):
    """분류 결과 화면. 왼쪽: 민원 내용 → 답변 초안 → 참고 자료(접힘). 오른쪽: 분류·긴급도·담당·기한 → 처리 상태 → 이첩 → 과거 이력 → 담임 전달.
    좁은 화면에서는 '분류 요약 → 민원 내용 → 답변 초안 → 이첩 → 과거 이력 …' 순서로 한 줄에 쌓인다. 웹 페이지와 report.html이 함께 쓴다."""
    notes = "".join(f'<span class="chip note">{html.escape(n)}</span>' for n in result["notes"])
    transfer = _transfer_card(result, transfer_href) if result["route"] == "ESCALATE" or transfer_href else ""
    more = (f'<details class="cd-more o9"><summary>참고 자료<small>지금 할 일 · 분류 사유 · 매뉴얼 근거 · 검토 기록'
            f'{" · 처리 경과" if timeline_html else ""}</small></summary>'
            f'<div class="box"><h3>지금 할 일 <small>(해 둔 항목은 체크하세요)</small></h3>{_todo(result)}</div>'
            f'<div class="box"><h3>분류 사유</h3>'
            f'<div class="rrow"><div class="sec-title">거부·종결 가능 사유</div>{_chips(result["reject"], "reject", tips=_tips(result))}</div>'
            f'<div class="rrow"><div class="sec-title">특이민원 유형</div>{_chips(result["malicious"], "mal", True, _tips(result))}</div>'
            f'{f"""<div class="rrow"><div class="sec-title">참고 (맥락 확인 필요)</div>{notes}</div>""" if notes else ""}</div>'
            f'{_review_box(result)}{timeline_html}'
            f'<div class="box">{_evidence(result, pdf_href)}</div>'
            f'<p class="cd-foot">자동 판정은 후보 제시용이며 최종 판단은 학교장(민원대응팀)이 합니다.</p></details>')
    return (f'<div class="cd"><div class="cd-main">{_content_card(result)}{_reply_card(result)}{more}</div>'
            f'<aside class="cd-side">{_facts_card(result, deadline_note)}{status_html}{transfer}'
            f'{_history_card(result)}{_homeroom_card(result, homeroom_footer)}</aside></div>')


def render_page(result, pdf_href=None):
    return (f'<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>민원 분류 결과</title><style>{STYLE}</style>'
            f'<header class="topbar"><div class="wrap"><b>학교 민원 분류 결과</b></div></header>'
            f'<main class="wrap">{render_body(result, pdf_href)}</main><script>{PAGE_SCRIPT}</script>')


def render_html(result, out_path, pdf_href=None):
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(render_page(result, pdf_href))
