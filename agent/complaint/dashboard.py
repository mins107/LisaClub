"""메인 화면(대시보드)과 민원 상세·처리 경과 화면의 HTML을 만든다. 서버 처리는 web.py가 한다."""
import html
from urllib.parse import urlencode

from .highlight import ROUTE_SHORT, URGENCY_CLASS, render_body
from .store import STATUSES

DEPTS = ["교무/학사", "생활지도/상담", "학부모/교직원 소통", "학교 운영", "기타"]
URGENCIES = ["낮음", "보통", "높음", "긴급"]
STATUS_CLASS = {"접수": "new", "처리 중": "doing", "완료": "done", "이첩": "esc"}
ROUTE_CLASS = {"REJECTABLE": "reject", "HANDLE": "ok", "ESCALATE": "mal"}
KIND_CLASS = {"접수": "k-new", "상태": "k-status", "메모": "k-memo", "담임전달": "k-hr"}

DASH_CSS = """
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:14px}
.kpi{display:block;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:12px 14px;text-decoration:none;color:var(--text)}
.kpi:hover{border-color:var(--primary)} .kpi .n{font-size:1.9em;font-weight:800;line-height:1.1} .kpi .l{font-size:.8em;color:var(--muted)}
.kpi.is-alert .n{color:var(--red)} .kpi.is-warn .n{color:var(--amber)}
.dash{display:grid;grid-template-columns:minmax(330px,390px) minmax(0,1fr);gap:16px;align-items:start}
@media(min-width:1001px){.dash-left{position:sticky;top:60px;max-height:calc(100vh - 76px);overflow-y:auto}}
@media(max-width:1000px){.dash{grid-template-columns:1fr}}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin-bottom:14px}
.chart{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:10px 12px}
.chart h3{font-size:.85em;margin:0 0 6px;color:var(--muted)}
.bar{display:grid;grid-template-columns:78px 1fr 26px;gap:6px;align-items:center;font-size:.8em;text-decoration:none;color:var(--text);margin:3px 0}
.bar:hover b{color:var(--primary)} .bar b{text-align:right}
.b-t{height:8px;background:var(--border);border-radius:4px;overflow:hidden} .b-t i{display:block;height:100%;background:var(--primary)}
.daily{display:flex;align-items:flex-end;gap:3px;height:56px} .daily div{flex:1;background:var(--primary);border-radius:3px 3px 0 0;min-height:2px}
.daily-l{display:flex;justify-content:space-between;font-size:.7em;color:var(--muted);margin-top:2px}
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:end;margin-bottom:10px}
.filters label{display:flex;flex-direction:column;font-size:.74em;color:var(--muted);gap:2px}
.filters select,.filters input[type=text]{padding:6px 8px;font:inherit;font-size:.9rem;color:var(--text);background:var(--card);border:1px solid var(--border);border-radius:8px}
.filters .ck{flex-direction:row;align-items:center;gap:5px;padding-bottom:7px;font-size:.82em}
.list{width:100%;border-collapse:collapse;font-size:.88em}
.list th{text-align:left;font-size:.76em;color:var(--muted);font-weight:700;padding:4px 8px}
.list td{padding:9px 8px;border-top:1px solid var(--border);vertical-align:top}
.list tbody tr:hover td{background:var(--soft)} .list a{color:inherit;text-decoration:none} .list a:hover{color:var(--primary)}
.list .id{font-weight:800} .sm{font-size:.76em;color:var(--muted)} .stu{font-weight:700} .snip{color:var(--muted)}
.list-wrap{overflow-x:auto} .list td.c-status{white-space:nowrap} .list td.c-cls{min-width:130px} .list td:nth-child(2){min-width:170px}
.st{display:inline-block;border-radius:12px;padding:1px 10px;font-weight:800;font-size:.84em;color:var(--on-c)}
.st-new{background:var(--muted)} .st-doing{background:var(--blue)} .st-done{background:var(--green)} .st-esc{background:var(--red)}
.rt{display:inline-block;border-radius:6px;padding:0 7px;font-size:.78em;font-weight:800;margin-bottom:3px;
background:color-mix(in srgb,var(--k) 16%,transparent);color:var(--k);border:1px solid color-mix(in srgb,var(--k) 38%,transparent)}
.rt.reject{--k:var(--amber)} .rt.ok{--k:var(--green)} .rt.mal{--k:var(--red)}
.over{color:var(--red);font-weight:800} .hr{font-size:.8em;font-weight:700} .hr.wait{color:var(--amber)} .hr.ok{color:var(--green)}
.need{font-size:.7em;font-weight:800;color:var(--warn-text);background:var(--warn-bg);border-radius:6px;padding:0 6px;margin-left:4px}
.pager{display:flex;justify-content:center;align-items:center;gap:12px;margin-top:12px;font-size:.88em}
.empty{padding:30px 0;text-align:center;color:var(--muted)}
/* 상세: 처리 경과 */
.head{display:flex;flex-wrap:wrap;align-items:center;gap:6px 12px;margin-bottom:12px} .head h1{font-size:1.25em;margin:0}
.meta{font-size:.85em;color:var(--muted)} .back{font-size:.88em;text-decoration:none;color:var(--primary)}
.okbanner{padding:9px 14px;border-radius:10px;background:color-mix(in srgb,var(--green) 14%,transparent);color:var(--green);font-weight:700;margin-bottom:12px}
.stepper{display:flex;margin:6px 0 10px} .step{flex:1;text-align:center;font-size:.82em;position:relative;color:var(--muted)}
.step i{display:block;width:28px;height:28px;line-height:28px;margin:0 auto 4px;border-radius:50%;background:var(--border);color:var(--muted);
font-style:normal;font-weight:800;position:relative;z-index:1}
.step+.step::before{content:"";position:absolute;top:13px;left:-50%;width:100%;height:3px;background:var(--border)}
.step.done i,.step.done+.step::before{background:var(--green);color:var(--on-c)}
.step.cur i{background:var(--primary);color:#fff;box-shadow:0 0 0 4px color-mix(in srgb,var(--primary) 25%,transparent)}
.step.cur.esc i{background:var(--red)} .step.cur{color:var(--text);font-weight:800}
.dueline{margin:0 0 10px;font-size:.88em} .rec label{display:flex;flex-direction:column;font-size:.78em;color:var(--muted);gap:2px;margin-bottom:8px}
.rec textarea{min-height:72px;resize:vertical} .rec select,.rec input[type=text],.rec textarea{padding:7px 9px;font:inherit;font-size:.92rem;color:var(--text);background:var(--card);border:1px solid var(--border);border-radius:8px;width:100%}
.rec .two{display:grid;grid-template-columns:1fr 1fr;gap:8px} .rec button,.hr-form button{background:var(--primary);color:#fff;border:0;border-radius:8px;padding:8px 18px;font:inherit;font-weight:800;cursor:pointer}
.tl{list-style:none;margin:0;padding:0 0 0 12px;border-left:2px solid var(--border)}
.tl li{position:relative;padding:0 0 12px 14px} .tl li::before{content:"";position:absolute;left:-19px;top:6px;width:10px;height:10px;border-radius:50%;background:var(--muted)}
.tl li.k-status::before{background:var(--primary)} .tl li.k-hr::before{background:var(--blue);box-shadow:0 0 0 3px color-mix(in srgb,var(--blue) 25%,transparent)} .tl li.k-memo::before{background:var(--amber)}
.tl .t{font-size:.76em;color:var(--muted)} .tl .tx{font-weight:600;word-break:break-word} .tl .by{font-size:.78em;color:var(--muted)}
.hr-form{display:flex;flex-wrap:wrap;gap:6px;align-items:center} .hr-form input{padding:6px 9px;font:inherit;font-size:.9rem;color:var(--text);background:var(--card);border:1px solid var(--border);border-radius:8px}
"""


def _qs(filters, **over):
    """주소에 붙일 조회 조건. 빈 값은 뺀다."""
    d = {**filters, **over}
    d = {k: v for k, v in d.items() if v not in (None, "", False, 0)}
    return "/?" + urlencode(d) if d else "/"


def status_pill(st):
    return f'<span class="st st-{STATUS_CLASS.get(st, "new")}">{html.escape(st)}</span>'


def _bars(items, total_max, href_fn):
    if not items:
        return '<div class="sm">아직 없습니다</div>'
    top = max(total_max, 1)
    return "".join(
        f'<a class="bar" href="{html.escape(href_fn(k))}"><span>{html.escape(label)}</span>'
        f'<span class="b-t"><i style="width:{n * 100 // top}%"></i></span><b>{n}</b></a>' for k, label, n in items)


def _options(pairs, selected):
    return "".join(f'<option value="{html.escape(v)}"{" selected" if v == selected else ""}>{html.escape(t)}</option>' for v, t in pairs)


def _filters_form(f):
    pairs_status = [("", "전체"), ("open", "진행 중 (접수·처리 중)")] + [(s, s) for s in STATUSES]
    pairs_route = [("", "전체")] + [(k, v) for k, v in ROUTE_SHORT.items()]
    pairs_dept = [("", "전체")] + [(d, d) for d in DEPTS]
    pairs_urg = [("", "전체")] + [(u, u) for u in URGENCIES]
    pairs_hr = [("", "전체"), ("pending", "전달 대기"), ("sent", "전달 완료")]
    return f"""<form class="filters" method="get" action="/">
<label>처리 상태<select name="status">{_options(pairs_status, f.get("status", ""))}</select></label>
<label>분류<select name="route">{_options(pairs_route, f.get("route", ""))}</select></label>
<label>담당 부서<select name="department">{_options(pairs_dept, f.get("department", ""))}</select></label>
<label>긴급도<select name="urgency">{_options(pairs_urg, f.get("urgency", ""))}</select></label>
<label>담임 전달<select name="homeroom">{_options(pairs_hr, f.get("homeroom", ""))}</select></label>
<label>검색(학생·내용)<input type="text" name="q" value="{html.escape(f.get("q", ""))}" placeholder="예: 홍길동"></label>
<label class="ck"><input type="checkbox" name="overdue" value="1"{" checked" if f.get("overdue") else ""}>기한 초과만</label>
<button class="btn" type="submit">조회</button><a class="btn" href="/">초기화</a></form>"""


def _rows(rows):
    if not rows:
        return '<div class="empty">조건에 맞는 민원이 없습니다.</div>'
    out = []
    for r in rows:
        if not r["homeroom_needed"]:
            hr = '<span class="sm">—</span>'
        elif r["homeroom_sent_at"]:
            hr = '<span class="hr ok">전달 완료</span>'
        else:
            hr = '<span class="hr wait">전달 대기</span>'
        need = '<span class="need">확인 필요</span>' if r["needs_human_review"] and r["status"] in ("접수", "처리 중") else ""
        due = f'<div class="sm{" over" if r["overdue"] else ""}">{html.escape(r["due"])}</div>' if r["due"] else ""
        url = f'/complaints/{r["id"]}'
        out.append(
            f'<tr><td><a class="id" href="{url}">#{r["id"]}</a><div class="sm">{html.escape(r["created_at"][5:])}</div></td>'
            f'<td><div class="stu">{html.escape(r["student"] or "학생 미상")}{need}</div>'
            f'<a class="snip" href="{url}">{html.escape(r["text"])}</a></td>'
            f'<td class="c-cls"><span class="rt {ROUTE_CLASS[r["route"]]}">{html.escape(ROUTE_SHORT[r["route"]])}</span>'
            f'<div class="sm">{html.escape(r["department"])} · 긴급도 {html.escape(r["urgency"])}</div></td>'
            f'<td class="c-status">{status_pill(r["status"])}{due}</td><td>{hr}</td></tr>')
    return ('<div class="list-wrap"><table class="list"><thead><tr><th>번호·접수</th><th>학생 · 민원</th><th>분류</th>'
            '<th>처리 상태</th><th>담임 전달</th></tr></thead><tbody>' + "".join(out) + "</tbody></table></div>")


def render_dashboard(stats, rows, total, filters, page, per_page, form_html):
    """메인 화면: 요약 숫자, 그래프, 새 민원 입력, 조회 조건, 민원 목록."""
    bs = stats["by_status"]
    kpis = [("전체 민원", stats["total"], _qs({}), ""),
            ("진행 중 (접수·처리 중)", stats["open"], _qs({}, status="open"), ""),
            ("기한 초과", stats["overdue"], _qs({}, overdue=1), "is-alert" if stats["overdue"] else ""),
            ("담임 전달 대기", stats["homeroom_pending"], _qs({}, homeroom="pending"), "is-warn" if stats["homeroom_pending"] else ""),
            ("완료", bs["완료"], _qs({}, status="완료"), ""), ("이첩", bs["이첩"], _qs({}, status="이첩"), "")]
    kp = "".join(f'<a class="kpi {cls}" href="{html.escape(h)}"><div class="n">{n}</div><div class="l">{html.escape(l)}</div></a>'
                 for l, n, h, cls in kpis)
    mx = max([stats["total"], 1])
    st_items = [(s, s, bs[s]) for s in STATUSES]
    rt_items = [(k, ROUTE_SHORT[k], stats["by_route"].get(k, 0)) for k in ROUTE_SHORT]
    dp_items = [(d, d, stats["by_department"].get(d, 0)) for d in DEPTS]
    daily = stats["daily"]
    dmax = max([n for _, n in daily] + [1])
    cols = "".join(f'<div title="{d} · {n}건" style="height:{max(n * 100 // dmax, 4)}%"></div>' for d, n in daily)
    charts = (f'<div class="charts"><div class="chart"><h3>처리 상태</h3>{_bars(st_items, mx, lambda k: _qs({}, status=k))}</div>'
              f'<div class="chart"><h3>분류</h3>{_bars(rt_items, mx, lambda k: _qs({}, route=k))}</div>'
              f'<div class="chart"><h3>담당 부서</h3>{_bars(dp_items, mx, lambda k: _qs({}, department=k))}</div>'
              f'<div class="chart" style="grid-column:1/-1"><h3>최근 {len(daily)}일 접수 건수</h3><div class="daily">{cols}</div>'
              f'<div class="daily-l"><span>{daily[0][0]}</span><span>{daily[-1][0]}</span></div></div></div>')
    pages = max((total + per_page - 1) // per_page, 1)
    f = {k: v for k, v in filters.items() if v}
    prev = f'<a class="btn" href="{html.escape(_qs(f, page=page - 1))}">← 이전</a>' if page > 1 else ""
    nxt = f'<a class="btn" href="{html.escape(_qs(f, page=page + 1))}">다음 →</a>' if page < pages else ""
    pager = f'<div class="pager">{prev}<span>{page} / {pages} 쪽 · 총 {total}건</span>{nxt}</div>' if total else ""
    return (f'<div class="kpis">{kp}</div><div class="dash"><div class="dash-left" id="new">{form_html}</div>'
            f'<div>{charts}<div class="box"><h2>민원 목록</h2>{_filters_form(filters)}{_rows(rows)}{pager}</div></div></div>')


def _stepper(status):
    path = ["접수", "처리 중", "이첩" if status == "이첩" else "완료"]
    cur = path.index(status) if status in path else 0
    out = []
    for i, name in enumerate(path):
        cls = "done" if i < cur else "cur" if i == cur else ""
        if cls == "cur" and name == "이첩":
            cls += " esc"
        mark = "✓" if i < cur or (i == cur and status in ("완료", "이첩")) else str(i + 1)
        out.append(f'<div class="step {cls}"><i>{mark}</i>{html.escape(name)}</div>')
    return f'<div class="stepper">{"".join(out)}</div>'


def _timeline(events):
    items = []
    for e in reversed(events):          # 최신 경과가 위
        title = {"접수": "접수", "상태": "상태 변경", "메모": "메모", "담임전달": "담임 교사 전달"}.get(e["kind"], e["kind"])
        note = f'<div class="tx">{html.escape(e["note"])}</div>' if e["note"] else ""
        by = f' · {html.escape(e["actor"])}' if e["actor"] else ""
        items.append(f'<li class="{KIND_CLASS.get(e["kind"], "")}"><div class="t">{html.escape(e["created_at"])}{by}</div>'
                     f'<div class="tx">{html.escape(title)}</div>{note}</li>')
    return f'<ul class="tl">{"".join(items)}</ul>'


def render_detail(c, pdf_href=None, new=False, error=""):
    """민원 상세: 처리 상태와 경과를 확인·기록하고, 분류 결과 전체를 본다."""
    cid = c["id"]
    banner = '<div class="okbanner">분류가 끝나 DB에 저장되었습니다. 아래에서 처리 경과를 기록해 주세요.</div>' if new else ""
    err = f'<div class="err" role="alert">{html.escape(error)}</div>' if error else ""
    due = (f'<p class="dueline">처리 기한 <b>{html.escape(c["deadline"])}</b>'
           + (f' · <span class="{"over" if c["overdue"] else ""}"><b>{html.escape(c["due"])}</b></span>' if c["due"] else "") + "</p>")
    done = f'<p class="meta">처리 완료 {html.escape(c["completed_at"])}</p>' if c["completed_at"] else ""
    status_opts = '<option value="">상태 유지</option>' + "".join(
        f'<option value="{s}">{s}{" (현재)" if s == c["status"] else ""}</option>' for s in STATUSES if s != c["status"])
    rec = (f'<form class="rec" method="post" action="/complaints/{cid}/record"><label>처리 상태 변경'
           f'<select name="status">{status_opts}</select></label>'
           f'<label>처리자 (선택)<input type="text" name="actor" maxlength="50" placeholder="예: 김민원"></label>'
           f'<label>경과 메모<textarea name="note" rows="3" maxlength="1000" placeholder="예: 학부모에게 전화로 설명함"></textarea></label>'
           f'<button type="submit">경과 기록하기</button></form>')
    footer = ""
    if c["homeroom_needed"]:
        footer = (f'<span class="hr ok">✓ 전달 완료 · {html.escape(c["homeroom_sent_at"])}</span>' if c["homeroom_sent_at"] else
                  f'<form class="hr-form" method="post" action="/complaints/{cid}/homeroom">'
                  f'<input type="text" name="note" maxlength="200" placeholder="전달 방법 (예: 메신저로 전달)">'
                  f'<input type="text" name="actor" maxlength="50" placeholder="처리자" style="width:110px">'
                  f'<button type="submit">전달함으로 표시</button></form>')
    head = (f'<a class="back" href="/">← 대시보드로</a><div class="head"><h1>민원 #{cid}</h1>{status_pill(c["status"])}'
            f'<span class="rt {ROUTE_CLASS[c["route"]]}">{html.escape(ROUTE_SHORT[c["route"]])}</span>'
            f'<span class="meta">{html.escape(c["student"] or "학생 미상")} · 접수 {html.escape(c["created_at"])}'
            f' · 최근 갱신 {html.escape(c["updated_at"] or c["created_at"])}</span></div>')
    panel = (f'<div class="cols"><div class="col"><div class="box"><h2>처리 상태</h2>{_stepper(c["status"])}{due}{done}{rec}</div></div>'
             f'<div class="col"><div class="box"><h2>처리 경과 <small>({len(c["events"])}건)</small></h2>{_timeline(c["events"])}</div></div></div>')
    return head + banner + err + panel + render_body(c["result"], pdf_href, footer)
