"""메인 화면(대시보드)과 민원 상세·처리 경과 화면의 HTML을 만든다. 서버 처리는 web.py가 한다."""
import html
from urllib.parse import urlencode

from .analytics import MIN_CORR, MIN_MONTHS_OF_DATA
from .insights import MIN_DEPT_CASES, department_insights
from .highlight import ROUTE_SHORT, URGENCY_CLASS, render_body
from .notices import LEAD_DAYS
from .rules import DEPT_DESC, DEPT_NAMES
from .store import STATUSES

DEPTS = DEPT_NAMES
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
.dp{display:grid;grid-template-columns:150px 1fr auto;gap:8px;align-items:center;font-size:.82em;text-decoration:none;color:var(--text);margin:5px 0}
.dp:hover .dn{color:var(--primary)} .dn{font-weight:700} .dm{color:var(--muted);font-size:.9em;white-space:nowrap}
.stack{display:flex;height:12px;background:var(--border);border-radius:6px;overflow:hidden} .stack i{display:block;height:100%}
.sg-done{background:var(--green)} .sg-open{background:var(--blue)} .sg-over{background:var(--red)}
.lg{display:flex;flex-wrap:wrap;gap:12px;font-size:.76em;color:var(--muted);margin-top:6px} .lg b{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:4px;vertical-align:-1px}
.ins{margin:10px 0 0;padding:10px 12px;border-radius:10px;background:var(--soft);font-size:.86em}
.ins h4{margin:0 0 4px;font-size:1em} .ins .fact{color:var(--muted);font-size:.92em} .ins ul{margin:4px 0 0;padding-left:18px}
.hm{width:100%;border-collapse:separate;border-spacing:2px;font-size:.78em}
.hm th{font-weight:700;color:var(--muted);text-align:center;padding:2px} .hm td.kw{white-space:nowrap;font-weight:700;padding-right:8px}
.hm td.c{text-align:center;border-radius:4px;min-width:26px;height:24px;color:var(--text);background:color-mix(in srgb,var(--primary) calc(var(--v) * 1%),var(--soft))}
.hm td.pk{outline:2px solid var(--amber);font-weight:800} .hm td.i{font-size:.9em;color:var(--muted);white-space:nowrap;padding-left:8px}
.nt{border:1px solid var(--border);border-radius:10px;padding:10px 12px;margin:8px 0}
.nt h4{margin:0 0 3px;font-size:.95em} .nt .sm{margin:2px 0}
.pl{display:inline-block;border-radius:10px;padding:0 9px;font-size:.78em;font-weight:800;margin-right:6px;color:var(--on-c)}
.pl-due{background:var(--red)} .pl-waiting{background:var(--muted)} .pl-sent{background:var(--green)}
.nt pre{white-space:pre-wrap;margin:6px 0} .nt form{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:6px}
.nt input[type=text]{padding:5px 8px;font:inherit;font-size:.88rem;color:var(--text);background:var(--card);border:1px solid var(--border);border-radius:8px}
.page-title{font-size:1.3em;margin:4px 0 14px}
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
.cd-head{margin:2px 0 18px} .cd-title{display:flex;align-items:center;gap:10px;margin:6px 0 2px} .cd-title h1{font-size:1.45em;margin:0}
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


def _dept_chart(stats):
    """부서별 민원 현황(처리 끝 / 진행 중 / 기한 초과 누적 막대)과 개선을 검토할 부서 설명."""
    depts, total = stats["departments"], stats["total"]
    names = [n for n in DEPTS if n in depts and (depts[n]["total"] or not n.startswith(("미분류", "학년부(")))] +             [n for n in depts if n not in DEPTS]
    top = max([depts[n]["total"] for n in names] + [1])
    rows = []
    for n in names:
        d = depts[n]
        done, over = d["done"], d["overdue"]
        seg = "".join(f'<i class="{c}" style="width:{v * 100 // top}%"></i>' for c, v in
                      (("sg-done", done), ("sg-open", d["open"] - over), ("sg-over", over)) if v)
        meta = f'{d["total"]}건' + (f' · 초과 {over}' if over else "") + (f' · 평균 {d["avg_days"]}일' if d["avg_days"] is not None else "")
        rows.append(f'<a class="dp" href="{html.escape(_qs({}, department=n))}" title="{html.escape(DEPT_DESC.get(n, ""))}">'
                    f'<span class="dn">{html.escape(n)}</span><span class="stack">{seg}</span><span class="dm">{meta}</span></a>')
    legend = ('<div class="lg"><span><b class="sg-done"></b>처리 끝(완료·이첩)</span><span><b class="sg-open"></b>진행 중</span>'
              '<span><b class="sg-over"></b>기한 초과</span></div>')
    ins = department_insights(depts, total)
    if ins:
        blocks = "".join(f'<div class="ins"><h4>{html.escape(i["dept"])}</h4><div class="fact">{html.escape(" · ".join(i["facts"]))}</div>'
                         f'<ul>{"".join(f"<li>{html.escape(a)}</li>" for a in i["advice"])}</ul></div>' for i in ins)
        note = f'<h3 style="margin-top:12px">개선을 검토할 부서</h3>{blocks}'
    else:
        note = (f'<div class="ins"><h4>개선을 검토할 부서</h4>현재 기준으로 개선 검토가 필요한 부서가 없습니다. '
                f'부서 접수가 {MIN_DEPT_CASES}건 이상 쌓여야 판단하며, 지금은 표본이 적을 수 있습니다.</div>')
    basis = ('<div class="sm" style="margin-top:8px">판단 기준(임의 시작값, 학교가 정한 값이 아님): 기한 초과·넘겨 처리 20% 이상, 진행 중 60% 이상, '
             '반복 민원 30% 이상, 전체 민원 중 40% 이상 집중(전체 10건 이상), 미분류 20% 이상. 의사결정 전에 실제 민원 내용을 함께 확인하세요.</div>')
    return f'<h3>부서별 민원 현황 (막대를 누르면 해당 부서 목록)</h3>{"".join(rows)}{legend}{note}{basis}'


def _md(d):
    return f"{d.month}/{d.day}"


def render_season(report, plans, today):
    """시즌 키워드 분석(달별 히트맵)과 가정통신문 전달 계획. plans는 notices.status_list의 결과."""
    head = '<h2 id="notices">시즌별 민원 키워드와 가정통신문</h2>'
    gen = ('<form method="post" action="/notices/generate" style="margin:6px 0">'
           '<button class="btn" type="submit">분석 결과로 가정통신문 계획 만들기·갱신</button></form>')
    if not report["enough"]:
        return (f'<div class="box">{head}<p class="sm">달별 흐름을 보려면 서로 다른 달의 민원이 {MIN_MONTHS_OF_DATA}개월 이상 쌓여야 합니다. '
                f'지금은 {report["months_of_data"]}개월 치입니다.</p></div>')
    cells_head = "".join(f"<th>{m}월</th>" for m in range(1, 13))
    rows = []
    for k in report["keywords"]:
        mx = max(k["counts"]) or 1
        tds = "".join(f'<td class="c{" pk" if m + 1 == k["peak_month"] else ""}" style="--v:{c * 70 // mx if c else 0}" '
                      f'title="{html.escape(k["keyword"])} {m + 1}월 {c}건">{c or ""}</td>' for m, c in enumerate(k["counts"]))
        info = f'{k["peak_month"]}월 집중 · 평소의 {k["lift"]}배' if k["seasonal"] else "뚜렷한 시즌 없음"
        rel = (" · 함께: " + ", ".join(f'{r["keyword"]}({r["r"]})' for r in k["related"])) if k["related"] else ""
        rows.append(f'<tr><td class="kw">{html.escape(k["keyword"])}</td>{tds}<td class="i">{html.escape(info + rel)}</td></tr>')
    seasonal = [k for k in report["keywords"] if k["seasonal"]]
    summary = ("늘어나는 시기가 뚜렷한 키워드: " + ", ".join(f'<b>{html.escape(k["keyword"])}</b>({k["peak_month"]}월)' for k in seasonal)
               if seasonal else "현재 기준으로 특정 달에 몰리는 키워드는 없습니다.")
    heat = (f'<p class="sm">{report["months_of_data"]}개월 치 민원 {report["total"]}건 · 칸의 진하기는 키워드별 최대 건수 대비, 노란 테두리는 가장 많은 달. '
            f'괄호 안 숫자는 같은 시기에 함께 늘어나는 정도(상관계수, {MIN_CORR} 이상만 표시)입니다.</p>'
            f'<div class="list-wrap"><table class="hm"><thead><tr><th></th>{cells_head}<th></th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>'
            f'<p style="margin:8px 0 0">{summary}</p>')
    due = [p for p in plans if p["state"] == "due"]
    cards = []
    for p in plans:
        win = f'{_md(p["start"])} ~ {_md(p["end"])}'
        sent = "".join(f'{x["season_year"]}년 {x["sent_at"]} {html.escape(x["actor"] or "")} 전달' for x in p["sends"][-1:])
        form = ""
        if p["state"] == "due":
            form = (f'<form method="post" action="/notices/{p["id"]}/send"><input type="hidden" name="season_year" value="{p["season_year"]}">'
                    f'<input type="text" name="actor" placeholder="처리자(선택)"><input type="text" name="note" placeholder="전달 방법(선택)">'
                    f'<button class="btn" type="submit">전달함으로 표시</button></form>')
        rel = f'<div class="sm">함께 늘어나는 키워드: {html.escape(", ".join(p["related"]))}</div>' if p["related"] else ""
        cards.append(
            f'<div class="nt"><h4><span class="pl pl-{p["state"]}">{p["label"]}</span>{html.escape(p["title"])}</h4>'
            f'<div class="sm">{p["peak_month"]}월 민원 증가 → 전달 시기 {win}(늘어나는 달 {p["lead_days"]}일 전부터) · 문의 창구 {html.escape(p["department"])}</div>'
            f'<div class="sm">근거: {html.escape(p["evidence"])}</div>{rel}'
            + (f'<div class="sm">{sent}</div>' if sent else "")
            + f'<details><summary class="sm" style="cursor:pointer">가정통신문 초안 보기</summary><pre id="nt-{p["id"]}">{html.escape(p["body"])}</pre>'
            f'<button type="button" class="btn" data-nt="nt-{p["id"]}">복사</button></details>{form}</div>')
    notes = (f'<h3 style="margin:14px 0 0">가정통신문 전달 계획 (지금 전달 필요 {len(due)}건)</h3>'
             f'<p class="sm">늘어나는 달이 시작되기 {LEAD_DAYS}일 전부터 그 달 말까지가 전달 시기입니다. 이 프로그램은 직접 발송하지 않고, 담당자가 보낸 뒤 '
             f'"전달함으로 표시"를 누르면 그해 시즌에 한 번 기록합니다.</p>'
             f'{"".join(cards) or "<p class=sm>아직 계획이 없습니다. 위 버튼으로 만들어 보세요.</p>"}')
    copy_js = ("<script>document.querySelectorAll('[data-nt]').forEach(function(b){b.onclick=function(){"
               "navigator.clipboard.writeText(document.getElementById(b.dataset.nt).textContent);b.textContent='복사됨';};});</script>")
    return f'<div class="box">{head}{heat}{gen}{notes}</div>{copy_js}'


def render_dashboard(stats, rows, total, filters, page, per_page):
    """메인 화면: 처리할 일을 보여 주는 요약 숫자(누르면 목록이 걸러짐)와 민원 목록."""
    kpis = [("진행 중", stats["open"], _qs({}, status="open"), ""),
            ("기한 초과", stats["overdue"], _qs({}, overdue=1), "is-alert" if stats["overdue"] else ""),
            ("담임 전달 대기", stats["homeroom_pending"], _qs({}, homeroom="pending"), "is-warn" if stats["homeroom_pending"] else ""),
            *([("가정통신문 전달 필요", stats["notice_due"], "/analysis#notices", "is-warn" if stats["notice_due"] else "")]
              if "notice_due" in stats else [])]
    kp = "".join(f'<a class="kpi {cls}" href="{html.escape(h)}"><div class="n">{n}</div><div class="l">{html.escape(l)}</div></a>'
                 for l, n, h, cls in kpis)
    pages = max((total + per_page - 1) // per_page, 1)
    f = {k: v for k, v in filters.items() if v}
    prev = f'<a class="btn" href="{html.escape(_qs(f, page=page - 1))}">← 이전</a>' if page > 1 else ""
    nxt = f'<a class="btn" href="{html.escape(_qs(f, page=page + 1))}">다음 →</a>' if page < pages else ""
    pager = f'<div class="pager">{prev}<span>{page} / {pages} 쪽 · 총 {total}건</span>{nxt}</div>' if total else ""
    return (f'<div class="kpis">{kp}</div>'
            f'<div class="box"><h2>민원 목록</h2>{_filters_form(filters)}{_rows(rows)}{pager}</div>')


def render_analysis(stats, season_html=""):
    """분석 화면: 처리 상태·분류 그래프, 부서별 민원 현황과 개선 검토 부서, 시즌별 민원 키워드와 가정통신문."""
    bs = stats["by_status"]
    mx = max([stats["total"], 1])
    st_items = [(s, s, bs[s]) for s in STATUSES]
    rt_items = [(k, ROUTE_SHORT[k], stats["by_route"].get(k, 0)) for k in ROUTE_SHORT]
    charts = (f'<div class="charts"><div class="chart"><h3>처리 상태 (전체 {stats["total"]}건)</h3>{_bars(st_items, mx, lambda k: _qs({}, status=k))}</div>'
              f'<div class="chart"><h3>분류</h3>{_bars(rt_items, mx, lambda k: _qs({}, route=k))}</div>'
              f'<div class="chart" style="grid-column:1/-1">{_dept_chart(stats)}</div></div>')
    return f'<h1 class="page-title">분석</h1>{charts}{season_html}'


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
    """민원 상세: 머리줄(번호·상태·학생·접수 시각) + render_body. 처리 상태 기록은 오른쪽 카드, 처리 경과는 참고 자료 안."""
    cid = c["id"]
    banner = '<div class="okbanner">분류가 끝나 저장되었습니다.</div>' if new else ""
    err = f'<div class="err" role="alert">{html.escape(error)}</div>' if error else ""
    due_note = (f'<span class="{"over" if c["overdue"] else ""}">{html.escape(c["due"])}</span>' if c["due"] else "")
    status_opts = '<option value="">상태 유지</option>' + "".join(
        f'<option value="{s}">{s}</option>' for s in STATUSES if s != c["status"])
    last = c["events"][-1] if c["events"] else None
    last_html = (f'<p class="cd-last">최근 기록 · {html.escape(last["created_at"])} {html.escape(last["kind"])}'
                 f'{" · " + html.escape(last["note"]) if last.get("note") else ""}</p>') if last else ""
    status_html = (f'<section class="cd-card o6"><div class="cd-label">처리 상태 {status_pill(c["status"])}</div>'
                   f'<form class="cd-form" method="post" action="/complaints/{cid}/record">'
                   f'<select name="status" aria-label="처리 상태 변경">{status_opts}</select>'
                   f'<input type="text" name="actor" maxlength="50" placeholder="처리자 (선택)">'
                   f'<textarea name="note" maxlength="1000" placeholder="경과 메모 (예: 학부모에게 전화로 설명함)"></textarea>'
                   f'<button type="submit" class="cd-btn solid">기록하기</button></form>'
                   f'{"<p class=cd-last>처리 완료 · " + html.escape(c["completed_at"]) + "</p>" if c["completed_at"] else last_html}</section>')
    footer = ""
    if c["homeroom_needed"]:
        footer = (f'<span class="hr ok">✓ 전달 완료 · {html.escape(c["homeroom_sent_at"])}</span>' if c["homeroom_sent_at"] else
                  f'<form class="cd-form" method="post" action="/complaints/{cid}/homeroom">'
                  f'<input type="text" name="note" maxlength="200" placeholder="전달 방법 (예: 메신저)">'
                  f'<button type="submit" class="cd-btn">전달함으로 표시</button></form>')
    head = (f'<div class="cd-head"><a class="back" href="/">← 민원 목록</a>'
            f'<div class="cd-title"><h1>민원 #{cid}</h1>{status_pill(c["status"])}</div>'
            f'<div class="meta">{html.escape(c["student"] or "학생 미상")} · 접수 {html.escape(c["created_at"])}</div></div>')
    timeline = f'<div class="box"><h3>처리 경과 <small>({len(c["events"])}건)</small></h3>{_timeline(c["events"])}</div>'
    transfer_href = f"/complaints/{cid}/transfer.hwpx" if c["route"] == "ESCALATE" or c["status"] == "이첩" else ""
    return head + banner + err + render_body(c["result"], pdf_href, footer, transfer_href, due_note, status_html, timeline)
