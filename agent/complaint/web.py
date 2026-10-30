"""민원대응팀용 웹 화면. 실행: python -m agent.complaint.web [--port 8000] [--llm auto|on|none]

 /                       메인 화면: 민원 DB 대시보드(요약·그래프·목록·조회) + 새 민원 입력
 /complaints/<번호>       민원 상세: 분류 결과 + 처리 상태·경과 기록 + 담임 교사 전달
 /api/classify           프로그램 연동용 JSON API

외부 의존성 없이 표준 라이브러리 http.server만 쓴다. 기본은 내 컴퓨터(127.0.0.1)에서만 접속된다.
"""
import argparse
import html
import json
import os
import re
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .dashboard import DASH_CSS, render_dashboard, render_detail
from .highlight import PAGE_SCRIPT, STYLE, render_body
from .service import ComplaintService

MAX_TEXT = 5000
PER_PAGE = 20
CASE_ID = re.compile(r"^(web-\d{8}-\d{6}-[0-9a-f]{4}|complaint-\d+)$")
FILES = {"report.html": "text/html; charset=utf-8", "result.json": "application/json; charset=utf-8",
         "evidence_highlighted.pdf": "application/pdf"}
FILTER_KEYS = ("status", "route", "department", "urgency", "homeroom", "overdue", "q")

FORM_CSS = """
.field-label{display:block;font-weight:700;margin-bottom:6px}
.req{font-size:.72em;color:var(--on-c);background:var(--red);border-radius:6px;padding:0 6px;margin-left:4px;vertical-align:1px}
textarea{width:100%;min-height:150px;padding:12px;font:inherit;font-size:1.02em;line-height:1.6;color:var(--text);
background:var(--card);border:1px solid var(--border);border-radius:10px;resize:vertical}
textarea:focus,input:focus,select:focus{outline:2px solid color-mix(in srgb,var(--primary) 50%,transparent);border-color:var(--primary)}
.ta-foot{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:6px;margin:6px 0 14px;font-size:.84em;color:var(--muted)}
.ta-foot .btn{margin-left:4px}
.groups{display:grid;grid-template-columns:1fr;gap:12px}
fieldset{border:1px solid var(--border);border-radius:10px;margin:0;padding:10px 14px 12px}
legend{font-weight:700;padding:0 6px} legend small{font-weight:400;color:var(--muted)}
.fields{display:flex;flex-wrap:wrap;gap:10px} .fields label{display:flex;flex-direction:column;font-size:.82em;color:var(--muted);gap:3px}
input[type=text],input[type=number],input[type=datetime-local]{padding:8px 10px;font:inherit;color:var(--text);
background:var(--card);border:1px solid var(--border);border-radius:8px}
.hint{margin:8px 0 0;font-size:.8em;color:var(--muted)}
.actions{display:flex;flex-wrap:wrap;align-items:center;gap:10px 14px;margin-top:16px}
button.primary{background:var(--primary);color:#fff;border:0;border-radius:10px;padding:11px 32px;font:inherit;font-size:1.02em;font-weight:800;cursor:pointer}
button.primary:disabled{opacity:.6;cursor:wait}
.chk{font-size:.88em;color:var(--muted);display:flex;gap:6px;align-items:center}
.err{background:var(--err-bg);color:var(--err-text);border-radius:10px;padding:10px 14px;margin-bottom:14px;font-weight:600;scroll-margin-top:60px}
.summary{scroll-margin-top:60px} .nav{margin-left:auto;display:flex;gap:8px}
.btn.cta{background:var(--primary);color:#fff;border-color:var(--primary);font-weight:800}
"""

FORM_SCRIPT = """
(function(){var t=document.getElementById('t'),c=document.getElementById('cnt'),f=document.getElementById('f'),g=document.getElementById('go');
if(!t||!f)return;
function u(){c.textContent=t.value.length+' / __MAX__자'}
t.addEventListener('input',u);u();
document.querySelectorAll('[data-sample]').forEach(function(b){b.addEventListener('click',function(){t.value=b.dataset.sample;u();t.focus()})});
f.addEventListener('submit',function(){g.disabled=true;g.textContent='분류 중…'});
window.addEventListener('pageshow',function(){g.disabled=false;g.textContent='분류하기'});
var r=document.querySelector('.err');if(r)r.scrollIntoView({block:'start'});})();
""".replace("__MAX__", str(MAX_TEXT))

SAMPLES = [("개인 연락처 요청", "선생님 개인 번호 좀 알려주세요. 카톡으로 상담하고 싶어요."),
           ("일반 문의", "수행평가 점수가 이해되지 않습니다. 채점 기준을 확인하고 싶습니다. 왜 이 점수인지 이유를 알려 주세요."),
           ("폭언·협박", "담임 때문에 우리 애가 학교 가기 싫대요!! 이게 말이 됩니까?? 당장 책임지세요. 이런 무능한 교사는 자격 없어요, 가만 안 둡니다.")]


def _layout(main_html):
    return (f'<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>학교 민원 관리</title><style>{STYLE}{FORM_CSS}{DASH_CSS}</style>'
            f'<header class="topbar"><div class="wrap"><b>학교 민원 관리</b><span>민원대응팀 · 매뉴얼 근거 기반 자동 분류</span>'
            f'<div class="nav noprint"><a class="btn" href="/">대시보드</a><a class="btn cta" href="/#new">＋ 새 민원 입력</a></div></div></header>'
            f'<main class="wrap">{main_html}</main><script>{PAGE_SCRIPT}{FORM_SCRIPT}</script>')


def _form(v=None, error=""):
    v = v or {}
    g = lambda k: html.escape(v.get(k, ""))  # noqa: E731
    err = f'<div class="err" role="alert">{html.escape(error)}</div>' if error else ""
    samples = "".join(f'<button type="button" class="btn" data-sample="{html.escape(t, quote=True)}">{html.escape(n)}</button>'
                      for n, t in SAMPLES)
    return f"""{err}<form method="post" action="/classify" id="f" class="box">
<h2>＋ 새 민원 입력</h2>
<label class="field-label" for="t">접수된 민원 내용 <span class="req">필수</span></label>
<textarea id="t" name="text" maxlength="{MAX_TEXT}" placeholder="접수한 민원 내용을 그대로 붙여넣으세요." required>{g('text')}</textarea>
<div class="ta-foot"><span id="cnt">0 / {MAX_TEXT}자</span><span>예시 {samples}</span></div>
<div class="groups">
<fieldset><legend>민원 대상 학생 <small>선택</small></legend><div class="fields">
<label>학생 이름<input type="text" name="student" value="{g('student')}" placeholder="예: 홍길동" style="width:140px"></label>
<label>학년반<input type="text" name="class_no" value="{g('class_no')}" placeholder="예: 305" maxlength="3" inputmode="numeric" pattern="[1-6][0-9]{{2}}" style="width:100px"></label></div>
<p class="hint">둘 다 입력하면 같은 학생의 과거 이력(반복 민원, 종결 직후 재접촉, 과거 악성 이력)을 반영합니다. 학년반은 3학년 5반 → 305처럼 숫자 3자리이고, 둘 다 비우면 '학생 미상'으로 저장합니다.</p></fieldset>
<fieldset><legend>접수 정보 <small>선택</small></legend><div class="fields">
<label>접수 시각<input type="datetime-local" name="received_at" value="{g('received_at')}"></label>
<label>통화·면담 시간(분)<input type="number" name="call_minutes" min="0" step="1" value="{g('call_minutes')}" style="width:110px"></label></div>
<p class="hint">접수 시각은 업무시간 외 연락, 통화·면담 시간은 20분 초과 판정에 쓰입니다. 비워도 됩니다.</p></fieldset>
</div>
<div class="actions"><button type="submit" id="go" class="primary">분류하기</button><a class="btn" href="/">초기화</a>
<label class="chk"><input type="checkbox" name="nosave" value="1" {'checked' if v.get('nosave') else ''}>시험 입력 (DB에 저장 안 함)</label></div>
<p class="foot" style="margin-top:12px">저장된 민원은 대시보드에 나타나고 처리 경과를 기록할 수 있습니다. 전화번호·주민번호·이메일은 가려진 채 저장됩니다.</p></form>"""


class Handler(BaseHTTPRequestHandler):
    service = None
    out_root = "out/web"

    # ---- 응답 도우미 ----
    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, url):
        self.send_response(303)
        self.send_header("Location", url)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def _not_found(self):
        self._send(404, _layout('<div class="box"><h2>찾을 수 없습니다</h2><a class="btn" href="/">대시보드로</a></div>'))

    def _dashboard(self, form_html, filters=None, page=1, code=200):
        filters = filters or {}
        store = self.service.store
        rows, total = store.list_complaints(
            status=filters.get("status"), route=filters.get("route"), department=filters.get("department"),
            urgency=filters.get("urgency"), homeroom=filters.get("homeroom"), overdue=bool(filters.get("overdue")),
            q=filters.get("q"), page=page, per_page=PER_PAGE)
        body = render_dashboard(store.stats(), rows, total, filters, page, PER_PAGE, form_html)
        self._send(code, _layout(body))

    def _pdf_href(self, case_id):
        f = os.path.join(self.out_root, case_id, "evidence_highlighted.pdf")
        return f"/cases/{case_id}/evidence_highlighted.pdf" if os.path.isfile(f) else None

    def _detail(self, cid, code=200, new=False, error=""):
        c = self.service.store.get_complaint(cid)
        if c is None:
            return self._not_found()
        self._send(code, _layout(render_detail(c, self._pdf_href(f"complaint-{cid}"), new, error)))

    def _read_form(self, as_json=False):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(n, 64 * 1024))
        if as_json:
            return {k: ("" if x is None else str(x)) for k, x in json.loads(raw or b"{}").items()}
        return {k: x[0] for k, x in parse_qs(raw.decode("utf-8"), keep_blank_values=True).items()}

    # ---- GET ----
    def do_GET(self):  # noqa: N802
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path
        if path == "/":
            filters = {k: qs.get(k, [""])[0].strip() for k in FILTER_KEYS}
            try:
                page = max(int(qs.get("page", ["1"])[0]), 1)
            except ValueError:
                page = 1
            return self._dashboard(_form(), filters, page)
        m = re.match(r"^/complaints/(\d+)$", path)
        if m:
            return self._detail(int(m.group(1)), new=bool(qs.get("new")))
        m = re.match(r"^/cases/([^/]+)/([^/]+)$", path)
        if m and CASE_ID.match(m.group(1)) and m.group(2) in FILES:
            f = os.path.join(self.out_root, m.group(1), m.group(2))
            if os.path.isfile(f):
                with open(f, "rb") as fh:
                    return self._send(200, fh.read(), FILES[m.group(2)])
        self._send(404, "찾을 수 없습니다.", "text/plain; charset=utf-8")

    # ---- POST ----
    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        m = re.match(r"^/complaints/(\d+)/(record|homeroom)$", path)
        if m:
            return self._post_progress(int(m.group(1)), m.group(2))
        if path not in ("/", "/classify", "/api/classify"):
            return self._send(404, "찾을 수 없습니다.", "text/plain; charset=utf-8")
        is_json = path == "/api/classify"
        try:
            v = self._read_form(as_json=is_json)
        except (ValueError, UnicodeDecodeError, AttributeError):
            return self._send(400, "요청 형식이 올바르지 않습니다.", "text/plain; charset=utf-8")
        self._post_classify(v, is_json)

    def _fail(self, v, msg, is_json, code=400):
        if is_json:
            return self._json(code, {"error": msg})
        self._dashboard(_form(v, msg), code=code)

    def _post_classify(self, v, is_json):
        text = (v.get("text") or "").strip()
        err = ""
        if not text:
            err = "민원 내용을 입력해 주세요."
        elif len(text) > MAX_TEXT:
            err = f"민원 내용은 {MAX_TEXT}자 이하로 입력해 주세요."
        minutes = None
        if not err and (v.get("call_minutes") or "").strip():
            try:
                minutes = float(v["call_minutes"])
            except ValueError:
                err = "통화·면담 시간은 숫자(분)로 입력해 주세요."
        received = (v.get("received_at") or "").strip() or None
        if not err and received:
            try:
                datetime.fromisoformat(received)
            except ValueError:
                err = "접수 시각 형식이 올바르지 않습니다."
        if err:
            return self._fail(v, err, is_json)
        try:
            res, used = self.service.classify(text, v.get("student"), v.get("class_no"), received, minutes,
                                              save=not v.get("nosave"))
            cid = res.get("complaint_id")
            case_id = f"complaint-{cid}" if cid else f"web-{datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:4]}"
            self.service.save_outputs(res, used, os.path.join(self.out_root, case_id))
        except ValueError as e:         # 학생 이름·학년반 입력 오류
            return self._fail(v, str(e), is_json)
        except Exception as e:  # noqa: BLE001
            print(f"[web] 오류: {type(e).__name__}: {str(e).splitlines()[0][:200] if str(e) else ''}")
            return self._fail(v, f"분류 중 오류가 발생했습니다({type(e).__name__}). 서버 실행 창의 로그를 확인해 주세요.",
                              is_json, 500)
        if is_json:
            return self._json(200, res)
        if cid:                         # 저장된 민원은 상세 화면(처리 경과 기록)으로 이동
            return self._redirect(f"/complaints/{cid}?new=1")
        notice = ('<a class="back" href="/">← 대시보드로</a><div class="box" style="margin-top:10px"><b>시험 입력입니다.</b> '
                  'DB에 저장하지 않아 대시보드에 나타나지 않고 처리 경과도 기록할 수 없습니다.</div>')
        self._send(200, _layout(notice + render_body(res, self._pdf_href(case_id))))

    def _post_progress(self, cid, action):
        store = self.service.store
        c = store.get_complaint(cid)
        if c is None:
            return self._not_found()
        try:
            v = self._read_form()
        except (ValueError, UnicodeDecodeError):
            return self._send(400, "요청 형식이 올바르지 않습니다.", "text/plain; charset=utf-8")
        note, actor = (v.get("note") or "").strip(), (v.get("actor") or "").strip()
        if action == "homeroom":
            if not c["homeroom_needed"]:
                return self._detail(cid, 400, error="담임 교사 전달 대상이 아닌 민원입니다.")
            if not c["homeroom_sent_at"]:
                store.mark_homeroom_sent(cid, note, actor)
        else:
            status = (v.get("status") or "").strip()
            if status and status != c["status"]:
                try:
                    store.set_status(cid, status, note, actor)
                except ValueError as e:
                    return self._detail(cid, 400, error=str(e))
            elif note:
                store.add_event(cid, "메모", note, None, actor)
            else:
                return self._detail(cid, 400, error="처리 상태를 바꾸거나 경과 메모를 입력해 주세요.")
        self._redirect(f"/complaints/{cid}")

    def log_message(self, fmt, *args):      # 민원 내용이 로그에 남지 않도록 요청 줄만 기록
        print(f"[web] {self.command} {urlparse(self.path).path} -> {args[1] if len(args) > 1 else ''}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--llm", choices=["auto", "on", "none"], default="auto")
    ap.add_argument("--pdf")
    ap.add_argument("--db")
    ap.add_argument("--out", default="out/web")
    a = ap.parse_args()
    try:
        svc = ComplaintService(a.pdf, a.db, a.llm)
    except FileNotFoundError as e:
        raise SystemExit(str(e))
    Handler.service, Handler.out_root = svc, a.out
    print(f"근거 단위 {len(svc.index)}개 색인 / LLM: {'연결' if svc.llm.available else '미연결(규칙 기반)'}")
    print(f"접속 주소: http://{a.host}:{a.port}  (종료: Ctrl+C)")
    ThreadingHTTPServer((a.host, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
