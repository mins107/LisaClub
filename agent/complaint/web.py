"""민원대응팀용 웹 화면. 실행: python -m agent.complaint.web [--port 8000] [--llm auto|on|none]

민원 텍스트를 붙여넣고 [분류하기]를 누르면 같은 화면 아래에 분류 결과가 나온다.
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

from .extract import extract_author
from .highlight import PAGE_SCRIPT, STYLE, render_body
from .service import ComplaintService

MAX_TEXT = 5000
CASE_ID = re.compile(r"^web-\d{8}-\d{6}-[0-9a-f]{4}$")
FILES = {"report.html": "text/html; charset=utf-8", "result.json": "application/json; charset=utf-8",
         "evidence_highlighted.pdf": "application/pdf"}

FORM_CSS = """
.field-label{display:block;font-weight:700;margin-bottom:6px}
.req{font-size:.72em;color:var(--on-c);background:var(--red);border-radius:6px;padding:0 6px;margin-left:4px;vertical-align:1px}
textarea{width:100%;min-height:170px;padding:12px;font:inherit;font-size:1.02em;line-height:1.6;color:var(--text);
background:var(--card);border:1px solid var(--border);border-radius:10px;resize:vertical}
textarea:focus,input:focus{outline:2px solid color-mix(in srgb,var(--primary) 50%,transparent);border-color:var(--primary)}
.ta-foot{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:6px;margin:6px 0 14px;font-size:.84em;color:var(--muted)}
.ta-foot .btn{margin-left:4px}
.groups{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}
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
.summary{scroll-margin-top:60px}
"""

FORM_SCRIPT = """
(function(){var t=document.getElementById('t'),c=document.getElementById('cnt'),f=document.getElementById('f'),g=document.getElementById('go');
if(!t||!f)return;
function u(){c.textContent=t.value.length+' / __MAX__자'}
t.addEventListener('input',u);u();
document.querySelectorAll('[data-sample]').forEach(function(b){b.addEventListener('click',function(){t.value=b.dataset.sample;u();t.focus();find(false)})});
var nm=document.getElementById('nm'),ph=document.getElementById('ph'),note=document.getElementById('auto-note'),timer=null;
function find(force){var v=t.value;if(v.trim().length<4)return;
fetch('/api/extract',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:v})})
.then(function(r){return r.json()}).then(function(d){var m=[];
if(d.name&&(force||!nm.value||nm.dataset.auto)){nm.value=d.name;nm.dataset.auto='1';m.push('이름 '+d.name)}
if(d.phone_last4&&(force||!ph.value||ph.dataset.auto)){ph.value=d.phone_last4;ph.dataset.auto='1';m.push('연락처 끝 '+d.phone_last4)}
note.textContent=m.length?'민원 내용에서 찾아 입력했습니다: '+m.join(', ')+' — 맞는지 확인하세요.':(force?'민원 내용에서 작성자 정보를 찾지 못했습니다. 직접 입력해 주세요.':'')}).catch(function(){})}
t.addEventListener('input',function(){clearTimeout(timer);timer=setTimeout(function(){find(false)},700)});
[nm,ph].forEach(function(e){e.addEventListener('input',function(){delete e.dataset.auto})});
document.getElementById('find-author').addEventListener('click',function(){find(true)});
f.addEventListener('submit',function(){g.disabled=true;g.textContent='분류 중…'});
window.addEventListener('pageshow',function(){g.disabled=false;g.textContent='분류하기'});
var r=document.getElementById('result')||document.querySelector('.err');if(r)r.scrollIntoView({block:'start'});})();
""".replace("__MAX__", str(MAX_TEXT))

SAMPLES = [("개인 연락처 요청", "선생님 개인 번호 좀 알려주세요. 카톡으로 상담하고 싶어요."),
           ("일반 문의", "수행평가 점수가 이해되지 않습니다. 채점 기준을 확인하고 싶습니다."),
           ("작성자 포함", "저는 홍길동입니다. 어제 담임 선생님과 통화했는데 숙제 양이 너무 많습니다. 줄여 주셨으면 합니다. 연락처는 010-1234-5678입니다."),
           ("폭언·협박", "담임 때문에 우리 애가 학교 가기 싫대요!! 이게 말이 됩니까?? 당장 책임지세요. 이런 무능한 교사는 자격 없어요, 가만 안 둡니다.")]


def _page(form, body=""):
    return (f'<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>학교 민원 분류</title><style>{STYLE}{FORM_CSS}</style>'
            f'<header class="topbar"><div class="wrap"><b>학교 민원 분류</b><span>민원대응팀 · 매뉴얼 근거 기반 자동 분류</span>'
            f'<a class="btn noprint" href="/" style="margin-left:auto">새 민원 입력</a></div></header>'
            f'<main class="wrap">{form}{body}</main><script>{PAGE_SCRIPT}{FORM_SCRIPT}</script>')


def _form(v=None, error=""):
    v = v or {}
    g = lambda k: html.escape(v.get(k, ""))  # noqa: E731
    err = f'<div class="err" role="alert">{html.escape(error)}</div>' if error else ""
    samples = "".join(f'<button type="button" class="btn" data-sample="{html.escape(t, quote=True)}">{html.escape(n)}</button>'
                      for n, t in SAMPLES)
    return f"""{err}<form method="post" action="/" id="f" class="box">
<h2>민원 내용 입력</h2>
<label class="field-label" for="t">접수된 민원 내용 <span class="req">필수</span></label>
<textarea id="t" name="text" maxlength="{MAX_TEXT}" placeholder="접수한 민원 내용을 그대로 붙여넣으세요." required>{g('text')}</textarea>
<div class="ta-foot"><span id="cnt">0 / {MAX_TEXT}자</span><span>예시 넣기 {samples}</span></div>
<div class="groups">
<fieldset><legend>작성자 <small>선택</small></legend><div class="fields">
<label>이름<input type="text" name="name" id="nm" value="{g('name')}" placeholder="예: 홍길동" style="width:150px"></label>
<label>연락처 끝 4자리<input type="text" name="phone" id="ph" value="{g('phone')}" placeholder="예: 1234" maxlength="4" inputmode="numeric" pattern="[0-9]{{4}}" style="width:120px"></label></div>
<p class="hint" style="margin-top:10px"><button type="button" class="btn" id="find-author">민원 내용에서 작성자 찾기</button>
<span id="auto-note" role="status"></span></p>
<p class="hint">민원 내용에 "성명: 홍길동", "저는 홍길동입니다", 전화번호가 있으면 자동으로 채웁니다(채운 값은 꼭 확인하세요). 이름과 연락처 끝자리를 둘 다 입력하면 같은 사람의 과거 이력(반복 민원, 종결 직후 재접촉, 과거 악성 이력)을 반영합니다. 둘 다 비우면 '작성자 미상'으로 저장합니다.</p></fieldset>
<fieldset><legend>접수 정보 <small>선택</small></legend><div class="fields">
<label>접수 시각<input type="datetime-local" name="received_at" value="{g('received_at')}"></label>
<label>통화·면담 시간(분)<input type="number" name="call_minutes" min="0" step="1" value="{g('call_minutes')}" style="width:130px"></label></div>
<p class="hint">접수 시각은 업무시간 외 연락, 통화·면담 시간은 20분 초과 판정에 쓰입니다. 비워도 됩니다.</p></fieldset>
</div>
<div class="actions"><button type="submit" id="go" class="primary">분류하기</button><a class="btn" href="/">초기화</a>
<label class="chk"><input type="checkbox" name="nosave" value="1" {'checked' if v.get('nosave') else ''}>시험 입력 (DB에 저장하지 않음)</label></div>
<p class="foot" style="margin-top:12px">처리한 민원은 DB에 저장됩니다. 전화번호·주민번호·이메일은 자동으로 가려진 채 저장됩니다.</p></form>"""


class Handler(BaseHTTPRequestHandler):
    service = None
    out_root = "out/web"

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path == "/":
            return self._send(200, _page(_form()))
        m = re.match(r"^/cases/([^/]+)/([^/]+)$", path)
        if m and CASE_ID.match(m.group(1)) and m.group(2) in FILES:
            f = os.path.join(self.out_root, m.group(1), m.group(2))
            if os.path.isfile(f):
                with open(f, "rb") as fh:
                    return self._send(200, fh.read(), FILES[m.group(2)])
        self._send(404, "찾을 수 없습니다.", "text/plain; charset=utf-8")

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(n, 64 * 1024))
        is_json = path == "/api/classify"
        if path == "/api/extract":          # 민원 내용에서 작성자(이름·연락처 끝자리) 찾기. 저장하지 않는다.
            try:
                text = str(json.loads(raw or b"{}").get("text") or "")[:MAX_TEXT]
            except (ValueError, AttributeError):
                return self._send(400, "요청 형식이 올바르지 않습니다.", "text/plain; charset=utf-8")
            return self._send(200, json.dumps(extract_author(text), ensure_ascii=False), "application/json; charset=utf-8")
        if path not in ("/", "/api/classify"):
            return self._send(404, "찾을 수 없습니다.", "text/plain; charset=utf-8")
        try:
            if is_json:
                v = {k: ("" if x is None else str(x)) for k, x in json.loads(raw or b"{}").items()}
            else:
                v = {k: x[0] for k, x in parse_qs(raw.decode("utf-8"), keep_blank_values=True).items()}
        except (ValueError, UnicodeDecodeError):
            return self._send(400, "요청 형식이 올바르지 않습니다.", "text/plain; charset=utf-8")

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
            if is_json:
                return self._send(400, json.dumps({"error": err}, ensure_ascii=False), "application/json; charset=utf-8")
            return self._send(400, _page(_form(v, err)))

        case_id = f"web-{datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:4]}"
        try:
            res, used = self.service.classify(text, v.get("name"), v.get("phone"), received, minutes,
                                              save=not v.get("nosave"))
            snippets = self.service.save_outputs(res, used, os.path.join(self.out_root, case_id))
        except ValueError as e:         # 이름·연락처 입력 오류
            if is_json:
                return self._send(400, json.dumps({"error": str(e)}, ensure_ascii=False), "application/json; charset=utf-8")
            return self._send(400, _page(_form(v, str(e))))
        except Exception as e:  # noqa: BLE001
            print(f"[web] 오류: {type(e).__name__}: {str(e).splitlines()[0][:200] if str(e) else ''}")
            msg = f"분류 중 오류가 발생했습니다({type(e).__name__}). 서버 실행 창의 로그를 확인해 주세요."
            if is_json:
                return self._send(500, json.dumps({"error": msg}, ensure_ascii=False), "application/json; charset=utf-8")
            return self._send(500, _page(_form(v, msg)))
        if is_json:
            return self._send(200, json.dumps(res, ensure_ascii=False), "application/json; charset=utf-8")
        href = f"/cases/{case_id}/evidence_highlighted.pdf" if used else None
        self._send(200, _page(_form(v), render_body(res, snippets, href)))

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
