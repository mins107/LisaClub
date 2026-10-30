import glob
import os

import pytest

from agent.complaint import rules as R
from agent.complaint.llm import NullLLM
from agent.complaint.manual_index import Evidence, build_index
from agent.complaint.pipeline import mask_pii, run
from agent.complaint.retriever import Retriever
from agent.complaint.store import Store, make_student

PDF = os.environ.get("MANUAL_PDF", "data/학교민원처리매뉴얼.pdf")
needs_pdf = pytest.mark.skipif(not os.path.exists(PDF), reason="매뉴얼 PDF 없음")


def keys(hits):
    return {h[0].key for h in hits}


def test_reject_rules():
    assert "personal_contact" in keys(R.detect_reject("선생님 개인 번호 알려주세요"))
    assert "after_hours" in keys(R.detect_reject("문의", received_at="2026-10-30T22:00:00"))
    assert "after_hours" not in keys(R.detect_reject("문의", received_at="2026-10-30T10:00:00"))
    assert "long_call" in keys(R.detect_reject("문의", call_minutes=25))
    assert "repeat" in keys(R.detect_reject("문의", repeat_count=3))


def test_malicious_rules_and_false_positives():
    assert {"threat", "weapon"} <= keys(R.detect_malicious("칼 들고 찾아가서 가만 안 둔다"))
    assert "doxxing" in keys(R.detect_malicious("맘카페에 선생 이름이랑 사진 올릴 거야"))
    assert not R.detect_malicious("칼로리 낮은 급식을 부탁드립니다")        # 오탐 방지
    assert not R.detect_malicious("체험학습 일정이 궁금합니다")


def test_urgency_from_severity_only():
    assert R.urgency(R.detect_malicious("무능한 교사 가만 안 둔다")) == "높음"       # 모욕(3)+협박(4)
    assert R.urgency(R.detect_malicious("칼 들고 찾아가서 가만 안 둔다")) == "긴급"   # 위험물(5)
    assert R.urgency([]) == "낮음"
    assert not hasattr(R, "excitement")                                              # 흥분도는 없앴다


def _fake_result(text, route="HANDLE", repeat=1):
    return {"text_masked": text, "route": route, "route_label": route, "urgency": "낮음", "department": "기타",
            "handler": "민원대응팀", "deadline": "즉시", "repeat_count": repeat, "needs_human_review": False,
            "llm_used": False, "reject": [],
            "malicious": [{"kind": "malicious", "key": "threat", "label": "협박", "severity": 4}]}


def test_make_student():
    s = make_student(" 홍 길동 ", "305")
    assert (s.name, s.class_no) == ("홍길동", "305") and s.display() == "홍길동(305)"      # 공백 제거
    assert make_student("", "") is None and make_student(None, None) is None
    for bad in (("홍길동", ""), ("", "305"), ("홍길동", "35"), ("홍길동", "705"), ("홍길동", "3050")):
        with pytest.raises(ValueError):
            make_student(*bad)


def test_store_identifies_student_by_name_and_class():
    s = Store()
    t = "수행평가 점수 채점 기준을 알려 주세요"
    a, other_class = make_student("홍길동", "305"), make_student("홍길동", "306")
    s.save(_fake_result(t), a)
    s.save(_fake_result(t + " 다시 문의합니다", "ESCALATE"), a)
    h = s.find_history(a, t)
    assert len(h["same_student"]) == 2 and h["student"]["total"] == 2 and h["student"]["escalated"] == 1
    assert h["prior_malicious"] == 1
    h = s.find_history(other_class, t)                         # 이름이 같아도 학년반이 다르면 다른 학생
    assert h["student"] is None and h["same_student"] == [] and len(h["similar_others"]) == 2
    assert h["similar_others"][0]["student"] == "홍길동(305)"
    s.save(_fake_result("체험학습 도시락 문의"), None)          # 학생 미상도 저장된다
    assert s.find_history(None, "체험학습 도시락 문의")["similar_others"][0]["student"] is None


def _make_old_db(path, rows):
    import sqlite3
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE complainants(id INTEGER PRIMARY KEY, name TEXT, phone_last4 TEXT, created_at TEXT)")
    c.execute("CREATE TABLE complaints(id INTEGER PRIMARY KEY, complainant_id INTEGER, excitement_score INTEGER NOT NULL)")
    for _ in range(rows):
        c.execute("INSERT INTO complaints(complainant_id, excitement_score) VALUES(NULL, 0)")
    c.commit()
    c.close()


def test_store_migrates_old_schema(tmp_path):
    import sqlite3
    empty = str(tmp_path / "empty.sqlite")
    _make_old_db(empty, 0)
    s = Store(empty)                                             # 비어 있으면 이전 테이블만 지우고 새 구조로
    s.save(_fake_result("문의"), make_student("홍길동", "305"))
    assert s.find_history(make_student("홍길동", "305"), "문의")["student"]["total"] == 1
    assert not glob.glob(empty + ".bak-*")

    full = str(tmp_path / "full.sqlite")
    _make_old_db(full, 2)
    s = Store(full)                                              # 데이터가 있으면 백업 파일로 보존하고 새로 시작
    backups = glob.glob(full + ".bak-*")
    assert len(backups) == 1 and sqlite3.connect(backups[0]).execute("SELECT COUNT(*) FROM complaints").fetchone()[0] == 2
    s.save(_fake_result("문의"), None)
    assert s.find_history(None, "문의")["similar_others"][0]["id"] == 1


def test_store_history_window_and_recontact():
    from datetime import timedelta
    from agent.complaint import store as st
    s = Store(window_days=180, recontact_hours=24)
    a = make_student("홍길동", "305")
    s.save(_fake_result("교사 개인 번호 알려 주세요", "REJECTABLE"), a)
    now = st._now()
    assert s.find_history(a, "다른 내용", now=now)["recent_closed"]                       # 종결 직후 재접촉
    assert not s.find_history(a, "다른 내용", now=now + timedelta(hours=25))["recent_closed"]
    assert s.find_history(a, "교사 개인 번호 알려 주세요", now=now + timedelta(days=181))["same_student"] == []   # 기간 밖


def test_mask_pii():
    assert "[전화번호]" in mask_pii("010-1234-5678로 연락")


def test_retriever_ranks_exact_anchor():
    texts = ["급식 메뉴 안내", "업무시간 외 연락하는 경우", "학사일정 변경 안내", "통학로 안전 점검", "방과후 수강 신청"]
    ev = [Evidence(str(i), 1, "1", t, [(0, 0, 1, 1)]) for i, t in enumerate(texts)]
    assert Retriever(ev).search("업무시간 외 연락")[0][0].id == "1"


@needs_pdf
def test_index_and_pipeline_on_real_manual():
    idx = build_index(PDF)
    assert len(idx) > 500 and all(e.rects for e in idx)
    retr, store, llm = Retriever(idx), Store(), NullLLM()
    res, used = run("카톡으로 개인 번호 알려주세요", make_student("가나", "101"), retr, store, llm, received_at="2026-10-30T22:00:00")
    assert res["route"] == "REJECTABLE" and res["student"] == "가나(101)"
    assert any(e["printed_page"] == "7" and "개인" in e["text"] for e in res["evidence"])
    res, _ = run("칼 들고 찾아가서 가만 안 둔다", make_student("나다", "102"), retr, store, llm)
    assert res["route"] == "ESCALATE" and res["transfer_doc"] and res["urgency"] == "긴급"
    assert any(e["printed_page"] == "53" for e in res["evidence"])
    res, _ = run("체험학습 일정이 궁금합니다", make_student("다라", "103"), retr, store, llm)
    assert res["route"] == "HANDLE" and not res["transfer_doc"] and "excitement" not in res


@needs_pdf
def test_todo_steps_are_merged_and_ordered():
    idx = build_index(PDF)
    retr, store, llm = Retriever(idx), Store(), NullLLM()
    res, _ = run("무능한 교사 가만 안 둔다. 칼 들고 찾아가겠다", None, retr, store, llm, save=False)
    acts = res["actions"]
    texts = [a["text"] for a in acts]
    assert len(texts) == len(set(texts))                                     # 같은 조치는 한 줄만
    record = [a for a in acts if a["text"] == "녹음·녹화 내용 확인"]
    assert len(record) == 1 and {"모욕", "협박"} <= set(record[0]["reasons"]) and record[0]["evidence"]
    report = [a for a in acts if a["text"] == "관리자에게 보고"]
    assert len(report) == 1 and len(report[0]["reasons"]) >= 2
    order = ["안전 확보·신고", "증거 확보", "민원인 응대", "보고·보호", "후속 조치"]
    phases = [a["phase"] for a in acts]
    assert phases == sorted(phases, key=order.index) and phases[0] == "안전 확보·신고"   # 위험물 -> 안전 확보가 맨 앞


@needs_pdf
def test_no_student_saved_without_repeat_judgement():
    idx = build_index(PDF)
    retr, store, llm = Retriever(idx), Store(), NullLLM()
    t = "수행평가 점수 채점 기준을 알려 주세요"
    outs = [run(t, None, retr, store, llm)[0] for _ in range(4)]
    assert [o["route"] for o in outs] == ["HANDLE"] * 4         # 학생을 모르면 반복 민원으로 보지 않는다
    assert all(o["complaint_id"] for o in outs) and len(store.find_history(None, t)["similar_others"]) == 4
    stu = make_student("마바", "104")
    res, _ = run(t, stu, retr, store, llm, save=False)          # 시험 입력은 저장하지 않는다
    assert res["complaint_id"] is None and store.find_history(stu, t)["student"] is None


@needs_pdf
def test_web_classify_and_validation(tmp_path):
    import json
    import threading
    import urllib.error
    import urllib.parse
    import urllib.request
    from http.server import ThreadingHTTPServer

    from agent.complaint import web
    from agent.complaint.service import ComplaintService

    web.Handler.service = ComplaintService(PDF, ":memory:", "none")
    web.Handler.out_root = str(tmp_path)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        form_page = urllib.request.urlopen(base + "/").read().decode()
        assert "분류하기" in form_page and "학생 이름" in form_page and "학년반" in form_page
        assert "작성자 찾기" not in form_page and "api/extract" not in form_page         # 자동 찾기는 없앴다
        body = urllib.parse.urlencode({"text": "칼 들고 찾아가서 가만 안 둔다", "nosave": "1"}).encode()
        page = urllib.request.urlopen(base + "/", body).read().decode()
        assert "악성 의심" in page and "evidence_highlighted.pdf" in page and "지금 할 일" in page
        assert "민원 유형 근거" in page and "처리 절차 근거" in page                      # 근거를 유형/절차로 구분
        assert "흥분도" not in page and "매뉴얼 원본 화면 보기" not in page and "data:image/png" not in page
        pdf_url = base + "/cases/" + page.split("/cases/")[1].split('"')[0]
        assert urllib.request.urlopen(pdf_url).read(4) == b"%PDF"
        req = urllib.request.Request(base + "/api/classify", json.dumps({"text": "체험학습 일정이 궁금합니다"}).encode())
        assert json.load(urllib.request.urlopen(req))["route"] == "HANDLE"
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(base + "/", urllib.parse.urlencode({"text": "  "}).encode())
        assert e.value.code == 400
        with pytest.raises(urllib.error.HTTPError) as e:          # 이름만 입력하면 학생을 식별할 수 없다
            urllib.request.urlopen(base + "/", urllib.parse.urlencode({"text": "문의", "student": "홍길동"}).encode())
        assert e.value.code == 400 and "학년반" in e.value.read().decode()
        with pytest.raises(urllib.error.HTTPError) as e:          # 학년반 형식 오류
            urllib.request.urlopen(base + "/", urllib.parse.urlencode(
                {"text": "문의", "student": "홍길동", "class_no": "35"}).encode())
        assert e.value.code == 400 and "3자리" in e.value.read().decode()
        with pytest.raises(urllib.error.HTTPError) as e:          # /api/extract는 더 이상 없다
            urllib.request.urlopen(urllib.request.Request(base + "/api/extract", b"{}"))
        assert e.value.code == 404
        form = {"text": "선생님 개인 번호 알려주세요", "student": "홍길동", "class_no": "305"}
        urllib.request.urlopen(base + "/", urllib.parse.urlencode(form).encode())
        page = urllib.request.urlopen(base + "/", urllib.parse.urlencode({**form, "text": "체험학습 일정"}).encode()).read().decode()
        assert "종결 직후 재접촉" in page and "홍길동(305)" in page
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(base + "/cases/../../etc/passwd")
        assert e.value.code == 404
    finally:
        srv.shutdown()


@needs_pdf
def test_history_rules_from_manual():
    idx = build_index(PDF)
    retr, store, llm = Retriever(idx), Store(), NullLLM()
    a = make_student("홍길동", "305")
    # 종결 민원 직후 다른 내용으로 재접촉 -> 거부 가능(PDF 11쪽 "종결 민원으로 종결하였으나, 바로 연락이 오는 등")
    run("선생님 개인 번호 알려주세요", a, retr, store, llm)
    res, _ = run("체험학습 일정이 궁금합니다", a, retr, store, llm)
    assert res["route"] == "REJECTABLE" and any(h["key"] == "recontact" for h in res["reject"])
    assert any(e["printed_page"] == "7" and "바로 연락" in e["text"] for e in res["evidence"])
    assert res["needs_human_review"] and res["history"]["recent_closed"]
    # 과거 악성 이력 -> 재접촉 대응 안내(PDF 49쪽)와 사람 확인 요구. 분기는 현재 민원 내용으로만 정해진다.
    b = make_student("김철수", "206")
    run("칼 들고 찾아가서 가만 안 둔다", b, retr, store, llm)
    res, _ = run("체험학습 일정이 궁금합니다", b, retr, store, llm)
    assert res["route"] == "HANDLE" and res["history"]["prior_malicious"] == 1 and res["needs_human_review"]
    assert any("재접촉 1차" in x["text"] and x["evidence"] for x in res["actions"])
    res, _ = run("또 가만 안 둔다", b, retr, store, llm)                    # 악성 이력 1건 -> 1차 대응, 접촉 제한 검토 함께 안내
    assert res["route"] == "ESCALATE" and any("재접촉 1차" in x["text"] for x in res["actions"])
    assert any("출입·면담 제한" in x["text"] for x in res["actions"])
    res, _ = run("또 가만 안 둔다", b, retr, store, llm)                    # 악성 이력 2건 -> 2차(상급자 응대)
    assert res["history"]["prior_malicious"] == 2 and any("재접촉 2차 이상" in x["text"] for x in res["actions"])


@needs_pdf
def test_repeat_closed_then_escalate():
    idx = build_index(PDF)
    retr, store, llm = Retriever(idx), Store(), NullLLM()
    t = "수행평가 점수 채점 기준을 알려 주세요"
    routes = [run(t, make_student("사아", "109"), retr, store, llm)[0]["route"] for _ in range(5)]
    assert routes[:2] == ["HANDLE", "HANDLE"] and routes[2] == "REJECTABLE" and routes[4] == "ESCALATE"
