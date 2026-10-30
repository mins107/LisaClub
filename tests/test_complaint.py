import os

import pytest

from agent.complaint import rules as R
from agent.complaint.llm import NullLLM
from agent.complaint.manual_index import Evidence, build_index
from agent.complaint.pipeline import mask_pii, run
from agent.complaint.retriever import Retriever
from agent.complaint.store import Store, make_author

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


def test_excitement_and_urgency():
    hits = R.detect_malicious("무능한 교사 가만 안 둔다!!")
    score, level = R.excitement("무능한 교사 가만 안 둔다!!", hits)
    assert level in ("주의", "고위험") and R.urgency(hits, level) in ("높음", "긴급")


def _fake_result(text, route="HANDLE", repeat=1):
    return {"text_masked": text, "route": route, "route_label": route, "urgency": "낮음", "department": "기타",
            "handler": "민원대응팀", "deadline": "즉시", "excitement": {"score": 0, "level": "낮음"},
            "repeat_count": repeat, "needs_human_review": False, "llm_used": False,
            "reject": [], "malicious": [{"kind": "malicious", "key": "threat", "label": "협박", "severity": 4}]}


def test_make_author():
    a = make_author(" 홍 길동 ", "010-1234-5678")
    assert (a.name, a.last4) == ("홍길동", "5678")           # 공백 제거, 연락처는 끝 4자리만 남긴다
    assert make_author("", "") is None and make_author(None, None) is None
    for bad in (("홍길동", ""), ("", "1234"), ("홍길동", "12")):
        with pytest.raises(ValueError):
            make_author(*bad)


def test_store_identifies_author_by_name_and_last4():
    s = Store()
    t = "수행평가 점수 채점 기준을 알려 주세요"
    a, same_name_other_phone = make_author("홍길동", "1234"), make_author("홍길동", "9999")
    s.save(_fake_result(t), a)
    s.save(_fake_result(t + " 다시 문의합니다", "ESCALATE"), a)
    h = s.find_history(a, t)
    assert len(h["same_author"]) == 2 and h["author"]["total"] == 2 and h["author"]["escalated"] == 1
    assert h["prior_malicious"] == 1
    h = s.find_history(same_name_other_phone, t)              # 이름이 같아도 끝자리가 다르면 다른 작성자
    assert h["author"] is None and h["same_author"] == [] and len(h["similar_others"]) == 2
    s.save(_fake_result("체험학습 도시락 문의"), None)          # 작성자 미상도 저장된다
    assert s.find_history(None, "체험학습 도시락 문의")["similar_others"][0]["author"] is None


def test_extract_author():
    from agent.complaint.extract import extract_author as x
    r = x("저는 홍길동입니다. 연락처는 010-1234-5678입니다. 숙제를 줄여 주세요.")
    assert (r["name"], r["phone_last4"]) == ("홍길동", "5678") and len(r["found"]) == 2
    r = x("성명: 박지은 / 연락처 01098765432")                      # 이름 끝 글자가 조사처럼 보여도 잘리지 않는다
    assert (r["name"], r["phone_last4"]) == ("박지은", "5432")
    r = x("민원인 김서이 님이 전화함. 뒷번호는 4321입니다.")
    assert (r["name"], r["phone_last4"]) == ("김서이", "4321")
    assert x("이름은 남궁민수입니다")["name"] == "남궁민수"
    for no in ("박지민 어머니가 전화하셨어요. 담임 김철수 선생님께 항의",      # 관계 표현 앞 이름은 학생일 수 있어 찾지 않는다
               "민원인이 지속적으로 전화를 합니다", "저는 학부모입니다", "체험학습 일정이 궁금합니다", ""):
        assert x(no)["name"] == "" and x(no)["phone_last4"] == ""


def test_store_replaces_empty_old_schema_but_keeps_data(tmp_path):
    import sqlite3
    path = str(tmp_path / "old.sqlite")
    def make_old(rows):
        c = sqlite3.connect(path)
        c.execute("DROP TABLE IF EXISTS complainants"); c.execute("DROP TABLE IF EXISTS complaints")
        c.execute("CREATE TABLE complainants(id INTEGER PRIMARY KEY, label TEXT, created_at TEXT)")
        c.execute("CREATE TABLE complaints(id INTEGER PRIMARY KEY, complainant_id INTEGER)")
        for i in range(rows):
            c.execute("INSERT INTO complaints(complainant_id) VALUES(NULL)")
        c.commit(); c.close()
    make_old(0)
    s = Store(path)                                              # 비어 있으면 새 구조로 바뀐다
    s.save(_fake_result("문의"), make_author("홍길동", "1234"))
    assert s.find_history(make_author("홍길동", "1234"), "문의")["author"]["total"] == 1
    make_old(2)
    with pytest.raises(RuntimeError, match="이전 버전"):          # 데이터가 있으면 덮어쓰지 않는다
        Store(path)
    assert sqlite3.connect(path).execute("SELECT COUNT(*) FROM complaints").fetchone()[0] == 2


def test_store_history_window_and_recontact():
    from datetime import timedelta
    from agent.complaint import store as st
    s = Store(window_days=180, recontact_hours=24)
    a = make_author("홍길동", "1234")
    s.save(_fake_result("교사 개인 번호 알려 주세요", "REJECTABLE"), a)
    now = st._now()
    assert s.find_history(a, "다른 내용", now=now)["recent_closed"]                       # 종결 직후 재접촉
    assert not s.find_history(a, "다른 내용", now=now + timedelta(hours=25))["recent_closed"]
    assert s.find_history(a, "교사 개인 번호 알려 주세요", now=now + timedelta(days=181))["same_author"] == []   # 기간 밖


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
    res, used = run("카톡으로 개인 번호 알려주세요", make_author("가", "0001"), retr, store, llm, received_at="2026-10-30T22:00:00")
    assert res["route"] == "REJECTABLE"
    assert any(e["printed_page"] == "7" and "개인" in e["text"] for e in res["evidence"])
    res, _ = run("칼 들고 찾아가서 가만 안 둔다", make_author("나", "0002"), retr, store, llm)
    assert res["route"] == "ESCALATE" and res["transfer_doc"] and res["urgency"] == "긴급"
    assert any(e["printed_page"] == "53" for e in res["evidence"])
    res, _ = run("체험학습 일정이 궁금합니다", make_author("다", "0003"), retr, store, llm)
    assert res["route"] == "HANDLE" and not res["transfer_doc"]


@needs_pdf
def test_no_complainant_saved_without_repeat_judgement():
    idx = build_index(PDF)
    retr, store, llm = Retriever(idx), Store(), NullLLM()
    t = "수행평가 점수 채점 기준을 알려 주세요"
    outs = [run(t, None, retr, store, llm)[0] for _ in range(4)]
    assert [o["route"] for o in outs] == ["HANDLE"] * 4         # 작성자를 모르면 반복 민원으로 보지 않는다
    assert all(o["complaint_id"] for o in outs) and len(store.find_history(None, t)["similar_others"]) == 4
    res, _ = run(t, make_author("라", "0005"), retr, store, llm, save=False)          # 시험 입력은 저장하지 않는다
    assert res["complaint_id"] is None and store.find_history(make_author("라", "0005"), t)["author"] is None


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
        assert "분류하기" in urllib.request.urlopen(base + "/").read().decode()
        body = urllib.parse.urlencode({"text": "칼 들고 찾아가서 가만 안 둔다", "nosave": "1"}).encode()
        page = urllib.request.urlopen(base + "/", body).read().decode()
        assert "악성 의심" in page and "매뉴얼 근거" in page and "evidence_highlighted.pdf" in page
        pdf_url = base + "/cases/" + page.split("/cases/")[1].split('"')[0]
        assert urllib.request.urlopen(pdf_url).read(4) == b"%PDF"
        req = urllib.request.Request(base + "/api/classify", json.dumps({"text": "체험학습 일정이 궁금합니다"}).encode())
        assert json.load(urllib.request.urlopen(req))["route"] == "HANDLE"
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(base + "/", urllib.parse.urlencode({"text": "  "}).encode())
        assert e.value.code == 400
        with pytest.raises(urllib.error.HTTPError) as e:          # 이름만 입력하면 작성자를 식별할 수 없다
            urllib.request.urlopen(base + "/", urllib.parse.urlencode({"text": "문의", "name": "홍길동"}).encode())
        assert e.value.code == 400 and "연락처 끝자리" in e.value.read().decode()
        ext = urllib.request.Request(base + "/api/extract", json.dumps({"text": "저는 홍길동입니다. 010-1234-5678"}).encode())
        r = json.load(urllib.request.urlopen(ext))               # 민원 내용에서 작성자 자동 찾기
        assert (r["name"], r["phone_last4"]) == ("홍길동", "5678")
        form = {"text": "선생님 개인 번호 알려주세요", "name": "홍길동", "phone": "1234"}
        urllib.request.urlopen(base + "/", urllib.parse.urlencode(form).encode())
        page = urllib.request.urlopen(base + "/", urllib.parse.urlencode({**form, "text": "체험학습 일정"}).encode()).read().decode()
        assert "종결 직후 재접촉" in page and "홍길동(끝 1234)" in page
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(base + "/cases/../../etc/passwd")
        assert e.value.code == 404
    finally:
        srv.shutdown()


@needs_pdf
def test_history_rules_from_manual():
    idx = build_index(PDF)
    retr, store, llm = Retriever(idx), Store(), NullLLM()
    a = make_author("홍길동", "1234")
    # 종결 민원 직후 다른 내용으로 재접촉 -> 거부 가능(PDF 11쪽 "종결 민원으로 종결하였으나, 바로 연락이 오는 등")
    run("선생님 개인 번호 알려주세요", a, retr, store, llm)
    res, _ = run("체험학습 일정이 궁금합니다", a, retr, store, llm)
    assert res["route"] == "REJECTABLE" and any(h["key"] == "recontact" for h in res["reject"])
    assert any(e["printed_page"] == "7" and "바로 연락" in e["text"] for e in res["evidence"])
    assert res["needs_human_review"] and res["history"]["recent_closed"]
    # 과거 악성 이력 -> 재접촉 대응 안내(PDF 49쪽)와 사람 확인 요구. 분기는 현재 민원 내용으로만 정해진다.
    b = make_author("김철수", "5678")
    run("칼 들고 찾아가서 가만 안 둔다", b, retr, store, llm)
    res, _ = run("체험학습 일정이 궁금합니다", b, retr, store, llm)
    assert res["route"] == "HANDLE" and res["history"]["prior_malicious"] == 1 and res["needs_human_review"]
    assert any("재접촉(1차)" in x["text"] and x["evidence"] for x in res["actions"])
    res, _ = run("또 가만 안 둔다", b, retr, store, llm)                    # 악성 이력 1건 -> 1차 대응, 접촉 제한 검토 함께 안내
    assert res["route"] == "ESCALATE" and any("재접촉(1차)" in x["text"] for x in res["actions"])
    assert any("출입·면담 제한" in x["text"] for x in res["actions"])
    res, _ = run("또 가만 안 둔다", b, retr, store, llm)                    # 악성 이력 2건 -> 2차(상급자 응대)
    assert res["history"]["prior_malicious"] == 2 and any("재접촉(2차 이상)" in x["text"] for x in res["actions"])


@needs_pdf
def test_repeat_closed_then_escalate():
    idx = build_index(PDF)
    retr, store, llm = Retriever(idx), Store(), NullLLM()
    t = "수행평가 점수 채점 기준을 알려 주세요"
    routes = [run(t, make_author("마", "0009"), retr, store, llm)[0]["route"] for _ in range(5)]
    assert routes[:2] == ["HANDLE", "HANDLE"] and routes[2] == "REJECTABLE" and routes[4] == "ESCALATE"
