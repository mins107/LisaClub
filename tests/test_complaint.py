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


def _handoff_result(text="숙제 문의 확인해 주세요"):
    return {**_fake_result(text), "handler": "담당(담임) 교사 협조 + 민원대응팀 총괄", "deadline": "7일 이내",
            "homeroom": {"to": "3학년 5반 담임 교사"}}


def test_store_progress_lifecycle():
    from datetime import timedelta
    from agent.complaint import store as st
    s = Store()
    cid = s.save(_handoff_result(), make_student("홍길동", "305"))
    c = s.get_complaint(cid)
    assert c["status"] == "접수" and c["homeroom_needed"] and not c["homeroom_sent_at"]
    assert [e["kind"] for e in c["events"]] == ["접수"]
    stats = s.stats()
    assert stats["total"] == 1 and stats["open"] == 1 and stats["homeroom_pending"] == 1 and stats["by_status"]["접수"] == 1

    s.mark_homeroom_sent(cid, "메신저로 전달", "김교사")                  # 전달하면 접수 -> 처리 중으로 바뀐다
    c = s.get_complaint(cid)
    assert c["status"] == "처리 중" and c["homeroom_sent_at"] and s.stats()["homeroom_pending"] == 0
    assert [e["kind"] for e in c["events"]] == ["접수", "담임전달", "상태"]

    s.set_status(cid, "완료", "회신함", "김교사")
    c = s.get_complaint(cid)
    assert c["status"] == "완료" and c["completed_at"] and "처리 중 → 완료" in c["events"][-1]["note"]
    assert c["events"][-1]["actor"] == "김교사" and s.stats()["open"] == 0
    s.set_status(cid, "처리 중")                                           # 다시 열면 완료 시각이 지워진다
    assert s.get_complaint(cid)["completed_at"] is None
    s.add_event(cid, "메모", "학부모 재문의 예정")
    assert s.get_complaint(cid)["events"][-1]["kind"] == "메모"
    with pytest.raises(ValueError):
        s.set_status(cid, "없는상태")
    with pytest.raises(KeyError):
        s.set_status(9999, "완료")

    assert s.list_complaints(status="open")[1] == 1 and s.list_complaints(status="완료")[1] == 0
    assert s.list_complaints(q="홍길")[1] == 1 and s.list_complaints(q="없는말")[1] == 0
    assert s.list_complaints(homeroom="sent")[1] == 1 and s.list_complaints(homeroom="pending")[1] == 0
    later = st._now() + timedelta(days=8)                                  # 기한 7일을 넘기면 초과로 센다
    assert s.list_complaints(overdue=True)[1] == 0
    rows, total = s.list_complaints(overdue=True, now=later)
    assert total == 1 and rows[0]["overdue"] and rows[0]["due"].startswith("초과")
    assert s.stats(now=later)["overdue"] == 1


def test_store_adds_progress_columns_to_existing_db(tmp_path):
    import sqlite3
    path = str(tmp_path / "prev.sqlite")
    Store(path).save(_fake_result("이전에 저장된 민원"), make_student("홍길동", "305"))
    c = sqlite3.connect(path)                                              # 처리 경과 기능이 생기기 전의 DB를 흉내 낸다
    c.execute("DROP INDEX ix_complaints_status")
    for col in ("status", "completed_at", "updated_at", "homeroom_needed", "homeroom_sent_at"):
        c.execute(f"ALTER TABLE complaints DROP COLUMN {col}")
    c.execute("DROP TABLE complaint_events")
    c.commit()
    c.close()
    s = Store(path)                                                        # 컬럼이 덧붙고 기존 민원은 그대로
    rows, total = s.list_complaints()
    assert total == 1 and rows[0]["status"] == "접수" and rows[0]["updated_at"]
    c = s.get_complaint(1)
    assert c["status"] == "접수" and [e["kind"] for e in c["events"]] == ["접수"]      # 경과가 없던 민원은 접수 한 줄
    s.set_status(1, "처리 중")
    assert s.get_complaint(1)["status"] == "처리 중"


@needs_pdf
def test_homeroom_handoff_only_when_teacher_involved():
    idx = build_index(PDF)
    retr, store, llm = Retriever(idx), Store(), NullLLM()
    text = "수행평가 점수가 이해되지 않습니다. 채점 기준을 확인하고 싶습니다. 왜 이 점수인지 이유를 알려 주세요."
    res, _ = run(text, make_student("홍길동", "305"), retr, store, llm, save=False)
    h = res["homeroom"]
    assert "담임" in res["handler"] and h["to"] == "3학년 5반 담임 교사" and h["student"] == "홍길동(305)"
    assert h["summary"] and len(h["actions"]) == 3 and h["actions"][0]["evidence"] and h["actions"][1]["evidence"]
    assert "성적" in h["actions"][0]["text"] and "7일 이내" in h["actions"][1]["text"]      # 교무/학사 -> 성적·출결 확인
    assert "■ 민원 요약" in h["message"] and "■ 요청 사항" in h["message"] and "홍길동(305)" in h["message"]
    res, _ = run(text, None, retr, store, llm, save=False)
    assert "미입력" in res["homeroom"]["to"]
    for other in ("체험학습 일정이 궁금합니다", "칼 들고 찾아가서 가만 안 둔다", "카톡으로 개인 번호 알려주세요"):
        res, _ = run(other, None, retr, store, llm, save=False)
        assert res["homeroom"] is None                                   # 담임이 담당에 없으면 만들지 않는다


@needs_pdf
def test_web_dashboard_and_progress(tmp_path):
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
    get = lambda p: urllib.request.urlopen(base + p).read().decode()  # noqa: E731
    post = lambda p, d: urllib.request.urlopen(base + p, urllib.parse.urlencode(d).encode()).read().decode()  # noqa: E731
    try:
        main = get("/")                                                    # 메인 화면: 대시보드 + 새 민원 입력
        assert "전체 민원" in main and "민원 목록" in main and "＋ 새 민원 입력" in main and "분류하기" in main
        assert "조건에 맞는 민원이 없습니다" in main

        text = "수행평가 점수가 이해되지 않습니다. 채점 기준을 확인하고 싶습니다. 왜 이 점수인지 이유를 알려 주세요."
        page = post("/classify", {"text": text, "student": "홍길동", "class_no": "305"})     # 저장 후 상세 화면으로 이동
        assert "민원 #1" in page and "분류가 끝나 DB에 저장되었습니다" in page and "처리 경과" in page
        assert "담임 교사 전달" in page and "전달함으로 표시" in page and "3학년 5반 담임 교사" in page
        assert "evidence_highlighted.pdf" in page

        main = get("/")
        assert 'href="/complaints/1"' in main and "홍길동(305)" in main and "전달 대기" in main
        assert 'href="/complaints/1"' in get("/?status=open") and "조건에 맞는 민원이 없습니다" in get("/?status=" + urllib.parse.quote("완료"))
        assert 'href="/complaints/1"' in get("/?homeroom=pending") and 'href="/complaints/1"' in get("/?q=" + urllib.parse.quote("홍길"))

        page = post("/complaints/1/homeroom", {"note": "메신저로 전달", "actor": "김교사"})
        assert "전달 완료" in page and "메신저로 전달" in page and "접수 → 처리 중" in page
        page = post("/complaints/1/record", {"status": "완료", "note": "학부모에게 설명함", "actor": "김교사"})
        assert "처리 중 → 완료" in page and "학부모에게 설명함" in page and "처리 완료" in page
        page = post("/complaints/1/record", {"status": "", "note": "추가 문의 없음"})
        assert "추가 문의 없음" in page
        assert 'href="/complaints/1"' in get("/?status=" + urllib.parse.quote("완료")) and "전달 완료" in get("/")
        for bad in ({"status": "", "note": ""}, {"status": "없는상태", "note": "x"}):
            with pytest.raises(urllib.error.HTTPError) as e:
                post("/complaints/1/record", bad)
            assert e.value.code == 400
        for missing in ("/complaints/999", "/cases/complaint-1/../../x"):
            with pytest.raises(urllib.error.HTTPError) as e:
                get(missing)
            assert e.value.code == 404
        post("/classify", {"text": "체험학습 일정이 궁금합니다", "nosave": "1"})              # 시험 입력은 목록에 안 나온다
        assert 'href="/complaints/2"' not in get("/")
    finally:
        srv.shutdown()


@needs_pdf
def test_repeat_closed_then_escalate():
    idx = build_index(PDF)
    retr, store, llm = Retriever(idx), Store(), NullLLM()
    t = "수행평가 점수 채점 기준을 알려 주세요"
    routes = [run(t, make_student("사아", "109"), retr, store, llm)[0]["route"] for _ in range(5)]
    assert routes[:2] == ["HANDLE", "HANDLE"] and routes[2] == "REJECTABLE" and routes[4] == "ESCALATE"


class FakeCalendar:
    configured = True

    def __init__(self, rows):
        self.rows, self.asked = rows, None

    def fetch(self, start, end):
        self.asked = (start, end)
        return self.rows


def _ev(ymd, name, **kw):
    return {"AA_YMD": ymd, "EVENT_NM": name, "EVENT_CNTNT": "", "SBTR_DD_SC_NM": "해당없음",
            "ONE_GRADE_EVENT_YN": "Y", "TW_GRADE_EVENT_YN": "Y", "THREE_GRADE_EVENT_YN": "Y", **kw}


def test_schedule_inquiry_detection_and_range():
    from datetime import date
    from agent.complaint import schedule as SC
    assert SC.is_schedule_inquiry("다음 주 현장체험학습 일정이 어떻게 되는지 궁금합니다")
    assert SC.is_schedule_inquiry("기말고사는 언제인가요?")
    assert not SC.is_schedule_inquiry("수행평가 점수가 이해되지 않습니다. 이유를 알려 주세요")
    assert not SC.is_schedule_inquiry("체험학습 때문에 화가 납니다")        # 질문 표현이 없으면 아님
    today = date(2026, 10, 30)                                               # 금요일
    assert SC.date_range("다음 주 체험학습", today)[:2] == (date(2026, 11, 2), date(2026, 11, 8))
    assert SC.date_range("12월 방학식 언제", today)[:2] == (date(2026, 12, 1), date(2026, 12, 31))
    assert SC.date_range("1월 5일 개학", today)[:2] == (date(2027, 1, 5), date(2027, 1, 5))


def test_schedule_answer_statuses_and_grade_filter():
    from agent.complaint import schedule as SC
    rows = [_ev("20261104", "현장체험학습", THREE_GRADE_EVENT_YN="N"), _ev("20261105", "현장체험학습", THREE_GRADE_EVENT_YN="N"),
            _ev("20261106", "현장체험학습", ONE_GRADE_EVENT_YN="N", TW_GRADE_EVENT_YN="N", THREE_GRADE_EVENT_YN="Y"),
            _ev("20261107", "개교기념일")]
    cal = FakeCalendar(rows)
    r = SC.answer("체험학습 일정이 언제인가요?", make_student("홍길동", "105"), cal)
    assert r["status"] == "ok" and len(r["events"]) == 1                      # 1학년 행사만, 연속 날짜는 기간 하나로
    assert r["events"][0]["start"] == "20261104" and r["events"][0]["end"] == "20261105"
    assert "11월 4일" in r["reply"] and "~" in r["reply"] and "11월 6일" not in r["reply"] and "출처" in r["reply"]
    assert SC.answer("체험학습 일정이 언제인가요?", make_student("김", "305"), cal)["events"][0]["start"] == "20261106"
    assert SC.answer("수학여행 언제인가요?", None, cal)["status"] == "no_match"
    assert SC.answer("체험학습 일정이 언제인가요?", None, SC.SchoolCalendar())["status"] == "not_configured"
    assert SC.answer("점수를 알려 주세요", None, cal) is None
    assert SC._rows({"RESULT": {"CODE": "INFO-200", "MESSAGE": "없음"}}) == []
    with pytest.raises(RuntimeError):
        SC._rows({"RESULT": {"CODE": "INFO-300", "MESSAGE": "키 오류"}})


@needs_pdf
def test_pipeline_uses_schedule_reply_only_for_handle():
    idx = build_index(PDF)
    retr, store, llm = Retriever(idx), Store(), NullLLM()
    cal = FakeCalendar([_ev("20261104", "현장체험학습")])
    res, _ = run("체험학습 일정이 언제인가요?", None, retr, store, llm, save=False, calendar=cal)
    assert res["route"] == "HANDLE" and res["schedule"]["status"] == "ok"
    assert res["reply_draft"] == res["schedule"]["reply"] and "현장체험학습" in res["reply_draft"]
    res, _ = run("체험학습 일정이 언제인가요?", None, retr, store, llm, save=False, calendar=SC_NONE())
    assert res["schedule"]["status"] == "not_configured" and "현장체험학습" not in res["reply_draft"]
    res, _ = run("칼 들고 찾아가서 가만 안 둔다. 체험학습 일정이 언제인가요?", None, retr, store, llm, save=False, calendar=cal)
    assert res["route"] == "ESCALATE" and res["schedule"] is None


def SC_NONE():
    from agent.complaint.schedule import SchoolCalendar
    return SchoolCalendar()
