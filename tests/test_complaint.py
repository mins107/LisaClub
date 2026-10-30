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
    assert h["student"] is None and h["same_student"] == []                   # 다른 학생의 민원은 이력에 넣지 않는다
    s.save(_fake_result("체험학습 도시락 문의"), None)          # 학생 미상도 저장된다
    assert s.find_history(None, "체험학습 도시락 문의")["same_student"] == []


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
    assert s.find_history(None, "문의")["same_student"] == []


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
    assert all(o["complaint_id"] for o in outs) and store.find_history(None, t)["same_student"] == []
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
        assert "특이 민원 의심" in page and "evidence_highlighted.pdf" in page and "지금 할 일" in page
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
    # 과거 특이 이력 -> 재접촉 대응 안내(PDF 49쪽)와 사람 확인 요구. 분기는 현재 민원 내용으로만 정해진다.
    b = make_student("김철수", "206")
    run("칼 들고 찾아가서 가만 안 둔다", b, retr, store, llm)
    res, _ = run("체험학습 일정이 궁금합니다", b, retr, store, llm)
    assert res["route"] == "HANDLE" and res["history"]["prior_malicious"] == 1 and res["needs_human_review"]
    assert any("과거 특이 이력 1건" in x["text"] and x["evidence"] for x in res["actions"])
    res, _ = run("또 가만 안 둔다", b, retr, store, llm)                    # 특이 이력 1건 -> 1차 대응, 접촉 제한 검토 함께 안내
    assert res["route"] == "ESCALATE" and any("과거 특이 이력 1건" in x["text"] for x in res["actions"])
    assert any("출입·면담 제한" in x["text"] for x in res["actions"])
    res, _ = run("또 가만 안 둔다", b, retr, store, llm)                    # 특이 이력 2건 -> 2차(상급자 응대)
    assert res["history"]["prior_malicious"] == 2 and any("과거 특이 이력 2건 이상" in x["text"] for x in res["actions"])


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
        assert "전체 민원" not in main and "민원 목록" in main and "＋ 새 민원 입력" in main and "분류하기" in main and "진행 중" in main
        assert "<dialog" in main and "최근 14일" not in main and "부서별 민원 현황" not in main          # 입력은 창으로, 그래프는 분석 탭으로
        ana = get("/analysis")
        assert "부서별 민원 현황" in ana and "시즌별 민원 키워드" in ana and "처리 상태" in ana and "최근 14일" not in ana
        assert "조건에 맞는 민원이 없습니다" in main

        text = "수행평가 점수가 이해되지 않습니다. 채점 기준을 확인하고 싶습니다. 왜 이 점수인지 이유를 알려 주세요."
        page = post("/classify", {"text": text, "student": "홍길동", "class_no": "305"})     # 저장 후 상세 화면으로 이동
        assert "민원 #1" in page and "분류가 끝나 저장되었습니다" in page and "처리 경과" in page
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
def test_benign_repeat_is_closable_but_not_malicious():
    idx = build_index(PDF)
    retr, store, llm = Retriever(idx), Store(), NullLLM()
    t = "수행평가 점수 채점 기준을 알려 주세요"
    res = [run(t, make_student("사아", "109"), retr, store, llm)[0] for _ in range(5)]
    assert [r["route"] for r in res[:3]] == ["HANDLE", "HANDLE", "REJECTABLE"]
    assert all(r["route"] != "ESCALATE" and r["malicious_repeat"]["count"] == 1 for r in res)   # 단순 반복은 특이으로 세지 않는다


@needs_pdf
def test_malicious_repeat_counts_only_open_similar_malicious_trait(monkeypatch):
    from agent.complaint import pipeline, similarity
    from agent.complaint.store import malicious_trait
    assert malicious_trait([{"severity": 3, "confident": True}]) and not malicious_trait([{"severity": 2}])
    assert not malicious_trait([{"severity": 4, "confident": False}])                       # 확신 낮은 규칙은 제외
    idx = build_index(PDF)
    retr, store, llm = Retriever(idx), Store(), NullLLM()
    stu = make_student("아자", "209")
    sims = {"v": 0.9}
    monkeypatch.setattr(similarity, "score", lambda *_a, **_k: (sims["v"], "llm"))
    ids = [run("칼 들고 찾아가서 가만 안 둔다", stu, retr, store, llm)[0]["complaint_id"] for _ in range(2)]
    benign = "수행평가 점수 채점 기준을 알려 주세요"
    r = run(benign, stu, retr, store, llm, save=False)[0]
    assert r["malicious_repeat"]["count"] == 3 and r["route"] == "ESCALATE"               # 유사한 특이 민원 특성 미해결 2건 + 이번
    store.set_status(ids[0], "완료")
    r = run(benign, stu, retr, store, llm, save=False)[0]
    assert r["malicious_repeat"]["count"] == 2 and r["route"] != "ESCALATE"               # 해결된 민원은 제외
    sims["v"] = 0.5
    r = run(benign, stu, retr, store, llm, save=False)[0]
    assert r["malicious_repeat"]["count"] == 1                                             # 임계값 미만이면 제외
    assert similarity.lexical("수행평가 점수 알려 주세요", "수행평가 점수 알려 주세요") == 1.0


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
    assert "현장체험학습" in res["reply_draft"] and "· " in res["reply_draft"] and "- 20" not in res["reply_draft"]   # 일정 답변도 기호 없이
    assert res["reply_staff_note"] == ""
    res, _ = run("체험학습 일정이 언제인가요?", None, retr, store, llm, save=False, calendar=SC_NONE())
    assert res["schedule"]["status"] == "not_configured" and "현장체험학습" not in res["reply_draft"]
    res, _ = run("칼 들고 찾아가서 가만 안 둔다. 체험학습 일정이 언제인가요?", None, retr, store, llm, save=False, calendar=cal)
    assert res["route"] == "ESCALATE" and res["schedule"] is None


def SC_NONE():
    from agent.complaint.schedule import SchoolCalendar
    return SchoolCalendar()


def test_team_tasks_by_complaint_content():
    from agent.complaint import tasks as TK
    assert TK.find_subject("국어 수행평가 점수가 이상합니다") == "국어"
    assert TK.find_subject("수학여행 일정이 궁금합니다") is None            # 수학여행은 수학 과목이 아님
    f, l = TK.team_tasks("국어 수행평가 점수가 이상합니다. 이유를 알려 주세요", "HANDLE", "7일 이내", None, ["E1"], ["E2"])
    assert "국어 교과 교사에게 문의" in f[0]["text"] and f[0]["evidence"] == ["E1"] and f[0]["phase"] == "담당자 문의·확인"
    assert "7일 이내" in l[0]["text"] and l[0]["evidence"] == ["E2"]
    f, _ = TK.team_tasks("수행평가 점수가 이상합니다", "HANDLE", "즉시", None)
    assert "과목" in f[0]["text"]                                             # 과목이 없으면 과목부터 확인
    f, _ = TK.team_tasks("급식이 차갑고 화장실도 고장 났어요", "HANDLE", "즉시", None)
    assert {"영양(교)사", "행정실"} <= {k for k in ("영양(교)사", "행정실") if any(k in a["text"] for a in f)}
    f, _ = TK.team_tasks("우리 애가 따돌림을 당해요", "HANDLE", "7일 이내", None)
    assert "학생생활안전부" in f[0]["text"]
    f, _ = TK.team_tasks("뭔가 불편합니다", "HANDLE", "즉시", None)
    assert "담당자" in f[0]["text"]                                           # 아무것도 못 읽어도 담당자 지정은 안내
    assert TK.team_tasks("x", "ESCALATE", "14일", None) == ([], [])


@needs_pdf
def test_pipeline_puts_team_tasks_into_actions():
    idx = build_index(PDF)
    retr, store, llm = Retriever(idx), Store(), NullLLM()
    res, _ = run("국어 수행평가 점수가 이해되지 않습니다. 채점 기준을 확인하고 싶습니다. 이유를 알려 주세요.",
                 make_student("홍길동", "305"), retr, store, llm, save=False)
    texts = [a["text"] for a in res["actions"]]
    assert any("국어 교과 교사에게 문의" in t for t in texts) and any("담임 교사 전달" in t for t in texts)
    assert res["actions"][-1]["phase"] == "민원인 응대" and "7일 이내" in res["actions"][-1]["text"]
    res, _ = run("카톡으로 개인 번호 알려주세요", None, retr, store, llm, save=False)
    assert res["route"] == "REJECTABLE" and "공식 접수 창구" in res["actions"][-1]["text"]


def test_department_classification_validation_set():
    """samples/dept_validation.jsonl: 부서 업무 설명을 보고 사람이 정한 정답과 키워드 분류를 비교한다."""
    import json
    rows = [json.loads(l) for l in open("samples/dept_validation.jsonl", encoding="utf-8")]
    wrong = [(r["text"], r["expected"], R.classify_department(r["text"])["name"]) for r in rows
             if R.classify_department(r["text"])["name"] != r["expected"]]
    assert len(rows) >= 90 and not wrong, wrong
    got = R.classify_department("국어 수행평가 점수 이의 신청")
    assert got["candidates"][0]["name"] == "교수학습지원부" and got["reason"].startswith("민원의")


@needs_pdf
def test_escalate_keeps_content_department_and_no_management_department():
    idx = build_index(PDF)
    res, _ = run("칼 들고 찾아가서 가만 안 둔다. 성적 올려 놔라", None, Retriever(idx), Store(), NullLLM(), save=False)
    assert res["route"] == "ESCALATE" and res["department"] == "교수학습지원부"
    assert "관리(교감/교장)" not in R.DEPT_NAMES and len(R.DEPT_NAMES) == 17


def test_department_stats_insights_and_dashboard(tmp_path):
    from datetime import timedelta
    from agent.complaint import insights as IN
    from agent.complaint import store as st
    from agent.complaint.dashboard import render_analysis
    s = Store()
    res = _fake_result("수행평가 점수 문의")
    res.update(department="교수학습지원부", deadline="7일 이내", department_keywords=["수행평가"])
    ids = [s.save(res, None, None, None, False) for _ in range(4)]
    s.set_status(ids[0], "완료", None, "김교사")
    with s.engine.begin() as c:
        c.execute(st.complaints.update().where(st.complaints.c.id.in_(ids[1:3])).values(created_at=st._now() - timedelta(days=9)))
    stats = s.stats()
    d = stats["departments"]["교수학습지원부"]
    assert d["total"] == 4 and d["done"] == 1 and d["open"] == 3 and d["overdue"] == 2 and d["top_topics"] == ["수행평가"]
    ins = IN.department_insights(stats["departments"], stats["total"])
    assert ins and ins[0]["dept"] == "교수학습지원부" and {"overdue", "backlog"} <= set(ins[0]["flags"])
    page = render_analysis(stats)
    assert "부서별 민원 현황" in page and "개선을 검토할 부서" in page and "교수학습지원부" in page and "기한 초과 2건" in page
    assert IN.department_insights(Store().stats()["departments"], 0) == []


def test_legacy_department_names_are_remapped(tmp_path):
    from agent.complaint import store as st
    db = str(tmp_path / "d.sqlite")
    s = Store(db)
    res = _fake_result("친구 문제")
    res["department"] = "생활지도/상담"
    cid = s.save(res, None, None, None, False)
    assert Store(db).get_complaint(cid)["department"] == "학생생활안전부"


def test_grade_department_follows_student_grade():
    text = "수학 선생님이 수업 시간에 아이에게 소리를 질렀다고 합니다"
    assert R.classify_department(text, "305")["name"] == "3학년부"
    assert R.classify_department(text, "112")["name"] == "1학년부"
    assert R.classify_department(text)["name"] == R.GRADE_UNKNOWN
    assert R.classify_department("국어 수행평가 점수 문의", "305")["name"] == "교수학습지원부"     # 내용 부서가 우선
    assert R.grade_department("205") == "2학년부" and R.grade_department(None) is None
    assert "학년부" in R.DEPT_DESC["3학년부"]


@needs_pdf
def test_grade_department_in_pipeline_and_homeroom_message():
    idx = build_index(PDF)
    res, _ = run("담임 선생님이 수업 시간에 학생에게 소리를 질렀습니다. 사실관계를 확인해 주세요.", make_student("홍길동", "205"),
                 Retriever(idx), Store(), NullLLM(), save=False)
    assert res["department"] == "2학년부" and res["grade_department"] == "2학년부" and "2학년부: " in res["department_reason"]
    texts = [a["text"] for a in res["actions"]]
    assert any(t.startswith("2학년부에 협조 요청") for t in texts)


def _season_rows():
    from datetime import date
    rows = []
    for y in (2025, 2026):                    # 3월에는 학사일정·시간표, 6월에는 기말고사·성적이 늘어난다
        rows += [(date(y, 3, 2 + i), ["학사일정", "시간표"]) for i in range(6)]
        rows += [(date(y, 6, 1 + i), ["기말고사", "성적"]) for i in range(5)]
        for m in (4, 5, 9, 10):
            rows += [(date(y, m, 3 + i), ["급식"]) for i in range(2)]
    return rows


def test_season_report_finds_seasonal_and_correlated_keywords():
    from datetime import date
    from agent.complaint import analytics as AN
    assert not AN.season_report([(date(2026, 3, 1), ["학사일정"])])["enough"]
    rep = AN.season_report(_season_rows())
    by = {k["keyword"]: k for k in rep["keywords"]}
    assert rep["enough"] and by["학사일정"]["seasonal"] and by["학사일정"]["peak_month"] == 3
    assert by["기말고사"]["peak_month"] == 6 and by["기말고사"]["counts"][5] == 10
    assert "시간표" in [r["keyword"] for r in by["학사일정"]["related"]]           # 같은 달에 같이 늘어남
    assert "성적" not in [r["keyword"] for r in by["학사일정"]["related"]]
    assert not by["급식"]["seasonal"]                                            # 여러 달에 고르게 나옴
    now = _season_rows() + [(date(2026, 10, 5 + i), ["상담"]) for i in range(8)]                # 끝나지 않은 이번 달은 분석에서 뺀다
    assert "상담" in {k["keyword"] for k in AN.season_report(now)["keywords"]}
    assert "상담" not in {k["keyword"] for k in AN.season_report(now, date(2026, 10, 31))["keywords"]}


def test_notice_window_state_and_plans():
    from datetime import date
    from agent.complaint import analytics as AN
    from agent.complaint import notices as NT
    plan = {"id": 1, "keyword": "학사일정", "related": ["시간표"], "peak_month": 3, "lead_days": 14, "active": True, "title": "t"}
    assert NT.window(3, 2026) == (date(2026, 2, 15), date(2026, 3, 31))
    assert NT.plan_state(plan, set(), date(2026, 2, 14))["state"] == "waiting"
    assert NT.plan_state(plan, set(), date(2026, 2, 15))["state"] == "due"
    st = NT.plan_state(plan, set(), date(2026, 3, 31))
    assert st["state"] == "due" and st["season_year"] == 2026
    assert NT.plan_state(plan, {2026}, date(2026, 3, 10))["state"] == "sent"
    st = NT.plan_state(plan, {2026}, date(2026, 4, 1))                              # 시기가 지나면 내년을 기다린다
    assert st["state"] == "waiting" and st["season_year"] == 2027 and st["start"] == date(2027, 2, 15)
    assert NT.plan_state({**plan, "peak_month": 1}, set(), date(2026, 12, 25))["season_year"] == 2027   # 연말에 1월 시즌 준비
    plans = NT.plans_from_report(AN.season_report(_season_rows()))
    assert {p["keyword"] for p in plans} >= {"학사일정", "기말고사"} and all("가정통신문" in p["title"] and p["body"] for p in plans)
    assert NT.matching_plans([plan], ["시간표"], date(2026, 3, 5), {}) [0]["state"] == "due"
    assert NT.matching_plans([plan], ["시간표"], date(2026, 8, 5), {}) == []


def test_store_notice_plans_and_sends():
    from agent.complaint import analytics as AN
    from agent.complaint import notices as NT
    s = Store()
    plans = NT.plans_from_report(AN.season_report(_season_rows()))
    assert s.upsert_notice_plans(plans) == len(plans) and s.upsert_notice_plans(plans) == 0     # 두 번째는 갱신만
    lst = s.list_notice_plans()
    p = next(x for x in lst if x["keyword"] == "학사일정")
    assert p["peak_month"] == 3 and "시간표" in p["related"] and p["sends"] == []
    assert s.mark_notice_sent(p["id"], 2026, "김교사", "알림장") is True
    assert s.mark_notice_sent(p["id"], 2026) is False                                           # 같은 해에는 한 번만
    assert [x["season_year"] for x in next(x for x in s.list_notice_plans() if x["id"] == p["id"])["sends"]] == [2026]
    with pytest.raises(KeyError):
        s.mark_notice_sent(9999, 2026)


@needs_pdf
def test_pipeline_mentions_notice_in_season_and_web_flow(tmp_path):
    from datetime import date
    from agent.complaint import analytics as AN
    from agent.complaint import notices as NT
    from agent.complaint.service import ComplaintService
    svc = ComplaintService(PDF, ":memory:", "none")
    svc.calendar = None
    svc.store.upsert_notice_plans(NT.plans_from_report(AN.season_report(_season_rows())))
    today = date.today()
    plan = next(p for p in svc.store.list_notice_plans() if p["keyword"] == "기말고사")
    st = NT.plan_state(plan, set(), today)
    res, _ = svc.classify("기말고사 성적 처리 일정이 궁금합니다", "김하늘", "305", save=False)
    in_season = st["state"] in ("due", "sent")
    assert bool(res["notices"]) == in_season
    assert any("가정통신문" in a["text"] for a in res["actions"]) == in_season
    from agent.complaint import web
    from http.server import ThreadingHTTPServer
    import threading, urllib.request, urllib.parse, json as _json
    web.Handler.service, web.Handler.out_root = svc, str(tmp_path)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        page = urllib.request.urlopen(base + "/analysis").read().decode("utf-8")
        assert "시즌별 민원 키워드와 가정통신문" in page and "3개월 이상" in page          # 데이터가 없으면 안내만
        notices = _json.loads(urllib.request.urlopen(base + "/api/notices").read())
        assert any(n["keyword"] == "기말고사" and n["state"] in ("due", "sent", "waiting") for n in notices)
        req = urllib.request.Request(base + f"/notices/{plan['id']}/send",
                                     urllib.parse.urlencode({"season_year": st["season_year"], "actor": "김교사"}).encode())
        urllib.request.urlopen(req)
        again = _json.loads(urllib.request.urlopen(base + "/api/notices").read())
        assert next(n for n in again if n["id"] == plan["id"])["sends"][0]["actor"] == "김교사"
    finally:
        srv.shutdown()


def _esc_result(**kw):
    base = {"route": "ESCALATE", "route_label": "특이 민원 의심", "department": "교수학습지원부", "handler": "관리자", "repeat_count": 1,
            "student": "홍길동(305)", "text_masked": "수행평가 점수를 올려 놔라. 안 그러면 가만 안 둔다.", "complaint_id": 7, "actions": [],
            "malicious": [{"kind": "malicious", "key": "threat", "label": "협박", "severity": 4, "matched": ["가만 안 둔다"], "confident": True}],
            "history": {"same_student": [], "prior_malicious": 0}}
    base.update(kw)
    return base


def test_transfer_checklist_selects_matching_criteria():
    from agent.complaint import transfer as TR
    cl = {c["no"]: c for c in TR.checklist(_esc_result())}
    assert len(cl) == 5 and cl[1]["text"].startswith("합리적인 답변을 하고 3회 이상")
    assert cl[3]["state"] == "해당" and "협박" in cl[3]["reasons"][0]                # 처벌 가능한 중대 사안
    assert cl[1]["state"] == "해당 가능" and "위력" in cl[1]["reasons"][0]            # 협박 = 위력 행사 가능성
    assert cl[2]["state"] == cl[4]["state"] == "확인 필요"                            # 학교 기록이 필요한 항목은 단정하지 않는다
    prior = [{"id": 3, "created_at": "2026-08-01 10:00", "snippet": "점수 이의", "closed": True}]
    rep = _esc_result(repeat_count=3, malicious=[], history={"same_student": prior, "prior_malicious": 1})
    cl = {c["no"]: c for c in TR.checklist(rep)}
    assert cl[1]["state"] == "해당" and "#3" in cl[1]["reasons"][0] and cl[3]["state"] == "해당 없음" and cl[5]["state"] == "해당 가능"
    t = TR.build_transfer(rep)
    assert t["chosen"] == [1, 5] and "같은 민원을 3회 이상 반복" in t["reason_lines"][1] and "교육활동에 심각한 지장" in t["reason_lines"][2] and any("2026-08-01" in l for l in t["history_lines"])
    assert any("법적 조치" in x for x in TR.build_transfer(_esc_result())["request_lines"])         # 기준 3번 -> 법적 조치 협의 요청
    sent = TR.checklist(_esc_result(malicious=[{"key": "threat", "label": "협박", "severity": 4, "matched": "가만 안"}]))[2]["reasons"][0]
    assert "'안 그러면 가만 안 둔다.'" in sent                                       # 감지된 말(가만 안)이 아니라 그 문장 전체
    assert TR._sentences({"text_masked": "첫째 문장입니다. 이런 교사는 자격 없어요, 가만 안 둔다! 끝."},
                         {"matched": "자격 없; 가만 안"}) == ["이런 교사는 자격 없어요, 가만 안 둔다!"]   # 같은 문장은 한 번만
    none = TR.build_transfer(_esc_result(malicious=[]))
    assert none["chosen"] == [] and "직접 적어" in none["reason_lines"][0]


def _hwpx_text(path):
    """hwpx(zip) 안 section0.xml의 모든 글(hp:t)을 줄바꿈으로 이어 붙인다."""
    import zipfile
    from lxml import etree
    with zipfile.ZipFile(path) as z:
        root = etree.fromstring(z.read("Contents/section0.xml"))
    return "\n".join(t.text or "" for t in root.iter("{http://www.hancom.co.kr/hwpml/2011/paragraph}t"))


def test_transfer_hwpx_fills_the_template_file(tmp_path):
    import zipfile
    from agent.complaint import transfer as TR
    assert os.path.isfile(TR.TEMPLATE_PATH)
    prior = [{"id": 3, "created_at": "2026-08-01 10:00", "snippet": "점수 이의", "snippet_raw": "점수 이의", "closed": True}]
    res = _esc_result(repeat_count=3, history={"same_student": prior, "prior_malicious": 0}, text_masked="점수를 올려라 씨X 가만 안 둔다")
    t = TR.build_transfer(res, school_name="가락고등학교", prior_texts={3: "점수 이의 신청합니다 원문 그대로"})
    assert t["category"] == "교무/학사" and t["target"] == "교수학습지원부" and len(t["history_rows"]) == 2
    f = TR.to_hwpx(t, str(tmp_path / "r.hwpx"))
    text = _hwpx_text(f)
    for want in ("가락고등학교", "■ 교무/학사", "□ 기타", "홍길동", "3학년 5반(305)", "2026. 8. 1.",
                 "점수 이의 신청합니다 원문 그대로", "점수를 올려라 씨X 가만 안 둔다",       # 이번 민원·이전 민원 모두 원문 그대로
                 "이첩 사유", "처벌이 가능할 정도의 중대한 위법 행위"):
        assert want in text, want
    assert "(작성예시)" not in text and "쉬는시간 중 담임교사가" not in text and "2025. 9. 30." not in text   # 서식의 예시 문구는 지운다
    assert "교육(지원)청별 여건에 따라" in text or "서식" in text                       # 서식의 나머지 문구는 그대로
    with zipfile.ZipFile(f) as z, zipfile.ZipFile(TR.TEMPLATE_PATH) as orig:             # 나머지 파일은 원본 그대로, mimetype이 맨 앞·무압축
        assert z.namelist() == orig.namelist() and z.infolist()[0].filename == "mimetype" and z.infolist()[0].compress_type == 0
        for n in orig.namelist():
            if n != "Contents/section0.xml":
                assert z.read(n) == orig.read(n), n
    many = TR.build_transfer(_esc_result(), school_name="x")
    many["history_rows"] = [(f"2026. 1. {i}.", [f"· 민원 {i}", "   → 처리"]) for i in range(1, 11)]
    g = TR.to_hwpx(many, str(tmp_path / "m.hwpx"))                                       # 7줄을 넘으면 줄을 늘린다
    text = _hwpx_text(g)
    assert "· 민원 10" in text and "· 민원 1\n" in text
    from lxml import etree
    with zipfile.ZipFile(g) as z:
        root = etree.fromstring(z.read("Contents/section0.xml"))
    hp = "{http://www.hancom.co.kr/hwpml/2011/paragraph}"
    tbl = next(root.iter(hp + "tbl"))
    rows = sorted({int(tc.find(hp + "cellAddr").get("rowAddr")) for tc in tbl.iter(hp + "tc")})
    assert tbl.get("rowCnt") == "16" and rows == list(range(16))                         # 13줄 + 3줄, 행 번호가 빠짐없이 이어진다
    label = [tc for tc in tbl.iter(hp + "tc") if tc.find(hp + "cellAddr").get("rowAddr") == "4" and tc.find(hp + "cellAddr").get("colAddr") == "0"][0]
    assert label.find(hp + "cellSpan").get("rowSpan") == "10"


def test_transfer_hwpx_missing_template(tmp_path):
    from agent.complaint import transfer as TR
    with pytest.raises(FileNotFoundError):
        TR.to_hwpx(TR.build_transfer(_esc_result()), str(tmp_path / "x.hwpx"), template=str(tmp_path / "없음.hwpx"))


@needs_pdf
def test_web_transfer_report_download(tmp_path):
    from agent.complaint import web
    from agent.complaint.service import ComplaintService
    from http.server import ThreadingHTTPServer
    import threading, urllib.request
    svc = ComplaintService(PDF, ":memory:", "none")
    svc.calendar = None
    res, used = svc.classify("칼 들고 찾아가서 수행평가 점수 올려 놔라, 가만 안 둔다", "홍길동", "305")
    ok, _ = svc.classify("국어 수행평가 점수가 궁금합니다", "김하늘", "101")
    web.Handler.service, web.Handler.out_root = svc, str(tmp_path)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        page = urllib.request.urlopen(base + f"/complaints/{res['complaint_id']}").read().decode("utf-8")
        from agent.complaint.rules import DEPT_DESC
        assert DEPT_DESC.get(res["department"], "(없음)") not in page and "→ " + res["department"] + ": " not in page                           # 분류(담당 부서) 아래 회색 설명은 보이지 않는다
        assert "상위기관 이첩" in page and "처벌이 가능할 정도의 중대한 위법 행위" in page and "■ 해당" not in page and "1번" not in page
        assert f"/complaints/{res['complaint_id']}/transfer.hwpx" in page and "이첩 보고서 내려받기" in page
        r = urllib.request.urlopen(base + f"/complaints/{res['complaint_id']}/transfer.hwpx")
        data = r.read()
        assert data[:2] == b"PK" and "hwpx" in r.headers["Content-Type"] and ".hwpx" in r.headers["Content-Disposition"]
        other = urllib.request.urlopen(base + f"/complaints/{ok['complaint_id']}").read().decode("utf-8")
        assert "transfer.hwpx" not in other                                       # 이첩 대상이 아닌 민원에는 없다
    finally:
        srv.shutdown()


class _FakeLLM:
    available = True

    def __init__(self, out):
        self.out = out

    def chat(self, system, user, json_mode=False):
        if isinstance(self.out, Exception):
            raise self.out
        return self.out


def test_soften_rules_llm_and_fallbacks():
    from agent.complaint import soften as SF
    rough = "담임이 무능한 교사라 가만 안 둔다. 수행평가 점수를 확인해 주세요."
    soft, n = SF.mask_rough(rough)
    assert n >= 1 and SF.MASK in soft and "수행평가 점수를 확인해 주세요" in soft and "가만 안" not in soft and "둔다" not in soft   # 요구 사항은 남기고 거친 표현만 가림(문장 끝까지)
    assert SF.soften(NullLLM(), rough)[1] == "rules"
    assert SF.soften(NullLLM(), "수행평가 점수를 확인해 주세요") == ("수행평가 점수를 확인해 주세요", "none")
    good = "담임 교사에 대한 불만이 있으며 수행평가 점수 확인을 요청합니다. (거친 표현이 있었음)"
    assert SF.soften(_FakeLLM(good), rough) == (good, "llm")
    assert SF.soften(_FakeLLM(""), rough)[1] == "rules"                               # 빈 응답 -> 규칙으로
    assert SF.soften(_FakeLLM(RuntimeError("down")), rough)[1] == "rules"            # 호출 실패 -> 규칙으로
    assert SF.soften(_FakeLLM("가"), rough)[1] == "rules"                             # 길이가 너무 달라도 버린다
    again = SF.soften(_FakeLLM("가만 안 둔다 라고 했고 점수 확인을 요청합니다 입니다 입니다"), rough)
    assert again[1] == "llm" and "가만 안" not in again[0]                       # 순화문에 거친 표현이 남으면 마저 가린다


@needs_pdf
def test_screens_show_soft_text_first_and_original_on_demand(tmp_path):
    from agent.complaint import web
    from agent.complaint.service import ComplaintService
    from http.server import ThreadingHTTPServer
    import threading, urllib.request
    svc = ComplaintService(PDF, ":memory:", "none")
    svc.calendar = None
    rough = "담임 때문에 우리 애가 힘들대요. 이런 무능한 교사는 자격 없어요, 가만 안 둔다."
    res, _ = svc.classify(rough, "홍길동", "305")
    assert res["text_masked"] == rough and res["text_soft_method"] == "rules" and "가만 안" not in res["text_soft"]
    web.Handler.service, web.Handler.out_root = svc, str(tmp_path)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        page = urllib.request.urlopen(base + f"/complaints/{res['complaint_id']}").read().decode("utf-8")
        head, _, tail = page.partition("원문 보기")
        assert "[부적절한 표현]" in head and "가만 안" not in head           # 원문 보기 위(기본 화면)에는 순화문만
        assert "가만 안" in tail and "<details" in page                      # 원문은 [원문 보기] 안에 있다
        home = urllib.request.urlopen(base + "/").read().decode("utf-8")
        lst = home.split("<h2>민원 목록</h2>")[1].split("<dialog")[0]                                   # (위쪽 입력 예시 문구는 제외)
        assert "가만 안" not in lst and "[부적절한 표현]" in lst            # 목록 내용 요약도 순화문
    finally:
        srv.shutdown()
    s = Store()                                                                      # 순화문이 없는 이전 민원
    legacy = _fake_result("x", route="HANDLE")
    legacy["text_masked"] = rough
    cid = s.save(legacy, None, None, None, False)
    assert "가만 안" not in s.get_complaint(cid)["result"]["text_soft"]
    assert "가만 안" not in s.list_complaints()[0][0]["text"]


@needs_pdf
def test_detail_page_shows_only_the_essentials_first(tmp_path):
    from agent.complaint import web
    from agent.complaint.service import ComplaintService
    from http.server import ThreadingHTTPServer
    import threading, urllib.request
    svc = ComplaintService(PDF, ":memory:", "none")
    svc.calendar = None
    for text in ("수행평가 점수 이의 신청을 하고 싶습니다. 이유를 알려 주세요.", "수행평가 점수 이의 신청을 다시 하고 싶습니다. 이유를 알려 주세요.",
                 "수행평가 점수 이의 신청을 또 하고 싶습니다. 이유를 알려 주세요."):
        res, _ = svc.classify(text, "홍길동", "305")
    web.Handler.service, web.Handler.out_root = svc, str(tmp_path)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        page = urllib.request.urlopen(base + f"/complaints/{res['complaint_id']}").read().decode("utf-8")
        main = page.split('<div class="cd-main">')[1]
        content, _, rest = main.partition('<details class="cd-more')
        more, _, side = rest.partition('<aside class="cd-side">')
        for want in ("민원 내용", "답변 초안", "원문 보기"):
            assert want in content, want                                           # 왼쪽: 민원 내용과 답변 초안
        for want in ("<dt>긴급도", "<dt>담당 부서", "<dt>처리 담당", "<dt>처리 기한", "과거 이력", "반복 패턴", "처리 상태"):
            assert want in side, want                                              # 오른쪽: 처리에 필요한 정보
        for hidden in ("<h3>지금 할 일", "<h3>분류 사유", ">매뉴얼 근거 <small>", "<h3>처리 경과"):
            assert hidden in more and hidden not in content + side, hidden          # 나머지는 접힌 '참고 자료' 안에만
        assert "<details class=\"cd-more o9\">" in page                           # 기본으로 접혀 있다
        home = urllib.request.urlopen(base + "/").read().decode("utf-8")
        form = home.split("접수된 민원 내용")[1].split("분류하기")[0]
        assert form.index("<textarea") < form.index("추가 정보") < form.index('name="student"') < form.index('name="call_minutes"')
        assert "<details class=\"drawer\" open>" not in form                      # 추가 정보는 기본으로 접혀 있다
    finally:
        srv.shutdown()



def test_reply_draft_is_plain_and_staff_note_is_separate():
    import json as _json
    from agent.complaint.pipeline import _draft, _plain

    class U:
        def __init__(self, label):
            self.label, self.ev = label, type("E", (), {"text": "매뉴얼 문장"})()

    used = [U("E1"), U("E2")]
    assert _plain("## 안내\n**안녕하세요** ++중요++ 입니다 [E1]\n- 첫째\n> 인용\n근거: E1, E2") == "안내\n안녕하세요 중요 입니다\n· 첫째\n인용"
    ok = _FakeLLM(_json.dumps({"reply": "**안녕하세요.** 확인 후 안내드리겠습니다.\n근거: E1", "staff_note": "보내기 전 **채점표**를 확인하세요.",
                               "evidence": ["E1"]}, ensure_ascii=False))
    reply, note, ev = _draft(ok, "민원", "HANDLE", used, "")
    assert reply == "안녕하세요. 확인 후 안내드리겠습니다." and note == "보내기 전 채점표를 확인하세요." and ev == ["E1"]
    bad = _FakeLLM(_json.dumps({"reply": "안내", "staff_note": "", "evidence": ["E9"]}))
    reply, note, ev = _draft(bad, "민원", "HANDLE", used, "")                       # 없는 근거 번호 -> 기본 문구
    assert reply.startswith("안녕하세요") and "근거" not in reply and note == "" and ev == ["E1", "E2"]
    reply, note, _ = _draft(NullLLM(), "민원", "REJECTABLE", used, "")
    assert "근거:" not in reply and note == ""


@needs_pdf
def test_evidence_tooltips_and_simple_manual_section():
    import html as _html
    from agent.complaint.highlight import render_body
    idx = build_index(PDF)
    res, _ = run("칼 들고 찾아가서 가만 안 둔다", None, Retriever(idx), Store(), NullLLM(), save=False)
    res["reply_staff_note"] = "경고 문구라 관리자 확인 후 발송하세요."
    page = render_body(res, pdf_href="x.pdf")
    first = res["evidence"][0]
    assert f'data-tip="{_html.escape(first["text"], quote=True)}"' in page                  # 근거 번호 말풍선 = 매뉴얼 문장
    assert '<a class="tag"' not in page and "data-tab" not in page                         # 누르는 링크·탭 버튼은 없다
    assert "연결된 판정" not in page and first["cite"] not in page                          # 판정·쪽 번호 표시는 없앴다
    assert "민원 유형 근거" in page and "처리 절차 근거" in page and "매뉴얼 PDF 열기" in page
    assert page.index("담당자 참고") < page.index("답변 초안")                              # 담당자 참고는 초안 위 별도 카드
    res["reply_staff_note"] = ""
    res["review"] = {**res["review"], "findings": []}
    assert "담당자 참고" not in render_body(res)


def test_review_loop_checks_history_and_boosts_weak_evidence():
    from agent.complaint import review as RV
    from agent.complaint.pipeline import _Collector

    class Ev:
        def __init__(self, i, text):
            self.id, self.text = i, text

    evs = [Ev(1, "무관한 문장 하나"), Ev(2, "처리 기한 복합민원 7일 이내 단순민원 즉시")]

    class Retr:
        def search(self, q, k=3):
            return [(e, 1.0) for e in evs if any(w in e.text for w in q.split())][:k]

    col = _Collector(Retr())
    col.items.append(type("U", (), {"label": "E1", "ev": evs[0], "role": "procedure", "reason": "처리 기한", "score": 1.0})())
    col.log.append({"anchor": "처리 기한 복합민원 7일 이내 단순민원 즉시", "role": "procedure", "reason": "처리 기한", "labels": ["E1"]})
    hits = [{"evidence": ["E1"]}]
    out = RV.run(NullLLM(), Retr(), col, hits, text="x", route="HANDLE", history={"prior_malicious": 1, "recent_closed": None},
                 mal_repeat=1, near_items=[], student=None, sim_threshold=0.8)
    assert out["added_evidence"] == ["E2"] and "E2" in hits[0]["evidence"] and not out["llm_used"]       # LLM 없이 규칙 재검색으로 보강
    assert out["rounds"][0]["weak"] == 1 and len(out["rounds"]) <= RV.MAX_ROUNDS
    assert [f["kind"] for f in out["findings"]] == ["history"] and "과거 특이" in out["findings"][0]["text"]   # 근거는 보강돼 evidence 지적 없음
    f = RV.history_findings(route="HANDLE", history={}, mal_repeat=2, near_items=[{}], student=None, sim_threshold=0.8)
    assert any("임계값" in t for t in f) and any("2회" in t for t in f)
    assert RV.history_findings(route="ESCALATE", history={}, mal_repeat=1, near_items=[], student=None, sim_threshold=0.8)    # 학생 미상 특이 민원 의심


@needs_pdf
def test_pipeline_attaches_review_and_flags_for_human():
    idx = build_index(PDF)
    res, _ = run("수행평가 점수 채점 기준을 알려 주세요", make_student("검토", "101"), Retriever(idx), Store(), NullLLM(), save=False)
    assert res["review"]["max_rounds"] == 3 and res["review"]["rounds"] and not res["review"]["findings"]
    res, _ = run("칼 들고 찾아가서 가만 안 둔다", None, Retriever(idx), Store(), NullLLM(), save=False)
    assert any(f["kind"] == "history" for f in res["review"]["findings"]) and res["needs_human_review"]
    from agent.complaint.highlight import render_body
    assert "학생 정보가 없어" in render_body(res) and "검토 기록" in render_body(res)
