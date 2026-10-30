"""예시 데이터로 민원 DB를 새로 채운다.  python samples/seed_demo_db.py [--db 경로] [--reset]

--reset이면 기존 DB 파일을 지우고 시작한다(없으면 그냥 만든다). samples/demo_db.jsonl의 민원을 실제 분류 흐름(LLM 없이,
학사일정 API 없이)으로 저장한 뒤, 접수 시각·처리 경과를 며칠 전 일로 옮겨 대시보드에 처리 현황이 보이게 한다.
"""
import argparse
import json
import os
import sys
from datetime import date, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
from sqlalchemy import update  # noqa: E402

from agent.complaint import store as st  # noqa: E402
from agent.complaint.service import ComplaintService  # noqa: E402
from agent.complaint.settings import load_settings  # noqa: E402
from agent.complaint.analytics import season_report  # noqa: E402
from agent.complaint.notices import plans_from_report  # noqa: E402
from seasonal_demo import seasonal_rows  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=None, help="DB 경로(기본: DATABASE_URL)")
    ap.add_argument("--reset", action="store_true", help="기존 DB 파일을 먼저 지운다(SQLite 파일만)")
    ap.add_argument("--no-seasonal", action="store_true", help="시즌 분석용 지난 1년 치 예시 민원은 넣지 않는다")
    ap.add_argument("--data", default=os.path.join(os.path.dirname(__file__), "demo_db.jsonl"))
    a = ap.parse_args()
    target = a.db or load_settings().database_url
    if a.reset and "://" not in target and os.path.exists(target):
        os.remove(target)
    svc = ComplaintService(db=target, llm_mode="none")
    svc.calendar = None                     # 예시 데이터는 외부 API 없이 같은 결과가 나오게 한다
    now = st._now()
    eng = svc.store.engine
    rows = [json.loads(line) for line in open(a.data, encoding="utf-8")]
    if not a.no_seasonal:
        rows = seasonal_rows() + rows              # 오래된 민원부터 넣어야 이력 판단이 시간 순서와 맞는다
    for r in rows:
        res, _ = svc.classify(r["text"], r["student"], r["class_no"])
        cid, created = res["complaint_id"], now - timedelta(days=r["days_ago"])
        if r["homeroom_sent"] and res.get("homeroom"):
            svc.store.mark_homeroom_sent(cid, "메신저로 전달", r["actor"] or None)
        if r["memo"]:
            svc.store.add_event(cid, "메모", r["memo"], None, r["actor"] or None)
        if r["status"] != "접수":
            svc.store.set_status(cid, r["status"], None, r["actor"] or None)
        # 접수 시각과 처리 경과를 과거로 옮긴다: 첫 경과는 접수 시각, 나머지는 처리 기간 안에 고르게 둔다
        done = min(r["done_after_days"] or 0.5, r["days_ago"])
        due = st.due_days(res["deadline"])
        if due and not r.get("late"):                # "late": true인 민원만 기한을 넘겨 끝낸 것으로 둔다
            done = min(done, due * 0.8)
        span = timedelta(days=done)
        with eng.begin() as c:
            evs = c.execute(st.complaint_events.select().where(st.complaint_events.c.complaint_id == cid)
                            .order_by(st.complaint_events.c.id)).all()
            last = created
            for i, e in enumerate(evs):
                last = created if i == 0 else created + span * i / (len(evs) - 1)
                c.execute(update(st.complaint_events).where(st.complaint_events.c.id == e.id).values(created_at=last))
            vals = {"created_at": created, "updated_at": last}
            if r["status"] in ("완료", "이첩"):
                vals["completed_at"] = last
            if r["homeroom_sent"] and res.get("homeroom"):
                vals["homeroom_sent_at"] = created + timedelta(hours=3)
            c.execute(update(st.complaints).where(st.complaints.c.id == cid).values(**vals))
    plans = plans_from_report(season_report(svc.store.topic_rows(), date.today()))      # 시즌 키워드의 가정통신문 전달 계획도 만들어 둔다
    added = svc.store.upsert_notice_plans(plans)
    print(f"예시 민원 저장 완료: {target} (가정통신문 계획 {added}건)")


if __name__ == "__main__":
    main()
