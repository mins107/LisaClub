"""터미널 실행: python -m agent.complaint --demo | --text "민원" [--name 홍길동 --phone-last4 1234]
웹 화면은 python -m agent.complaint.web"""
import argparse
import json
import os

from .service import ComplaintService

DEMO = "samples/demo_complaints.jsonl"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--text")
    ap.add_argument("--name", help="민원인 이름 (--phone-last4와 함께 쓰면 작성자 이력을 반영)")
    ap.add_argument("--phone-last4", help="민원인 연락처 끝 4자리")
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--pdf")
    ap.add_argument("--out", default="out")
    ap.add_argument("--llm", choices=["auto", "on", "none"], default="auto")
    ap.add_argument("--received-at")
    ap.add_argument("--call-minutes", type=float)
    ap.add_argument("--db")
    a = ap.parse_args()
    if not (a.demo or a.text):
        ap.error("--text 또는 --demo 가 필요합니다")

    try:
        svc = ComplaintService(a.pdf, a.db or (":memory:" if a.demo else None), a.llm)
    except FileNotFoundError as e:
        raise SystemExit(str(e))
    print(f"근거 단위 {len(svc.index)}개 색인 완료 / LLM: {'연결' if svc.llm.available else '미연결(규칙 기반)'}")

    if a.demo:
        cases = [json.loads(l) for l in open(DEMO, encoding="utf-8") if l.strip()]
    else:
        cases = [{"text": a.text, "name": a.name, "phone_last4": a.phone_last4,
                  "received_at": a.received_at, "call_minutes": a.call_minutes}]

    for i, c in enumerate(cases, 1):
        try:
            res, used = svc.classify(c["text"], c.get("name"), c.get("phone_last4"),
                                     c.get("received_at"), c.get("call_minutes"))
        except ValueError as e:
            raise SystemExit(str(e))
        d = os.path.join(a.out, f"case{i:02d}")
        svc.save_outputs(res, used, d)
        print(f"[{i}] {res['route_label']} | 긴급도 {res['urgency']} | 분류 {res['department']} | "
              f"근거 {', '.join(e['label'] + '=' + e['cite'] for e in res['evidence'][:3])} -> {d}/report.html")


if __name__ == "__main__":
    main()
