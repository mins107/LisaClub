"""실행: python -m agent.complaint --demo | --text "민원" [--complainant P1]"""
import argparse
import json
import os

from .highlight import annotate, render_html
from .llm import connect
from .manual_index import build_index
from .pipeline import run
from .retriever import Retriever
from .settings import load_settings
from .store import Store

DEMO = "samples/demo_complaints.jsonl"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--text")
    ap.add_argument("--complainant", default="P001")
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--pdf")
    ap.add_argument("--out", default="out")
    ap.add_argument("--llm", choices=["auto", "on", "none"], default="auto")
    ap.add_argument("--received-at")
    ap.add_argument("--call-minutes", type=float)
    ap.add_argument("--db")
    a = ap.parse_args()

    s = load_settings()
    pdf = a.pdf or s.manual_pdf
    if not os.path.exists(pdf):
        raise SystemExit(f"매뉴얼 PDF가 없습니다: {pdf} (data/ 폴더에 넣거나 --pdf로 지정)")
    llm = connect(s, a.llm)
    index = build_index(pdf)
    embed = llm.embed if (llm.available and s.embed_model) else None
    retr = Retriever(index, embed)
    store = Store(a.db or (":memory:" if a.demo else s.db_path))
    print(f"근거 단위 {len(index)}개 색인 완료 / LLM: {'연결' if llm.available else '미연결(규칙 기반)'}")

    cases = []
    if a.demo:
        cases = [json.loads(l) for l in open(DEMO, encoding="utf-8") if l.strip()]
    elif a.text:
        cases = [{"text": a.text, "complainant": a.complainant,
                  "received_at": a.received_at, "call_minutes": a.call_minutes}]
    else:
        ap.error("--text 또는 --demo 가 필요합니다")

    for i, c in enumerate(cases, 1):
        res, used = run(c["text"], c.get("complainant", a.complainant), retr, store, llm,
                        received_at=c.get("received_at"), call_minutes=c.get("call_minutes"))
        d = os.path.join(a.out, f"case{i:02d}")
        _, snips = annotate(pdf, used, d) if used else (None, {})
        if used:
            render_html(res, snips, os.path.join(d, "report.html"))
        with open(os.path.join(d, "result.json"), "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=2)
        print(f"[{i}] {res['route_label']} | 긴급도 {res['urgency']} | 분류 {res['department']} | "
              f"근거 {', '.join(e['label'] + '=' + e['cite'] for e in res['evidence'][:3])} -> {d}/report.html")


if __name__ == "__main__":
    main()
