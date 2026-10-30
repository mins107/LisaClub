"""민원대응팀이 입력한 민원 텍스트를 분류하는 진입점. 웹(web.py)과 CLI(__main__.py)가 함께 쓴다.

매뉴얼 색인과 LLM 연결은 시작할 때 한 번만 만들고, 요청마다 classify()만 부른다.
"""
import json
import os
import threading

from .highlight import annotate, render_page
from .llm import connect
from .manual_index import build_index
from .pipeline import run
from .retriever import Retriever
from .settings import load_settings
from .store import Store, make_author


class ComplaintService:
    def __init__(self, pdf=None, db=None, llm_mode="auto"):
        s = load_settings()
        self.pdf = pdf or s.manual_pdf
        if not os.path.exists(self.pdf):
            raise FileNotFoundError(f"매뉴얼 PDF가 없습니다: {self.pdf} (data/ 폴더에 넣거나 MANUAL_PDF로 지정)")
        self.llm = connect(s, llm_mode)
        self.index = build_index(self.pdf)
        embed = self.llm.embed if (self.llm.available and s.embed_model) else None
        self.retr = Retriever(self.index, embed)
        self.store = Store(db or s.database_url, s.history_window_days, s.recontact_hours)
        self._lock = threading.Lock()      # sqlite 이력 갱신을 요청 간에 직렬화

    def classify(self, text, name=None, phone=None, received_at=None, call_minutes=None, save=True):
        """반환: (result dict, 사용된 근거 목록).
        작성자는 이름 + 연락처 끝자리로 식별한다. 둘 다 없으면 작성자 미상이라 작성자 기준 이력 판단은 하지 않는다.
        이름만 있거나 연락처가 4자리 미만이면 ValueError."""
        author = make_author(name, phone)
        with self._lock:
            return run(text, author, self.retr, self.store, self.llm,
                       received_at=received_at or None, call_minutes=call_minutes, save=save)

    def save_outputs(self, result, used, out_dir):
        """근거 형광펜 PDF, result.json, report.html을 out_dir에 쓰고 근거별 확대 이미지를 돌려준다."""
        os.makedirs(out_dir, exist_ok=True)
        snippets = annotate(self.pdf, used, out_dir)[1] if used else {}
        with open(os.path.join(out_dir, "result.json"), "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        with open(os.path.join(out_dir, "report.html"), "w", encoding="utf-8") as f:
            f.write(render_page(result, snippets, pdf_href="evidence_highlighted.pdf" if used else None))
        return snippets
