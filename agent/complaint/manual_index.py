"""매뉴얼 PDF를 근거 단위(Evidence)로 쪼갠다.

각 근거 단위는 쪽 번호와 줄별 좌표(rect)를 가지므로, 나중에 PDF 위에 형광펜을
정확히 칠할 수 있다. 근거 인용은 LLM이 아니라 이 색인에서만 나온다.
"""
import re
from dataclasses import dataclass, field

import pymupdf

BULLETS = tuple("◦▹☞※▪▸◈♣◇•①②③④⑤❶❷❸❹❺")
HEAD = re.compile(r"^(\d{1,2}\.|[가-힣]\.|[가-힣]\)|\d\)|\(\d\)|제\d+조|[-–] )")
FOOT_Y = 700      # 쪽 하단(쪽 번호, 러닝헤드) 시작 y
SIDE_X = 515      # 오른쪽 장 표시 탭 x


@dataclass
class Evidence:
    id: str
    page: int                       # PDF 쪽 번호(1부터)
    printed_page: str               # 매뉴얼에 인쇄된 쪽 번호
    text: str
    rects: list = field(default_factory=list)   # [(x0,y0,x1,y1), ...] 줄별

    def cite(self) -> str:
        return f"매뉴얼 {self.printed_page}쪽(PDF {self.page}쪽)"


def _is_start(line: str) -> bool:
    return line.startswith(BULLETS) or bool(HEAD.match(line))


def build_index(pdf_path: str, max_chars: int = 320) -> list:
    doc = pymupdf.open(pdf_path)
    units = []
    for pno, page in enumerate(doc, start=1):
        printed = str(pno)
        lines_by_block = []
        for b in page.get_text("dict")["blocks"]:
            if b["type"] != 0:
                continue
            ls = []
            for ln in b["lines"]:
                t = "".join(s["text"] for s in ln["spans"]).strip()
                x0, y0, x1, y1 = ln["bbox"]
                if not t:
                    continue
                if y0 >= FOOT_Y:
                    if t.isdigit():
                        printed = t
                    continue
                if x0 >= SIDE_X:
                    continue
                ls.append((t, (x0, y0, x1, y1)))
            if ls:
                lines_by_block.append(ls)
        n = 0
        for ls in lines_by_block:
            cur_t, cur_r = [], []

            def flush():
                nonlocal n, cur_t, cur_r
                text = " ".join(cur_t).strip()
                if len(text) >= 8:
                    n += 1
                    units.append(Evidence(f"p{pno:02d}-{n:02d}", pno, printed, text, list(cur_r)))
                cur_t, cur_r = [], []

            for t, r in ls:
                if cur_t and (_is_start(t) or len(" ".join(cur_t)) > max_chars):
                    flush()
                cur_t.append(t)
                cur_r.append(r)
            flush()
        # 인쇄 쪽 번호는 해당 쪽 전체에 적용
        for u in units:
            if u.page == pno:
                u.printed_page = printed
    return units
