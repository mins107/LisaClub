"""근거를 PDF에 형광펜으로 칠하고, 카피킬러식 HTML 리포트를 만든다."""
import base64
import html
import os

import pymupdf

COLORS = {"reject": (1, 0.9, 0.2), "malicious": (1, 0.55, 0.55),
          "procedure": (0.6, 0.95, 0.6), "reply": (0.65, 0.8, 1)}
CSS = {"reject": "#ffe94d", "malicious": "#ff9c9c", "procedure": "#a6f2a6", "reply": "#a6ccff"}
ROLE_NAME = {"reject": "거부·종결 사유", "malicious": "특이민원 유형", "procedure": "처리 절차", "reply": "답변"}


def annotate(pdf_path, used, out_dir):
    """형광펜 PDF(근거 쪽만)와 근거별 확대 이미지를 만든다. 반환: (pdf경로, {label: png bytes})."""
    os.makedirs(out_dir, exist_ok=True)
    doc = pymupdf.open(pdf_path)
    snippets = {}
    for u in used:
        page = doc[u.ev.page - 1]
        for r in u.ev.rects:
            a = page.add_highlight_annot(pymupdf.Rect(r))
            a.set_colors(stroke=COLORS[u.role])
            a.set_info(title=u.label, content=u.reason)
            a.update()
        x0, y0 = min(((r[0], r[1]) for r in u.ev.rects), key=lambda t: (round(t[1] / 6), t[0]))
        bx = max(2, x0 - 26)
        badge = pymupdf.Rect(bx, y0 - 1, bx + 24, y0 + 12)
        page.draw_rect(badge, color=None, fill=(0.75, 0.1, 0.1))
        page.insert_text((bx + 3, y0 + 9), u.label, fontsize=7.5, color=(1, 1, 1), fontname="helv")
    for u in used:
        page = doc[u.ev.page - 1]
        ys = [r[1] for r in u.ev.rects] + [r[3] for r in u.ev.rects]
        clip = pymupdf.Rect(20, max(0, min(ys) - 40), page.rect.width - 20, min(page.rect.height, max(ys) + 40))
        snippets[u.label] = page.get_pixmap(clip=clip, matrix=pymupdf.Matrix(1.6, 1.6), annots=True).tobytes("png")
    out_pdf = os.path.join(out_dir, "evidence_highlighted.pdf")
    doc.select(sorted({u.ev.page - 1 for u in used}))
    doc.save(out_pdf)
    return out_pdf, snippets


def render_html(result, snippets, out_path):
    text = result["text_masked"]
    parts, pos = [], 0
    for s in result["spans"]:
        if s["start"] < pos:
            continue
        parts.append(html.escape(text[pos:s["start"]]))
        parts.append(f'<mark style="background:{CSS[s["kind"]]}">{html.escape(text[s["start"]:s["end"]])}'
                     f'<sup>{s["label"]}</sup></mark>')
        pos = s["end"]
    parts.append(html.escape(text[pos:]))
    cards = []
    for e in result["evidence"]:
        img = base64.b64encode(snippets[e["label"]]).decode()
        cards.append(
            f'<div class="card" style="border-left:6px solid {CSS[e["role"]]}"><b>{e["label"]}</b> · '
            f'{html.escape(ROLE_NAME[e["role"]])} · {html.escape(e["cite"])}<br>'
            f'<small>{html.escape(e["reason"])}</small>'
            f'<img src="data:image/png;base64,{img}" style="width:100%;margin-top:6px"></div>')
    def lst(items, key="label"):
        return "".join(f"<li>{html.escape(i[key] if isinstance(i, dict) else i)}</li>" for i in items) or "<li>없음</li>"
    doc = f"""<!doctype html><meta charset="utf-8"><title>민원 근거 리포트</title>
<style>body{{font-family:sans-serif;margin:0;display:flex;gap:16px;padding:16px;background:#f6f6f6}}
.col{{flex:1;min-width:0}} .card,.box{{background:#fff;border-radius:8px;padding:10px;margin-bottom:10px}}
mark{{padding:1px 2px;border-radius:3px}} sup{{font-size:.65em;color:#a00}} pre{{white-space:pre-wrap;margin:0}}</style>
<div class="col"><div class="box"><h3>민원 원문 (개인정보 마스킹)</h3><pre>{''.join(parts)}</pre></div>
<div class="box"><h3>판정: {html.escape(result['route_label'])}</h3>
<p>흥분도 {result['excitement']['score']}점({result['excitement']['level']}) · 긴급도 {result['urgency']} ·
분류 {html.escape(result['department'])} · 담당 {html.escape(result['handler'])} · 기한 {html.escape(result['deadline'])} ·
동일 유사 민원 {result['repeat_count']}회째</p>
<b>거부·종결 가능 사유</b><ul>{lst(result['reject'])}</ul><b>특이민원 유형</b><ul>{lst(result['malicious'])}</ul>
<b>현장 조치</b><ul>{lst(result['actions'], 'text')}</ul></div>
<div class="box"><h3>답변·경고 초안</h3><pre>{html.escape(result['reply_draft'])}</pre></div>
<p><small>※ 자동 판정은 후보 제시용이며 최종 판단은 학교장(민원대응팀)이 한다.
{'사람 확인 필요' if result['needs_human_review'] else ''}</small></p></div>
<div class="col"><h3>매뉴얼 근거</h3>{''.join(cards)}</div>"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
