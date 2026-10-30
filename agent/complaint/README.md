# 학교 민원 식별 에이전트 (근거 하이라이팅)

구조도 흐름: 민원 → 거부 가능 판단 → 악성 판단 → (비악성) 흥분도·유형·긴급도·담당부서 / (악성) 교육지원청용 문서.
근거는 LLM이 아니라 매뉴얼 PDF 색인에서만 나오며, 쪽 번호와 줄 좌표로 PDF에 형광펜을 칠한다.

## 실행
```bash
pip install -r requirements.txt
cp "학교민원처리매뉴얼.pdf" data/            # PDF는 저장소에 올리지 않는다(.gitignore)
python -m agent.complaint --demo --llm none  # 규칙 기반, 모델 없이 바로 실행
python -m agent.complaint --text "개인 번호 알려주세요" --received-at 2026-10-30T22:10 --llm none
open out/case01/report.html                   # 카피킬러식 화면
```
결과: `out/caseNN/report.html`(원문 하이라이트 + 근거 카드), `evidence_highlighted.pdf`(형광펜 PDF), `result.json`.

## 무료 모델 연결 (선택)
```bash
# 1) https://ollama.com 설치 후
ollama pull qwen2.5:7b-instruct
ollama pull bge-m3                       # 임베딩 검색까지 쓸 때
# 2) .env 에 EMBED_MODEL=bge-m3 추가
python -m agent.complaint --demo --llm on
```
LLM은 (1) 악성 여부 2차 의견 (2) 답변 초안에만 쓰이고, 인용 라벨이 존재하지 않으면 초안을 폐기한다.

## 테스트
```bash
pytest tests/test_complaint.py
```
