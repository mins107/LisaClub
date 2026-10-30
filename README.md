# 학교 민원 분류 에이전트

학교 민원대응팀이 접수한 민원 내용을 텍스트로 입력하면, 처리 방향(거부·종결 가능 / 일반 처리 / 악성 의심)을 분류하고
학교 민원 처리 매뉴얼 PDF에서 찾은 근거를 쪽 번호와 함께 보여 줍니다. 처리한 민원은 DB에 저장하고 과거 이력을 반영합니다.

구조·설계 원칙·DB·보안 기준은 [CLAUDE.md](CLAUDE.md), 사용법은 [agent/complaint/README.md](agent/complaint/README.md)를 보세요.

## 빠른 시작
```bash
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux는 source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # LLM·DB·학사일정 설정 (모두 선택)
python -m agent.complaint.web --llm none
# 브라우저에서 http://127.0.0.1:8000
python samples/seed_demo_db.py --reset   # (선택, 서버를 끈 뒤) 예시 민원으로 DB 채우기
```

주요 기능: 민원 분류(부서·긴급도·기한)와 매뉴얼 근거, 처리 상태 기록, 담임 교사 전달, 악성 의심 이첩 보고서(.hwpx), 민원 원문 순화,
악성 반복 판정(유사도 기반), 검토 루프(이력 점검·근거 보강), 시즌 키워드 분석과 가정통신문 계획, 학사일정 답변 초안.

## 테스트
```bash
pytest
```
