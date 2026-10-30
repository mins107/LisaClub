# 학교 민원 분류 에이전트 (민원대응팀용)

민원대응팀이 접수한 민원 내용을 텍스트로 입력하면 **처리 방향을 분류**하고, 그 근거를
학교 민원 처리 매뉴얼 PDF에서 찾아 쪽 번호와 함께 보여 준다. 근거는 LLM이 아니라 매뉴얼 색인에서만 나온다.

## 구조
```
입력(웹 화면 web.py / 터미널 __main__.py)
  -> service.py   매뉴얼 색인·LLM 연결을 한 번만 만들고, 요청마다 classify() 호출
  -> pipeline.py  개인정보 마스킹 -> 반복 민원 확인 -> 규칙 판정(rules.py) -> 분기
                  분기: 거부·종결 가능 / 일반 처리 / 악성 의심(이첩 검토)
                  근거: anchor 문장으로 매뉴얼 색인 검색(manual_index.py, retriever.py)
  -> highlight.py 분류 결과 화면 + 형광펜 PDF
```

## 웹 화면 실행
```bash
pip install -r requirements.txt
# data/ 폴더에 학교민원처리매뉴얼.pdf 를 넣는다 (저장소에 올리지 않음)
python -m agent.complaint.web --llm none     # 규칙 기반, 모델 없이 바로 실행
# 브라우저에서 http://127.0.0.1:8000 접속
```
- **입력**: 민원 내용(필수), 민원 대상 학생 이름·학년반(305 등)·접수 시각·통화 시간(선택), "DB에 저장하지 않음"(시험 입력용).
- **결과**: 분기, 긴급도, 분류(담당 부서), 처리 담당·기한, **지금 할 일**(단계별 체크리스트: 안전 확보 → 증거 확보 → 민원인 응대 →
  보고·보호 → 후속 조치. 여러 유형에서 겹치는 조치는 한 줄로 합쳐 표시), 분류 사유, 과거 이력,
  **매뉴얼 근거**(민원 유형 근거 / 처리 절차 근거로 나뉘며 탭으로 골라 볼 수 있음). E1·E2 번호를 누르면 해당 근거로 이동한다.
  답변·경고 초안과 교육(지원)청 이첩 보고서 초안은 접혀 있다.
- 처리한 민원은 DB에 저장된다(아래 "민원 DB"). 학생 이름과 학년반을 둘 다 비우면 '학생 미상'으로 저장하고 학생 기준 이력 판단은 하지 않는다.
  접수 시각을 비우면 업무시간 외 판정, 통화 시간을 비우면 20분 초과 판정을 하지 않는다.
- 기본은 내 컴퓨터(127.0.0.1)에서만 접속된다. 다른 PC에서 쓰려면 `--host 0.0.0.0`을 주되,
  인증이 없으므로 신뢰할 수 있는 내부망에서만 쓴다.
- 결과 파일은 `out/web/web-날짜-시각-코드/`(report.html, result.json, evidence_highlighted.pdf)에 남는다.
- 프로그램 연동용: `POST /api/classify` 에 JSON(`text`, `student`, `class_no`, `received_at`, `call_minutes`)을 보내면 JSON 결과를 준다.

## 민원 DB
처리한 민원은 `DATABASE_URL`(기본 SQLite `data/complaints.sqlite`)에 저장된다. 테이블은 처음 실행할 때 자동으로 만들어진다.

| 테이블 | 내용 |
|---|---|
| `students` | 민원 대상 학생. 이름 + 학년반이 같으면 같은 학생 |
| `complaints` | 민원 1건 = 1행. 접수 시각·통화 시간·마스킹된 원문·분기·긴급도·담당 부서·담당·기한·반복 횟수·검토 필요 여부, 전체 결과(`result_json`) |
| `complaint_hits` | 민원별로 걸린 거부·악성 규칙(종류, 규칙 키, 라벨, 심각도) |

- **학생 식별**: 학생 이름과 학년반(숫자 3자리, 3학년 5반 = 305)을 둘 다 입력해야 한다. 둘 다 비우면 '학생 미상'으로 저장한다.
  이전 구조의 DB는 자동으로 새 구조로 바뀌며, 민원이 있으면 `파일명.bak-날짜시각`으로 보관된다.
- **이력 판단**(매뉴얼 근거는 CLAUDE.md의 표 참고): 동일·유사 민원 3회 이상 반복, 종결 직후 재접촉, 과거 악성 이력(재접촉 1·2차 대응),
  반복 악성 시 접촉 제한 검토. 기간은 `HISTORY_WINDOW_DAYS`(기본 180일), "바로"의 기준은 `RECONTACT_HOURS`(기본 24시간)이다.
  다른 학생의 매우 비슷한 민원(0.5 이상)은 결과 화면의 "과거 이력"에 참고용으로만 나온다.
- SQL DB(PostgreSQL·MySQL 등)로 바꾸려면 `.env`의 `DATABASE_URL`만 바꾼다. 예: `postgresql+psycopg://사용자:비밀번호@주소:5432/DB이름`
  (드라이버 `pip install "psycopg[binary]"` 필요).
- **Upstash는 Redis 계열이라 `DATABASE_URL`로 붙지 않는다.** 이관할 때는 `store.py`의 `find_history`·`save`를 Redis로 구현한 저장소가 필요하다
  (지금은 로컬 SQLite로 확인).
- 저장되는 원문은 전화번호·주민번호·이메일이 마스킹된 텍스트이며, 이름은 마스킹하지 않는다.

## 터미널 실행
```bash
python -m agent.complaint --demo --llm none
python -m agent.complaint --text "개인 번호 알려주세요" --student 홍길동 --class-no 305 --received-at 2026-10-30T22:10 --llm none
```

## LLM 연결 (선택)
`.env`에 OpenAI 호환 서버 정보를 넣는다(`.env.example` 참고).
```
LLM_BASE_URL=...   LLM_MODEL=...   LLM_API_KEY=...
```
LLM은 (1) 악성 여부 2차 의견 (2) 답변 초안에만 쓰이고, 인용 라벨이 존재하지 않으면 초안을 폐기한다.
`--llm auto`(기본)는 연결이 안 되면 규칙 기반으로 넘어가고, `--llm on`은 연결 실패 시 오류로 멈춘다.
민원 원문(마스킹 후)이 LLM 서버로 전송되므로 외부 서비스를 쓸 때는 개인정보 처리 기준을 확인한다.

## 테스트
```bash
pytest tests/test_complaint.py
```
