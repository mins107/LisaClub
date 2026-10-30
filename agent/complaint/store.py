"""민원 이력 DB. 처리한 민원을 저장하고, 새 민원이 들어오면 같은 학생의 과거 민원과 비슷한 민원을 찾는다.

민원 대상 학생은 학생 이름 + 학년반(예: 305)으로 식별한다(둘 다 같아야 같은 학생).
이 모듈의 바깥 경계는 find_history()와 save() 두 메서드뿐이라, 다른 저장소(예: Redis)로 바꿀 때는
이 두 메서드를 같은 형태로 구현하면 된다. SQL DB(PostgreSQL·MySQL 등)는 DATABASE_URL만 바꾸면 된다.

테이블
  students          민원 대상 학생(이름 + 학년반)
  complaints        처리한 민원 1건 = 1행. 접수 정보 + 분류 결과 + 전체 결과(result_json) + 처리 상태·담임 전달 상태
  complaint_hits    민원별로 걸린 거부·악성 규칙
  complaint_events  민원별 처리 경과(접수, 상태 변경, 메모, 담임 전달)

이력 판단 기준(매뉴얼 근거는 pipeline.py·rules.py 참고)
  동일·유사 반복      같은 학생의 과거 민원 중 내용이 비슷한 것(window_days 이내)
  종결 직후 재접촉    같은 학생의 종결(거부·종결 가능) 민원이 recontact_hours 이내에 있음
  과거 악성 이력      같은 학생의 악성(특이) 의심 민원 건수(window_days 이내)
"""
import json
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import (Boolean, Column, DateTime, Float, ForeignKey, Integer, MetaData, String, Table, Text,
                        UniqueConstraint, create_engine, false, func, true, inspect, or_, select, text)
from sqlalchemy.pool import StaticPool

from .retriever import tokenize
from .rules import DEPT_NAMES, UNASSIGNED
from .soften import mask_rough

SAME_STUDENT_SIM = 0.3    # 같은 학생의 과거 민원이 "동일·유사"로 보이는 기준(자카드 유사도)
OTHER_STUDENT_SIM = 0.5   # 다른 학생의 민원은 더 비슷할 때만 참고용으로 보여 준다
SCAN_LIMIT = 500          # 내용 비교는 기간 안의 최근 N건만 (학교 규모에서는 충분)

STATUSES = ["접수", "처리 중", "완료", "이첩"]      # 처리 상태. 완료·이첩은 처리가 끝난 상태
OPEN_STATUSES = ["접수", "처리 중"]
EVENT_KINDS = ["접수", "상태", "메모", "담임전달"]

# 이전 4개 분류 -> 현재 부서 체계(근사 대응). 정확한 부서는 담당자가 확인한다.
LEGACY_DEPARTMENT = {"교무/학사": "교무기획부", "생활지도/상담": "학생생활안전부", "학부모/교직원 소통": "교무기획부",
                     "학교 운영": "교무기획부", "기타": UNASSIGNED}

meta = MetaData()

students = Table(
    "students", meta,
    Column("id", Integer, primary_key=True),
    Column("name", String(100), nullable=False),
    Column("class_no", String(4), nullable=False),           # 학년반. 3학년 5반 = 305
    Column("created_at", DateTime, nullable=False),
    UniqueConstraint("name", "class_no", name="uq_student_identity"),
)

complaints = Table(
    "complaints", meta,
    Column("id", Integer, primary_key=True),
    Column("student_id", Integer, ForeignKey("students.id"), index=True),    # NULL = 학생 미상
    Column("received_at", DateTime),                       # 접수 시각(입력 시)
    Column("call_minutes", Float),                         # 통화·면담 시간(분)
    Column("text_masked", Text, nullable=False),           # 개인정보(전화번호 등) 마스킹 후 원문
    Column("text_soft", Text),                             # 담당자 화면용 순화문(없으면 규칙으로 가려서 보여 줌)
    Column("route", String(16), nullable=False, index=True),   # REJECTABLE | HANDLE | ESCALATE
    Column("route_label", String(100), nullable=False),
    Column("urgency", String(8), nullable=False),
    Column("department", String(40), nullable=False),
    Column("handler", String(100), nullable=False),
    Column("deadline", String(60), nullable=False),
    Column("repeat_count", Integer, nullable=False),       # 동일·유사 민원 몇 회째인지
    Column("closed_by_repeat", Boolean, nullable=False),   # 반복 사유로 종결 가능 판정이었는지
    Column("needs_human_review", Boolean, nullable=False),
    Column("llm_used", Boolean, nullable=False),
    Column("result_json", Text, nullable=False),           # 분류 결과 전체(근거·초안 포함)
    Column("created_at", DateTime, nullable=False, index=True),
    Column("status", String(10), nullable=False, server_default="접수", index=True),   # STATUSES
    Column("completed_at", DateTime),                      # 완료·이첩 처리한 시각
    Column("updated_at", DateTime),                        # 마지막으로 처리 경과가 바뀐 시각
    Column("homeroom_needed", Boolean, nullable=False, server_default=false()),   # 담임 교사 전달이 필요한 민원
    Column("homeroom_sent_at", DateTime),                  # 담임 교사에게 전달했다고 표시한 시각
)

complaint_hits = Table(
    "complaint_hits", meta,
    Column("id", Integer, primary_key=True),
    Column("complaint_id", Integer, ForeignKey("complaints.id"), nullable=False, index=True),
    Column("kind", String(12), nullable=False),            # reject | malicious
    Column("rule_key", String(30), nullable=False),
    Column("label", String(100), nullable=False),
    Column("severity", Integer),
)

complaint_events = Table(
    "complaint_events", meta,
    Column("id", Integer, primary_key=True),
    Column("complaint_id", Integer, ForeignKey("complaints.id"), nullable=False, index=True),
    Column("created_at", DateTime, nullable=False),
    Column("kind", String(12), nullable=False),            # EVENT_KINDS
    Column("status", String(10)),                          # 상태 변경이면 바뀐 상태
    Column("note", Text),
    Column("actor", String(50)),                           # 처리자(선택 입력)
)

notice_plans = Table(
    "notice_plans", meta,
    Column("id", Integer, primary_key=True),
    Column("keyword", String(60), nullable=False, unique=True),     # 시즌 키워드 하나당 계획 하나
    Column("related", Text, nullable=False),                        # 같이 늘어나는 키워드(JSON 목록)
    Column("peak_month", Integer, nullable=False),                  # 민원이 늘어나는 달(1~12)
    Column("lead_days", Integer, nullable=False),                   # 그 달 며칠 전부터 전달하는가
    Column("department", String(40), nullable=False),               # 문의 창구 부서
    Column("title", String(200), nullable=False),
    Column("body", Text, nullable=False),                           # 가정통신문 초안
    Column("evidence", Text, nullable=False),                       # 계획을 세운 근거(분석 결과 요약)
    Column("active", Boolean, nullable=False, server_default=true()),
    Column("created_at", DateTime, nullable=False),
)

notice_sends = Table(
    "notice_sends", meta,
    Column("id", Integer, primary_key=True),
    Column("plan_id", Integer, ForeignKey("notice_plans.id"), nullable=False, index=True),
    Column("season_year", Integer, nullable=False),                 # 어느 해 시즌에 전달했는가
    Column("sent_at", DateTime, nullable=False),
    Column("actor", String(50)),
    Column("note", Text),
    UniqueConstraint("plan_id", "season_year", name="uq_notice_send"),
)


@dataclass(frozen=True)
class Student:
    name: str
    class_no: str

    def display(self) -> str:
        return f"{self.name}({self.class_no})"


def make_student(name, class_no):
    """학생 이름과 학년반으로 학생을 만든다. 둘 다 비면 None(학생 미상). 학년반은 숫자 3자리(305 등)."""
    name = "".join((name or "").split())
    cls = re.sub(r"\D", "", class_no or "")
    if not name and not cls:
        return None
    if not name or not cls:
        raise ValueError("학생을 식별하려면 학생 이름과 학년반을 둘 다 입력해 주세요(둘 다 비우면 학생 미상으로 저장).")
    if not re.fullmatch(r"[1-6]\d{2}", cls):
        raise ValueError("학년반은 숫자 3자리로 입력해 주세요. 예: 3학년 5반 → 305")
    return Student(name, cls)


def _jaccard(a: str, b: str) -> float:
    A, B = set(tokenize(a)), set(tokenize(b))
    return len(A & B) / len(A | B) if A and B else 0.0


MAL_TRAIT_SEVERITY = 3    # 반복민원으로 셀 민원의 악성 특성: 심각도 3 이상이면서 확신 있는 규칙이 걸림(팀 결정)


def malicious_trait(hits):
    """분류 결과의 악성 유형 목록(hit dict)에 '악성 특성'이 있는지. 심각도 3 이상이고 확신 낮은 규칙(오탐 가능)이 아닌 것만 인정한다."""
    return any((h.get("severity") or 0) >= MAL_TRAIT_SEVERITY and h.get("confident", True) for h in hits or [])


def _malicious_trait(result_json):
    try:
        return malicious_trait(json.loads(result_json).get("malicious"))
    except (TypeError, ValueError, AttributeError):
        return False


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _local(dt):
    """DB에는 UTC로 저장하므로, 화면에는 이 컴퓨터의 현지 시각으로 바꿔 보여 준다."""
    return dt.replace(tzinfo=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M") if dt else None


def due_days(deadline):
    """처리 기한 문구에서 일 수를 뽑는다. '7일 이내' -> 7, '즉시…' -> 1(당일~익일로 본다, 임의 기준), 그 외 None."""
    m = re.search(r"(\d+)\s*일", deadline or "")
    if m:
        return int(m.group(1))
    return 1 if "즉시" in (deadline or "") else None


def _due_info(created, deadline, status, completed, now):
    """(표시 문구, 기한 초과 여부). 진행 중이면 남은 기한, 끝났으면 걸린 기간."""
    if status in ("완료", "이첩"):
        end = completed or created
        d = (end - created).days
        return ("당일 처리" if d <= 0 else f"{d}일 소요"), False
    n = due_days(deadline)
    if n is None:
        return "", False
    left = created + timedelta(days=n) - now
    if left.total_seconds() >= 0:
        return ("오늘 마감" if left.days == 0 else f"D-{left.days}"), False
    return f"초과 {-(-int(-left.total_seconds()) // 86400)}일", True


def _url(target: str) -> str:
    if target == ":memory:":
        return "sqlite://"
    if target.startswith("sqlite:///") and target != "sqlite:///:memory:":
        os.makedirs(os.path.dirname(target[len("sqlite:///"):]) or ".", exist_ok=True)
    if "://" in target:
        return target
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    return "sqlite:///" + target


def _soft(row):
    """담당자 화면에 보여 줄 순화문. 저장된 순화문이 없는 이전 민원은 거친 표현만 규칙으로 가려서 쓴다."""
    return row["text_soft"] if row["text_soft"] else mask_rough(row["text_masked"])[0]


def _snippet(text_, n=60):
    return text_[:n] + ("…" if len(text_) > n else "")


def _engine(url):
    kw = {"poolclass": StaticPool, "connect_args": {"check_same_thread": False}} if url == "sqlite://" else {}
    return create_engine(url, **kw)


class Store:
    def __init__(self, target=":memory:", window_days=180, recontact_hours=24):
        """target: DATABASE_URL, SQLite 파일 경로, 또는 ':memory:'.
        window_days: 반복·악성 이력을 세는 기간. 매뉴얼에 기간 규정은 없고, 지원 요청 보고서 작성 예시가 '6개월간'이다.
        recontact_hours: 종결 후 '바로' 연락이 온 것으로 보는 시간. 매뉴얼에 기준이 없어 임의로 정한 값이다."""
        url = _url(target)
        self.engine = _engine(url)
        self.window_days, self.recontact_hours = window_days, recontact_hours
        self._migrate_old_schema(url)
        meta.create_all(self.engine)       # 테이블이 없을 때만 만든다
        self._add_missing_columns()

    def _add_missing_columns(self):
        """이전 버전의 complaints 테이블에 처리 상태 관련 컬럼이 없으면 덧붙인다(데이터는 그대로 유지)."""
        have = {c["name"] for c in inspect(self.engine).get_columns("complaints")}
        not_null = {"status": "NOT NULL DEFAULT '접수'", "homeroom_needed": "NOT NULL DEFAULT FALSE"}
        with self.engine.begin() as c:
            for col in complaints.c:
                if col.name not in have:
                    c.execute(text(f"ALTER TABLE complaints ADD COLUMN {col.name} "
                                   f"{col.type.compile(dialect=self.engine.dialect)} {not_null.get(col.name, '')}"))
            c.execute(text("UPDATE complaints SET updated_at = created_at WHERE updated_at IS NULL"))
            for old, new in LEGACY_DEPARTMENT.items():      # 이전 부서 체계로 저장된 민원을 새 부서 체계로 옮긴다(한 번만 일어남)
                c.execute(text("UPDATE complaints SET department = :new WHERE department = :old"), {"new": new, "old": old})

    def _migrate_old_schema(self, url):
        """이전 구조(작성자 테이블 complainants, 흥분도 컬럼)를 만나면 새 구조로 바꾼다.
        민원이 없으면 이전 테이블만 지우고, 있으면 SQLite 파일은 백업으로 옮겨 보존한 뒤 새로 만든다."""
        insp = inspect(self.engine)
        old = insp.has_table("complainants") or (
            insp.has_table("complaints") and "excitement_score" in {c["name"] for c in insp.get_columns("complaints")})
        if not old:
            return
        n = 0
        if insp.has_table("complaints"):
            with self.engine.connect() as c:
                n = c.execute(text("SELECT COUNT(*) FROM complaints")).scalar()
        if n == 0:
            with self.engine.begin() as c:
                for t in ("complaint_hits", "complaints", "complainants"):
                    c.execute(text(f"DROP TABLE IF EXISTS {t}"))
            return
        if url.startswith("sqlite:///") and url != "sqlite:///:memory:":
            path = url[len("sqlite:///"):]
            self.engine.dispose()
            backup = f"{path}.bak-{datetime.now():%Y%m%d-%H%M%S}"
            try:
                shutil.move(path, backup)
            except OSError as e:
                raise RuntimeError("이전 구조의 DB 파일을 백업하지 못했습니다. 실행 중인 서버를 모두 끈 뒤 다시 실행해 주세요.") from e
            self.engine = _engine(url)
            print(f"[DB] 이전 구조의 DB(민원 {n}건)를 {backup}로 보관하고 새 DB를 만들었습니다.")
            return
        raise RuntimeError(f"DB가 이전 버전 구조이고 민원 {n}건이 들어 있어 자동으로 바꾸지 않았습니다. 백업한 뒤 옮기거나 비우고 다시 실행해 주세요.")

    def find_history(self, student, text_, now=None):
        """새 민원의 과거 이력. student가 None이면 학생 이력은 비고, 다른 민원과의 유사도만 본다.

        반환: {"student": 학생 요약|None,
               "same_student": 같은 학생의 동일·유사 민원(기간 이내),
               "similar_others": 다른 학생의 매우 유사한 민원(참고용),
               "recent_closed": 종결 직후 재접촉이면 그 종결 민원, 아니면 None,
               "prior_malicious": 같은 학생의 악성 의심 민원 건수(기간 이내),
               "repeat_candidates": 같은 학생의 미해결(접수·처리 중) 민원 중 악성 특성이 있는 것(내용 포함, 유사도는 아직 안 잼)}
        """
        now = now or _now()
        with self.engine.connect() as c:
            student_id = c.execute(select(students.c.id).where(
                students.c.name == student.name, students.c.class_no == student.class_no)).scalar() if student else None
            rows = c.execute(
                select(complaints, students.c.name.label("s_name"), students.c.class_no.label("s_class"))
                .select_from(complaints.outerjoin(students, complaints.c.student_id == students.c.id))
                .where(complaints.c.created_at >= now - timedelta(days=self.window_days))
                .order_by(complaints.c.id.desc()).limit(SCAN_LIMIT)).mappings().all()
            summary = None
            if student_id:
                total, last = c.execute(select(func.count(), func.max(complaints.c.created_at))
                                        .where(complaints.c.student_id == student_id)).one()
                esc = c.execute(select(func.count()).where(complaints.c.student_id == student_id,
                                                           complaints.c.route == "ESCALATE")).scalar()
                summary = {"name": student.name, "class_no": student.class_no, "total": total, "escalated": esc,
                           "last_at": _local(last)}
        same, others, recent_closed, malicious, candidates = [], [], None, 0, []
        recontact_from = now - timedelta(hours=self.recontact_hours)
        for r in rows:
            sim = _jaccard(r["text_masked"], text_)
            closed = r["route"] == "REJECTABLE" or bool(r["closed_by_repeat"])
            item = {"id": r["id"], "created_at": _local(r["created_at"]),
                    "student": f"{r['s_name']}({r['s_class']})" if r["s_name"] else None,
                    "route": r["route"], "similarity": round(sim, 2), "snippet": _snippet(_soft(r)), "snippet_raw": _snippet(r["text_masked"], 400),
                    "closed": closed, "status": r["status"], "malicious_trait": _malicious_trait(r["result_json"])}
            if student_id and r["student_id"] == student_id:
                if r["status"] in OPEN_STATUSES and item["malicious_trait"]:
                    candidates.append({**item, "text": r["text_masked"]})      # 반복민원 후보(유사도는 pipeline에서 잰다)
                if r["route"] == "ESCALATE":
                    malicious += 1
                if closed and recent_closed is None and r["created_at"] >= recontact_from:
                    recent_closed = item
                if sim >= SAME_STUDENT_SIM:
                    same.append(item)
            elif sim >= OTHER_STUDENT_SIM:
                others.append(item)
        return {"student": summary, "same_student": same, "similar_others": others[:5],
                "recent_closed": recent_closed, "prior_malicious": malicious, "repeat_candidates": candidates}

    def save(self, result, student=None, received_at=None, call_minutes=None, closed_by_repeat=False):
        """분류가 끝난 민원 1건을 저장하고 민원 번호(id)를 돌려준다. 학생이 없으면 '학생 미상'으로 저장한다."""
        now = _now()
        with self.engine.begin() as c:
            student_id = None
            if student:
                student_id = c.execute(select(students.c.id).where(
                    students.c.name == student.name, students.c.class_no == student.class_no)).scalar()
                if student_id is None:
                    student_id = c.execute(students.insert().values(
                        name=student.name, class_no=student.class_no, created_at=now)).inserted_primary_key[0]
            cid = c.execute(complaints.insert().values(
                student_id=student_id,
                received_at=datetime.fromisoformat(received_at) if received_at else None,
                call_minutes=call_minutes, text_masked=result["text_masked"], text_soft=result.get("text_soft"),
                route=result["route"], route_label=result["route_label"], urgency=result["urgency"],
                department=result["department"], handler=result["handler"], deadline=result["deadline"],
                repeat_count=result["repeat_count"], closed_by_repeat=closed_by_repeat,
                status="접수", updated_at=now, homeroom_needed=bool(result.get("homeroom")),
                needs_human_review=result["needs_human_review"], llm_used=result["llm_used"],
                result_json=json.dumps(result, ensure_ascii=False), created_at=now)).inserted_primary_key[0]
            hits = [{"complaint_id": cid, "kind": h["kind"], "rule_key": h["key"], "label": h["label"],
                     "severity": h.get("severity")} for h in result["reject"] + result["malicious"]]
            if hits:
                c.execute(complaint_hits.insert(), hits)
            c.execute(complaint_events.insert().values(
                complaint_id=cid, created_at=now, kind="접수", status="접수", note=f"자동 분류: {result['route_label']}"))
        return cid

    # ---- 처리 경과·대시보드 ----

    def get_complaint(self, cid):
        """민원 1건의 상세. 없으면 None. result는 저장해 둔 분류 결과(dict), events는 처리 경과(오래된 순)."""
        with self.engine.connect() as c:
            r = c.execute(
                select(complaints, students.c.name.label("s_name"), students.c.class_no.label("s_class"))
                .select_from(complaints.outerjoin(students, complaints.c.student_id == students.c.id))
                .where(complaints.c.id == cid)).mappings().first()
            if not r:
                return None
            evs = c.execute(select(complaint_events).where(complaint_events.c.complaint_id == cid)
                            .order_by(complaint_events.c.id)).mappings().all()
        result = json.loads(r["result_json"])
        result["complaint_id"] = r["id"]
        if not result.get("text_soft"):         # 순화문이 생기기 전에 저장된 민원
            result["text_soft"], n = mask_rough(r["text_masked"])
            result["text_soft_method"] = "rules" if n else "none"
        events = [{"created_at": _local(e["created_at"]), "kind": e["kind"], "status": e["status"],
                   "note": e["note"], "actor": e["actor"]} for e in evs]
        if not events:      # 처리 경과 기능이 생기기 전에 저장된 민원
            events = [{"created_at": _local(r["created_at"]), "kind": "접수", "status": "접수", "note": None, "actor": None}]
        now = _now()
        due, overdue = _due_info(r["created_at"], r["deadline"], r["status"], r["completed_at"], now)
        return {"id": r["id"], "student": f"{r['s_name']}({r['s_class']})" if r["s_name"] else None,
                "created_at": _local(r["created_at"]), "updated_at": _local(r["updated_at"]),
                "completed_at": _local(r["completed_at"]), "status": r["status"], "route": r["route"],
                "route_label": r["route_label"], "urgency": r["urgency"], "department": r["department"],
                "handler": r["handler"], "deadline": r["deadline"], "due": due, "overdue": overdue,
                "homeroom_needed": bool(r["homeroom_needed"]), "homeroom_sent_at": _local(r["homeroom_sent_at"]),
                "needs_human_review": bool(r["needs_human_review"]), "result": result, "events": events}

    def add_event(self, cid, kind, note=None, status=None, actor=None):
        with self.engine.begin() as c:
            self._event(c, cid, kind, note, status, actor, _now())

    def _event(self, c, cid, kind, note, status, actor, now):
        c.execute(complaint_events.insert().values(
            complaint_id=cid, created_at=now, kind=kind, status=status, actor=(actor or "").strip()[:50] or None,
            note=(note or "").strip()[:1000] or None))
        c.execute(complaints.update().where(complaints.c.id == cid).values(updated_at=now))

    def set_status(self, cid, status, note=None, actor=None):
        """처리 상태를 바꾸고 경과에 남긴다. 완료·이첩이면 처리 완료 시각을 기록하고, 다시 열면 지운다."""
        if status not in STATUSES:
            raise ValueError("처리 상태는 " + ", ".join(STATUSES) + " 중 하나여야 합니다.")
        now = _now()
        with self.engine.begin() as c:
            old = c.execute(select(complaints.c.status).where(complaints.c.id == cid)).scalar()
            if old is None:
                raise KeyError(cid)
            c.execute(complaints.update().where(complaints.c.id == cid).values(
                status=status, completed_at=now if status in ("완료", "이첩") else None))
            label = f"{old} → {status}" + (f" — {note.strip()}" if (note or "").strip() else "")
            self._event(c, cid, "상태", label, status, actor, now)

    def mark_homeroom_sent(self, cid, note=None, actor=None):
        """담임 교사에게 전달했다고 표시한다. 아직 '접수'면 '처리 중'으로 바꾼다."""
        now = _now()
        with self.engine.begin() as c:
            row = c.execute(select(complaints.c.status, complaints.c.homeroom_needed)
                            .where(complaints.c.id == cid)).first()
            if row is None:
                raise KeyError(cid)
            c.execute(complaints.update().where(complaints.c.id == cid).values(homeroom_sent_at=now))
            self._event(c, cid, "담임전달", note or "담임 교사에게 전달함", None, actor, now)
            if row.status == "접수":
                c.execute(complaints.update().where(complaints.c.id == cid).values(status="처리 중", completed_at=None))
                self._event(c, cid, "상태", "접수 → 처리 중 — 담임 교사 전달 후 자동 변경", "처리 중", actor, now)

    def list_complaints(self, status=None, route=None, department=None, urgency=None, homeroom=None,
                        overdue=False, q=None, page=1, per_page=20, now=None):
        """대시보드 목록. 최신 순. status는 STATUSES 또는 'open'(접수+처리 중), homeroom은 'pending'|'sent'.
        반환: (이번 쪽 행 목록, 조건에 맞는 전체 건수)"""
        now = now or _now()
        cond = []
        if status == "open":
            cond.append(complaints.c.status.in_(OPEN_STATUSES))
        elif status in STATUSES:
            cond.append(complaints.c.status == status)
        for col, v in ((complaints.c.route, route), (complaints.c.department, department), (complaints.c.urgency, urgency)):
            if v:
                cond.append(col == v)
        if homeroom == "pending":
            cond += [complaints.c.homeroom_needed.is_(True), complaints.c.homeroom_sent_at.is_(None)]
        elif homeroom == "sent":
            cond.append(complaints.c.homeroom_sent_at.is_not(None))
        if q and q.strip():
            like = "%" + q.strip().replace("%", "").replace("_", "") + "%"
            cond.append(or_(complaints.c.text_masked.ilike(like), complaints.c.text_soft.ilike(like), students.c.name.ilike(like)))
        with self.engine.connect() as c:
            rows = c.execute(
                select(complaints, students.c.name.label("s_name"), students.c.class_no.label("s_class"))
                .select_from(complaints.outerjoin(students, complaints.c.student_id == students.c.id))
                .where(*cond).order_by(complaints.c.id.desc()).limit(5000)).mappings().all()
        out = []
        for r in rows:
            due, over = _due_info(r["created_at"], r["deadline"], r["status"], r["completed_at"], now)
            if overdue and not (over and r["status"] in OPEN_STATUSES):
                continue
            out.append({"id": r["id"], "created_at": _local(r["created_at"]), "updated_at": _local(r["updated_at"]),
                        "student": f"{r['s_name']}({r['s_class']})" if r["s_name"] else None,
                        "text": _snippet(_soft(r), 70), "route": r["route"], "urgency": r["urgency"],
                        "department": r["department"], "handler": r["handler"], "deadline": r["deadline"],
                        "status": r["status"], "due": due, "overdue": over,
                        "homeroom_needed": bool(r["homeroom_needed"]), "homeroom_sent_at": _local(r["homeroom_sent_at"]),
                        "needs_human_review": bool(r["needs_human_review"])})
        start = (max(page, 1) - 1) * per_page
        return out[start:start + per_page], len(out)

    def stats(self, days=14, now=None):
        """대시보드 요약 숫자와 그래프용 집계."""
        now = now or _now()
        with self.engine.connect() as c:
            rows = c.execute(select(complaints.c.created_at, complaints.c.route, complaints.c.department,
                                    complaints.c.status, complaints.c.deadline, complaints.c.completed_at,
                                    complaints.c.homeroom_needed, complaints.c.homeroom_sent_at)).all()
        count = lambda key: {k: sum(1 for r in rows if getattr(r, key) == k) for k in sorted({getattr(r, key) for r in rows})}  # noqa: E731
        today = now.replace(tzinfo=timezone.utc).astimezone().date()
        daily = {today - timedelta(days=i): 0 for i in range(days - 1, -1, -1)}
        overdue = 0
        for r in rows:
            d = r.created_at.replace(tzinfo=timezone.utc).astimezone().date()
            if d in daily:
                daily[d] += 1
            if r.status in OPEN_STATUSES and _due_info(r.created_at, r.deadline, r.status, r.completed_at, now)[1]:
                overdue += 1
        by_status = {k: count("status").get(k, 0) for k in STATUSES}
        return {"total": len(rows), "by_status": by_status, "open": by_status["접수"] + by_status["처리 중"],
                "overdue": overdue, "by_route": count("route"), "by_department": count("department"),
                "homeroom_pending": sum(1 for r in rows if r.homeroom_needed and not r.homeroom_sent_at),
                "daily": [(d.strftime("%m-%d"), n) for d, n in daily.items()],
                "departments": self.department_stats(now)}

    def department_stats(self, now=None):
        """부서별 민원 현황. 부서마다 접수·진행 중·처리 끝(완료·이첩)·기한 초과·기한 넘겨 끝낸 건·평균 처리일·반복 민원·악성 의심·주요 주제."""
        now = now or _now()
        with self.engine.connect() as c:
            rows = c.execute(select(complaints.c.created_at, complaints.c.department, complaints.c.status, complaints.c.deadline,
                                    complaints.c.completed_at, complaints.c.route, complaints.c.repeat_count,
                                    complaints.c.result_json)).all()
        out = {d: {"total": 0, "open": 0, "done": 0, "overdue": 0, "late_done": 0, "days": [], "repeat": 0, "escalate": 0, "topics": {}}
               for d in DEPT_NAMES}
        for r in rows:
            d = out.setdefault(r.department, {"total": 0, "open": 0, "done": 0, "overdue": 0, "late_done": 0, "days": [],
                                              "repeat": 0, "escalate": 0, "topics": {}})
            d["total"] += 1
            d["repeat"] += r.repeat_count >= 2
            d["escalate"] += r.route == "ESCALATE"
            if r.status in OPEN_STATUSES:
                d["open"] += 1
                d["overdue"] += _due_info(r.created_at, r.deadline, r.status, r.completed_at, now)[1]
            else:
                d["done"] += 1
                days = ((r.completed_at or r.created_at) - r.created_at).total_seconds() / 86400
                d["days"].append(days)
                n = due_days(r.deadline)
                d["late_done"] += n is not None and days > n
            try:
                for kw in json.loads(r.result_json).get("department_keywords", []):
                    d["topics"][kw] = d["topics"].get(kw, 0) + 1
            except (ValueError, TypeError):
                pass
        for d in out.values():
            d["avg_days"] = round(sum(d["days"]) / len(d["days"]), 1) if d["days"] else None
            d["top_topics"] = sorted(d["topics"], key=lambda k: -d["topics"][k])[:3]
            del d["days"], d["topics"]
        return out

    # ---- 시즌 분석과 가정통신문 계획 ----
    def topic_rows(self):
        """시즌 분석 입력: [(접수 날짜(현지), [키워드])]. 키워드는 분류 때 저장한 topic_keywords(없으면 department_keywords)."""
        with self.engine.connect() as c:
            rows = c.execute(select(complaints.c.created_at, complaints.c.result_json)).all()
        out = []
        for r in rows:
            try:
                res = json.loads(r.result_json)
            except (ValueError, TypeError):
                continue
            kws = res.get("topic_keywords") or res.get("department_keywords") or []
            out.append((r.created_at.replace(tzinfo=timezone.utc).astimezone().date(), list(kws)))
        return out

    def upsert_notice_plans(self, plans, now=None):
        """새 시즌 키워드는 계획으로 추가하고, 이미 있는 키워드는 분석 결과(시기·연관 키워드·근거)만 갱신한다. 제목·본문은 그대로 둔다.
        반환: 새로 추가한 건수."""
        now, added = now or _now(), 0
        with self.engine.begin() as c:
            for p in plans:
                row = c.execute(select(notice_plans.c.id).where(notice_plans.c.keyword == p["keyword"])).first()
                vals = {"related": json.dumps(p["related"], ensure_ascii=False), "peak_month": p["peak_month"],
                        "evidence": p["evidence"]}
                if row:
                    c.execute(notice_plans.update().where(notice_plans.c.id == row.id).values(**vals))
                else:
                    c.execute(notice_plans.insert().values(keyword=p["keyword"], lead_days=p["lead_days"], department=p["department"],
                                                           title=p["title"], body=p["body"], active=True, created_at=now, **vals))
                    added += 1
        return added

    def list_notice_plans(self):
        """계획 목록(시기 빠른 순)과 전달 기록: [{id, keyword, related, peak_month, lead_days, department, title, body, evidence, active, sends}]."""
        with self.engine.connect() as c:
            plans = c.execute(select(notice_plans).order_by(notice_plans.c.peak_month, notice_plans.c.id)).mappings().all()
            sends = c.execute(select(notice_sends).order_by(notice_sends.c.sent_at)).mappings().all()
        out = []
        for p in plans:
            out.append({**{k: p[k] for k in ("id", "keyword", "peak_month", "lead_days", "department", "title", "body", "evidence")},
                        "related": json.loads(p["related"]), "active": bool(p["active"]),
                        "sends": [{"season_year": s["season_year"], "sent_at": _local(s["sent_at"]), "actor": s["actor"], "note": s["note"]}
                                  for s in sends if s["plan_id"] == p["id"]]})
        return out

    def mark_notice_sent(self, plan_id, season_year, actor=None, note=None, now=None):
        """가정통신문을 전달했다고 기록한다(계획·시즌 연도당 한 번). 이미 기록돼 있으면 False. 없는 계획이면 KeyError."""
        with self.engine.begin() as c:
            if not c.execute(select(notice_plans.c.id).where(notice_plans.c.id == plan_id)).first():
                raise KeyError(plan_id)
            if c.execute(select(notice_sends.c.id).where((notice_sends.c.plan_id == plan_id)
                                                         & (notice_sends.c.season_year == season_year))).first():
                return False
            c.execute(notice_sends.insert().values(plan_id=plan_id, season_year=season_year, sent_at=now or _now(),
                                                   actor=actor or None, note=note or None))
        return True

    def get_texts(self, ids):
        """민원 번호 -> 마스킹된 원문. 이첩 보고서에 이전 민원의 원문을 적을 때 쓴다."""
        if not ids:
            return {}
        with self.engine.connect() as c:
            return {r.id: r.text_masked for r in c.execute(select(complaints.c.id, complaints.c.text_masked)
                                                           .where(complaints.c.id.in_(list(ids))))}
