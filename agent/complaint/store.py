"""민원 이력 DB. 처리한 민원을 저장하고, 새 민원이 들어오면 같은 학생의 과거 민원과 비슷한 민원을 찾는다.

민원 대상 학생은 학생 이름 + 학년반(예: 305)으로 식별한다(둘 다 같아야 같은 학생).
이 모듈의 바깥 경계는 find_history()와 save() 두 메서드뿐이라, 다른 저장소(예: Redis)로 바꿀 때는
이 두 메서드를 같은 형태로 구현하면 된다. SQL DB(PostgreSQL·MySQL 등)는 DATABASE_URL만 바꾸면 된다.

테이블
  students        민원 대상 학생(이름 + 학년반)
  complaints      처리한 민원 1건 = 1행. 접수 정보 + 분류 결과 + 전체 결과(result_json)
  complaint_hits  민원별로 걸린 거부·악성 규칙

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
                        UniqueConstraint, create_engine, func, inspect, select, text)
from sqlalchemy.pool import StaticPool

from .retriever import tokenize

SAME_STUDENT_SIM = 0.3    # 같은 학생의 과거 민원이 "동일·유사"로 보이는 기준(자카드 유사도)
OTHER_STUDENT_SIM = 0.5   # 다른 학생의 민원은 더 비슷할 때만 참고용으로 보여 준다
SCAN_LIMIT = 500          # 내용 비교는 기간 안의 최근 N건만 (학교 규모에서는 충분)

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


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _url(target: str) -> str:
    if target == ":memory:":
        return "sqlite://"
    if target.startswith("sqlite:///") and target != "sqlite:///:memory:":
        os.makedirs(os.path.dirname(target[len("sqlite:///"):]) or ".", exist_ok=True)
    if "://" in target:
        return target
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    return "sqlite:///" + target


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
               "prior_malicious": 같은 학생의 악성 의심 민원 건수(기간 이내)}
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
                           "last_at": last.isoformat(timespec="minutes") if last else None}
        same, others, recent_closed, malicious = [], [], None, 0
        recontact_from = now - timedelta(hours=self.recontact_hours)
        for r in rows:
            sim = _jaccard(r["text_masked"], text_)
            closed = r["route"] == "REJECTABLE" or bool(r["closed_by_repeat"])
            item = {"id": r["id"], "created_at": r["created_at"].isoformat(timespec="minutes"),
                    "student": f"{r['s_name']}({r['s_class']})" if r["s_name"] else None,
                    "route": r["route"], "similarity": round(sim, 2), "snippet": _snippet(r["text_masked"]),
                    "closed": closed}
            if student_id and r["student_id"] == student_id:
                if r["route"] == "ESCALATE":
                    malicious += 1
                if closed and recent_closed is None and r["created_at"] >= recontact_from:
                    recent_closed = item
                if sim >= SAME_STUDENT_SIM:
                    same.append(item)
            elif sim >= OTHER_STUDENT_SIM:
                others.append(item)
        return {"student": summary, "same_student": same, "similar_others": others[:5],
                "recent_closed": recent_closed, "prior_malicious": malicious}

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
                call_minutes=call_minutes, text_masked=result["text_masked"],
                route=result["route"], route_label=result["route_label"], urgency=result["urgency"],
                department=result["department"], handler=result["handler"], deadline=result["deadline"],
                repeat_count=result["repeat_count"], closed_by_repeat=closed_by_repeat,
                needs_human_review=result["needs_human_review"], llm_used=result["llm_used"],
                result_json=json.dumps(result, ensure_ascii=False), created_at=now)).inserted_primary_key[0]
            hits = [{"complaint_id": cid, "kind": h["kind"], "rule_key": h["key"], "label": h["label"],
                     "severity": h.get("severity")} for h in result["reject"] + result["malicious"]]
            if hits:
                c.execute(complaint_hits.insert(), hits)
        return cid
