"""민원 이력 DB. 처리한 민원을 저장하고, 새 민원이 들어오면 과거 작성자·내용으로 이력을 찾는다.

작성자는 이름 + 연락처 끝 4자리로 식별한다(둘 다 같아야 같은 작성자).
이 모듈의 바깥 경계는 find_history()와 save() 두 메서드뿐이라, 다른 저장소(예: Redis)로 바꿀 때는
이 두 메서드를 같은 형태로 구현하면 된다. SQL DB(PostgreSQL·MySQL 등)는 DATABASE_URL만 바꾸면 된다.

테이블
  complainants    작성자(이름 + 연락처 끝 4자리)
  complaints      처리한 민원 1건 = 1행. 접수 정보 + 분류 결과 + 전체 결과(result_json)
  complaint_hits  민원별로 걸린 거부·악성 규칙

이력 판단 기준(매뉴얼 근거는 pipeline.py·rules.py 참고)
  동일·유사 반복      같은 작성자의 과거 민원 중 내용이 비슷한 것(window_days 이내)
  종결 직후 재접촉    같은 작성자의 종결(거부·종결 가능) 민원이 recontact_hours 이내에 있음
  과거 악성 이력      같은 작성자의 악성(특이) 의심 민원 건수(window_days 이내)
"""
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import (Boolean, Column, DateTime, Float, ForeignKey, Integer, MetaData, String, Table, Text,
                        UniqueConstraint, create_engine, func, inspect, select, text)
from sqlalchemy.pool import StaticPool

from .retriever import tokenize

SAME_AUTHOR_SIM = 0.3     # 같은 작성자의 과거 민원이 "동일·유사"로 보이는 기준(자카드 유사도)
OTHER_AUTHOR_SIM = 0.5    # 다른 작성자의 민원은 더 비슷할 때만 참고용으로 보여 준다
SCAN_LIMIT = 500          # 내용 비교는 기간 안의 최근 N건만 (학교 규모에서는 충분)

meta = MetaData()

complainants = Table(
    "complainants", meta,
    Column("id", Integer, primary_key=True),
    Column("name", String(100), nullable=False),
    Column("phone_last4", String(4), nullable=False),
    Column("created_at", DateTime, nullable=False),
    UniqueConstraint("name", "phone_last4", name="uq_complainant_identity"),
)

complaints = Table(
    "complaints", meta,
    Column("id", Integer, primary_key=True),
    Column("complainant_id", Integer, ForeignKey("complainants.id"), index=True),   # NULL = 작성자 미상
    Column("received_at", DateTime),                       # 접수 시각(입력 시)
    Column("call_minutes", Float),                         # 통화·면담 시간(분)
    Column("text_masked", Text, nullable=False),           # 개인정보(전화번호 등) 마스킹 후 원문
    Column("route", String(16), nullable=False, index=True),   # REJECTABLE | HANDLE | ESCALATE
    Column("route_label", String(100), nullable=False),
    Column("urgency", String(8), nullable=False),
    Column("department", String(40), nullable=False),
    Column("handler", String(100), nullable=False),
    Column("deadline", String(60), nullable=False),
    Column("excitement_score", Integer, nullable=False),
    Column("excitement_level", String(8), nullable=False),
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
class Author:
    name: str
    last4: str

    def display(self) -> str:
        return f"{self.name}(끝 {self.last4})"


def make_author(name, phone):
    """이름과 연락처로 작성자를 만든다. 둘 다 비면 None(작성자 미상). 연락처는 끝 4자리만 남긴다."""
    name = "".join((name or "").split())
    digits = re.sub(r"\D", "", phone or "")
    if not name and not digits:
        return None
    if not name or not digits:
        raise ValueError("작성자를 식별하려면 이름과 연락처 끝자리를 둘 다 입력해 주세요(둘 다 비우면 작성자 미상).")
    if len(digits) < 4:
        raise ValueError("연락처 끝자리는 숫자 4자리로 입력해 주세요.")
    return Author(name, digits[-4:])


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


def _snippet(text, n=60):
    return text[:n] + ("…" if len(text) > n else "")


class Store:
    def __init__(self, target=":memory:", window_days=180, recontact_hours=24):
        """target: DATABASE_URL, SQLite 파일 경로, 또는 ':memory:'.
        window_days: 반복·악성 이력을 세는 기간. 매뉴얼에 기간 규정은 없고, 지원 요청 보고서 작성 예시가 '6개월간'이다.
        recontact_hours: 종결 후 '바로' 연락이 온 것으로 보는 시간. 매뉴얼에 기준이 없어 임의로 정한 값이다."""
        url = _url(target)
        kw = {"poolclass": StaticPool, "connect_args": {"check_same_thread": False}} if url == "sqlite://" else {}
        self.engine = create_engine(url, **kw)
        self.window_days, self.recontact_hours = window_days, recontact_hours
        self._migrate_old_schema()
        meta.create_all(self.engine)       # 테이블이 없을 때만 만든다

    def _migrate_old_schema(self):
        """작성자를 label 한 칸으로 저장하던 이전 구조(complainants.label)를 만나면,
        민원이 하나도 없을 때만 새 구조로 다시 만든다. 데이터가 있으면 덮어쓰지 않고 멈춘다."""
        insp = inspect(self.engine)
        if not insp.has_table("complainants") or "name" in {c["name"] for c in insp.get_columns("complainants")}:
            return
        with self.engine.connect() as c:
            n = c.execute(text("SELECT COUNT(*) FROM complaints")).scalar() if insp.has_table("complaints") else 0
        if n:
            raise RuntimeError(f"DB가 이전 버전 구조이고 민원 {n}건이 들어 있어 자동으로 바꾸지 않았습니다. "
                               "DB 파일을 백업한 뒤 옮기거나 지우고 다시 실행해 주세요.")
        meta.drop_all(self.engine)         # 비어 있는 이전 구조 테이블만 지운다

    def find_history(self, author, text, now=None):
        """새 민원의 과거 이력. author가 None이면 작성자 이력은 비고, 다른 민원과의 유사도만 본다.

        반환: {"author": 작성자 요약|None,
               "same_author": 같은 작성자의 동일·유사 민원(기간 이내),
               "similar_others": 다른 작성자의 매우 유사한 민원(참고용),
               "recent_closed": 종결 직후 재접촉이면 그 종결 민원, 아니면 None,
               "prior_malicious": 같은 작성자의 악성 의심 민원 건수(기간 이내)}
        """
        now = now or _now()
        with self.engine.connect() as c:
            author_id = c.execute(select(complainants.c.id).where(
                complainants.c.name == author.name, complainants.c.phone_last4 == author.last4)).scalar() if author else None
            rows = c.execute(
                select(complaints, complainants.c.name.label("a_name"), complainants.c.phone_last4.label("a_last4"))
                .select_from(complaints.outerjoin(complainants, complaints.c.complainant_id == complainants.c.id))
                .where(complaints.c.created_at >= now - timedelta(days=self.window_days))
                .order_by(complaints.c.id.desc()).limit(SCAN_LIMIT)).mappings().all()
            summary = None
            if author_id:
                total, last = c.execute(select(func.count(), func.max(complaints.c.created_at))
                                        .where(complaints.c.complainant_id == author_id)).one()
                esc = c.execute(select(func.count()).where(complaints.c.complainant_id == author_id,
                                                           complaints.c.route == "ESCALATE")).scalar()
                summary = {"name": author.name, "last4": author.last4, "total": total, "escalated": esc,
                           "last_at": last.isoformat(timespec="minutes") if last else None}
        same, others, recent_closed, malicious = [], [], None, 0
        recontact_from = now - timedelta(hours=self.recontact_hours)
        for r in rows:
            sim = _jaccard(r["text_masked"], text)
            closed = r["route"] == "REJECTABLE" or bool(r["closed_by_repeat"])
            item = {"id": r["id"], "created_at": r["created_at"].isoformat(timespec="minutes"),
                    "author": f"{r['a_name']}(끝 {r['a_last4']})" if r["a_name"] else None,
                    "route": r["route"], "similarity": round(sim, 2), "snippet": _snippet(r["text_masked"]),
                    "closed": closed}
            if author_id and r["complainant_id"] == author_id:
                if r["route"] == "ESCALATE":
                    malicious += 1
                if closed and recent_closed is None and r["created_at"] >= recontact_from:
                    recent_closed = item
                if sim >= SAME_AUTHOR_SIM:
                    same.append(item)
            elif sim >= OTHER_AUTHOR_SIM:
                others.append(item)
        return {"author": summary, "same_author": same, "similar_others": others[:5],
                "recent_closed": recent_closed, "prior_malicious": malicious}

    def save(self, result, author=None, received_at=None, call_minutes=None, closed_by_repeat=False):
        """분류가 끝난 민원 1건을 저장하고 민원 번호(id)를 돌려준다. 작성자가 없으면 '작성자 미상'으로 저장한다."""
        now = _now()
        with self.engine.begin() as c:
            author_id = None
            if author:
                author_id = c.execute(select(complainants.c.id).where(
                    complainants.c.name == author.name, complainants.c.phone_last4 == author.last4)).scalar()
                if author_id is None:
                    author_id = c.execute(complainants.insert().values(
                        name=author.name, phone_last4=author.last4, created_at=now)).inserted_primary_key[0]
            cid = c.execute(complaints.insert().values(
                complainant_id=author_id,
                received_at=datetime.fromisoformat(received_at) if received_at else None,
                call_minutes=call_minutes, text_masked=result["text_masked"],
                route=result["route"], route_label=result["route_label"], urgency=result["urgency"],
                department=result["department"], handler=result["handler"], deadline=result["deadline"],
                excitement_score=result["excitement"]["score"], excitement_level=result["excitement"]["level"],
                repeat_count=result["repeat_count"],
                closed_by_repeat=closed_by_repeat,
                needs_human_review=result["needs_human_review"], llm_used=result["llm_used"],
                result_json=json.dumps(result, ensure_ascii=False), created_at=now)).inserted_primary_key[0]
            hits = [{"complaint_id": cid, "kind": h["kind"], "rule_key": h["key"], "label": h["label"],
                     "severity": h.get("severity")} for h in result["reject"] + result["malicious"]]
            if hits:
                c.execute(complaint_hits.insert(), hits)
        return cid
