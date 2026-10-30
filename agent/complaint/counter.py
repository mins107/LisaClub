"""공식 민원 접수 창구 안내 정보. 이 사이트가 공식 창구이고, 아래 연락처·운영시간·온라인 접수 주소는 임의로 정한 예시 값이다.
실제 학교 정보는 .env의 SCHOOL_PHONE, SCHOOL_HOURS, SCHOOL_ONLINE_URL로 바꾼다(운영시간은 rules.py의 업무시간 판정 8~17시와 맞춘다)."""
import os

from . import settings  # noqa: F401  .env를 먼저 읽는다


def info():
    return {
        "phone": os.environ.get("SCHOOL_PHONE", "").strip() or "02-1234-5678",
        "hours": os.environ.get("SCHOOL_HOURS", "").strip() or "평일 08:00~17:00",
        "online": os.environ.get("SCHOOL_ONLINE_URL", "").strip() or "https://school.example.kr/complaint",
    }


def phone_line():
    c = info()
    return f"학교 대표번호 {c['phone']}({c['hours']})"


def online_line():
    c = info()
    return f"온라인 민원 접수 {c['online']}(24시간 접수, 처리는 업무시간 중)"


def full_line():
    return f"{phone_line()} 또는 {online_line()}"
