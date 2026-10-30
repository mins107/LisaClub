"""학사일정 문의 민원: 나이스(NEIS) 교육정보 개방 포털 '학사일정' API로 일정을 조회해 답변 초안을 만든다.

답변의 날짜는 API 응답에 있는 값만 쓴다(LLM이 날짜를 만들지 않는다). 인증키·교육청 코드·학교 코드가 없으면
조회하지 않고 '설정 필요' 안내만 남기며, 일반 처리 초안을 그대로 쓴다.
"""
import calendar
import json
import re
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta

API_URL = "http://open.neis.go.kr/hub/SchoolSchedule"
SOURCE = "나이스 교육정보 개방 포털 학사일정(SchoolSchedule)"
WEEKDAY = "월화수목금토일"

# 민원에 나온 말 -> 학사일정 행사명(EVENT_NM)에서 찾을 말
TERMS = {
    "중간고사": ["중간고사", "지필평가", "지필"], "기말고사": ["기말고사", "지필평가", "지필"],
    "시험": ["고사", "지필평가", "지필", "시험"], "고사": ["고사", "지필평가", "지필"],
    "방학": ["방학"], "개학": ["개학", "개교"], "종업식": ["종업식"], "졸업식": ["졸업"], "입학식": ["입학"],
    "시업식": ["시업", "개학"],
    "체험학습": ["체험학습", "현장학습", "수학여행", "소풍"], "현장학습": ["체험학습", "현장학습", "수학여행", "소풍"],
    "수학여행": ["수학여행"], "소풍": ["소풍", "체험학습"], "운동회": ["운동회", "체육대회", "체육한마당"],
    "체육대회": ["체육대회", "운동회", "체육한마당"], "축제": ["축제", "문화예술", "발표회"],
    "학예회": ["학예", "발표회"], "공개수업": ["공개수업", "수업공개", "참관"], "학부모 총회": ["총회"],
    "상담주간": ["상담"], "재량휴업": ["재량휴업"], "휴업일": ["휴업"], "공휴일": ["공휴일", "휴업"],
    "쉬는 날": ["휴업", "공휴일"], "쉬는날": ["휴업", "공휴일"], "단축수업": ["단축"],
}
CUE = re.compile(r"(언제|일정|날짜|며칠|몇\s*일|기간|쉬나요|쉬는|있나요|인가요|하나요|궁금|알려)")
GRADE_FIELD = {"1": "ONE_GRADE_EVENT_YN", "2": "TW_GRADE_EVENT_YN", "3": "THREE_GRADE_EVENT_YN",
               "4": "FR_GRADE_EVENT_YN", "5": "FIV_GRADE_EVENT_YN", "6": "SIX_GRADE_EVENT_YN"}


class SchoolCalendar:
    def __init__(self, key="", office_code="", school_code="", timeout=10):
        self.key, self.office, self.school, self.timeout = key, office_code, school_code, timeout
        self._cache = {}

    @classmethod
    def from_settings(cls, s):
        return cls(s.neis_api_key, s.neis_office_code, s.neis_school_code)

    @property
    def configured(self):
        return bool(self.key and self.office and self.school)

    def fetch(self, start, end):
        """start~end(date) 학사일정 행 목록. 데이터가 없으면 []. 실패하면 예외."""
        ck = (start, end)
        if ck in self._cache:
            return self._cache[ck]
        q = {"KEY": self.key, "Type": "json", "pIndex": 1, "pSize": 1000,
             "ATPT_OFCDC_SC_CODE": self.office, "SD_SCHUL_CODE": self.school,
             "AA_FROM_YMD": start.strftime("%Y%m%d"), "AA_TO_YMD": end.strftime("%Y%m%d")}
        with urllib.request.urlopen(f"{API_URL}?{urllib.parse.urlencode(q)}", timeout=self.timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
        rows = _rows(data)
        self._cache[ck] = rows
        return rows


def _rows(data):
    """API 응답(JSON)에서 행 목록을 꺼낸다. 데이터 없음(INFO-200)은 [], 그 밖의 오류 코드는 예외."""
    if "RESULT" in data:
        code = data["RESULT"].get("CODE", "")
        if code == "INFO-200":
            return []
        raise RuntimeError(f"NEIS 응답 오류 {code}")
    for block in data.get("SchoolSchedule", []):
        if "row" in block:
            return block["row"]
    return []


def find_terms(text):
    """민원에 나온 학사일정 말 -> 행사명 검색어 목록."""
    names, seen = [], set()
    for term, keys in TERMS.items():
        if term in text:
            for k in keys:
                if k not in seen:
                    seen.add(k)
                    names.append(k)
    return names


def date_range(text, today):
    """민원에서 조회 기간을 읽는다. 반환: (시작, 끝, 명시 여부). 없으면 오늘부터 180일."""
    m = re.search(r"(\d{1,2})\s*월\s*(\d{1,2})\s*일", text)
    if m:
        mo, d = int(m.group(1)), int(m.group(2))
        try:
            day = date(today.year if (mo, d) >= (today.month, today.day) else today.year + 1, mo, d)
            return day, day, True
        except ValueError:
            pass
    m = re.search(r"(\d{1,2})\s*월", text)
    if m and 1 <= int(m.group(1)) <= 12:
        mo = int(m.group(1))
        y = today.year if mo >= today.month else today.year + 1
        return date(y, mo, 1), date(y, mo, calendar.monthrange(y, mo)[1]), True
    monday = today - timedelta(days=today.weekday())
    if "다음 주" in text or "다음주" in text:
        return monday + timedelta(days=7), monday + timedelta(days=13), True
    if "이번 주" in text or "이번주" in text:
        return monday, monday + timedelta(days=6), True
    for word, shift in (("이번 달", 0), ("이번달", 0), ("다음 달", 1), ("다음달", 1)):
        if word in text:
            y, mo = today.year + (today.month - 1 + shift) // 12, (today.month - 1 + shift) % 12 + 1
            return date(y, mo, 1), date(y, mo, calendar.monthrange(y, mo)[1]), True
    if "내일" in text:
        return today + timedelta(days=1), today + timedelta(days=1), True
    if "오늘" in text:
        return today, today, True
    return today, today + timedelta(days=180), False


def is_schedule_inquiry(text):
    """학사일정을 묻는 민원인가. 행사 말(또는 '일정'+기간)과 질문 표현이 함께 있어야 한다."""
    if not CUE.search(text):
        return False
    return bool(find_terms(text)) or ("일정" in text and date_range(text, date.today())[2])


def _grade_of(student):
    return student.class_no[0] if student else None


def _applies(row, grade):
    if not grade or grade not in GRADE_FIELD:
        return True
    flags = [row.get(f) for f in GRADE_FIELD.values()]
    if "Y" not in flags:                    # 학년 표시가 없으면 전교 행사로 본다
        return True
    return row.get(GRADE_FIELD[grade]) == "Y"


def _fmt_day(ymd):
    d = datetime.strptime(ymd, "%Y%m%d").date()
    return f"{d.year}년 {d.month}월 {d.day}일({WEEKDAY[d.weekday()]})"


def _merge(rows):
    """같은 행사명이 연속한 날짜에 걸리면 기간 하나로 합친다."""
    out = []
    for r in sorted(rows, key=lambda r: (r["EVENT_NM"], r["AA_YMD"])):
        d = datetime.strptime(r["AA_YMD"], "%Y%m%d").date()
        if out and out[-1]["name"] == r["EVENT_NM"] and (d - out[-1]["_end"]).days == 1:
            out[-1]["end"], out[-1]["_end"] = r["AA_YMD"], d
        else:
            out.append({"name": r["EVENT_NM"], "start": r["AA_YMD"], "end": r["AA_YMD"], "_end": d,
                        "content": r.get("EVENT_CNTNT") or "", "day_type": r.get("SBTR_DD_SC_NM") or ""})
    for e in out:
        del e["_end"]
    return sorted(out, key=lambda e: e["start"])


def _reply(events, rng, explicit):
    lines = ["안녕하세요. 문의해 주셔서 감사합니다. 문의하신 학사일정을 안내해 드립니다.", ""]
    for e in events[:8]:
        span = _fmt_day(e["start"]) + (f" ~ {_fmt_day(e['end'])}" if e["end"] != e["start"] else "")
        tag = f" [{e['day_type']}]" if e["day_type"] and e["day_type"] != "해당없음" else ""
        lines.append(f"- {span}: {e['name']}{tag}")
    if len(events) > 8:
        lines.append(f"- 그 밖에 {len(events) - 8}건이 더 있습니다.")
    lines += ["", "학사일정은 학교 사정에 따라 바뀔 수 있으니, 변경 사항은 학교 안내문(홈페이지·알림장)을 함께 확인해 주시기 바랍니다.",
              f"출처: {SOURCE}"]
    return "\n".join(lines)


def answer(text, student, cal, today=None):
    """학사일정 문의면 {status, reply, events, ...}, 아니면 None.

    status: ok(일정 찾음) / no_match(조회했으나 해당 일정 없음) / not_configured(API 설정 없음) / error(조회 실패)."""
    if not is_schedule_inquiry(text):
        return None
    today = today or date.today()
    start, end, explicit = date_range(text, today)
    names = find_terms(text)
    out = {"status": "not_configured", "source": SOURCE, "range": [start.isoformat(), end.isoformat()],
           "keywords": names, "events": [], "reply": None, "message": None}
    if not cal or not cal.configured:
        out["message"] = ".env에 NEIS_API_KEY, NEIS_OFFICE_CODE, NEIS_SCHOOL_CODE를 넣으면 학사일정으로 직접 답변 초안을 만듭니다."
        return out
    try:
        rows = cal.fetch(start, end)
    except Exception as e:  # noqa: BLE001  키가 담긴 주소가 로그에 남지 않도록 종류만 적는다
        out.update(status="error", message=f"학사일정 조회에 실패했습니다({type(e).__name__}). 일반 초안을 사용합니다.")
        return out
    grade = _grade_of(student)
    rows = [r for r in rows if _applies(r, grade) and r.get("EVENT_NM")]
    if names:
        rows = [r for r in rows if any(n in r["EVENT_NM"] or n in (r.get("EVENT_CNTNT") or "") for n in names)]
    events = _merge(rows)
    if not events:
        out.update(status="no_match", message="조회한 기간에 해당하는 학사일정이 없습니다. 일반 초안을 사용합니다.")
        return out
    out.update(status="ok", events=events[:20], reply=_reply(events, (start, end), explicit),
               message=f"학사일정 API 조회 결과 {len(events)}건" + (f" ({grade}학년 해당 행사)" if grade else ""))
    return out
