"""민원 내용에서 작성자(이름, 연락처 끝 4자리)를 찾는다. 입력 폼을 미리 채워 주는 용도이며 최종 확인은 사람이 한다.

틀린 작성자로 이력이 연결되는 것을 막기 위해 정확도를 우선한다.
- 이름은 "성명: 홍길동", "민원인 홍길동", "저는 홍길동입니다"처럼 작성자임이 드러난 표현에서만 찾는다.
  "박지민 어머니"처럼 관계 표현 앞의 이름은 학생 이름일 수 있어서 찾지 않는다.
- 연락처는 전화번호(010-1234-5678)나 "끝자리 1234", "뒷번호 1234" 표현에서 끝 4자리만 가져온다.
- 후보가 여럿이면 가장 먼저 나온 것을 쓰고, 못 찾으면 빈 문자열을 돌려준다.
"""
import re

# 흔한 성씨와 두 글자 성씨. 이름 후보의 첫 글자(또는 앞 두 글자)가 여기에 있어야 이름으로 본다.
SURNAMES = set("김이박최정강조윤장임한오서신권황안송류유홍전고문양손배백허남심노하곽성차주우구민나진지엄채원천방공현함변염여추도소석선설마길연위표명기반왕금옥육인맹제모탁국은편용예경봉사부")
COMPOUND = ("남궁", "황보", "제갈", "선우", "독고", "사공", "서문", "어금", "동방")
# 성씨로 시작하지만 이름이 아닌 흔한 단어
NOT_NAMES = {"정말", "한번", "조금", "주말", "신경", "안녕", "오늘", "서로", "전화", "이번", "이게", "이런", "이것", "하지",
             "우리", "나중", "고객", "유독", "문의", "문제", "도움", "주변", "이후", "가족", "사실", "신청", "성함", "이름"}

# 이름 바로 뒤에 올 수 있는 것. 조사(이/가/은/는)는 "박지은"처럼 이름 끝 글자와 구분할 수 없어서 넣지 않는다.
_END = r"(?=님|씨|께서|입니다|이에요|예요|이고|이라고|라고|이며|[^가-힣]|$)"
_NAME = r"([가-힣]{2,4}?)"
# 라벨형: "성명: 홍길동", "민원인 홍길동 님", "이름은 홍길동입니다"
_LABELED = re.compile(r"(?:성함|성명|이름|민원인|작성자|신청인|보호자\s*(?:성함|성명|이름))\s*(?:은|는|이|가)?\s*[:：\-]?\s*" + _NAME + _END)
# 자기소개형: "저는 홍길동입니다", "제 이름은 홍길동이에요"
_SELF = re.compile(r"(?:저는|저의\s*이름은|제\s*이름은)\s*" + _NAME + r"\s*(?=입니다|이에요|예요|이라고|라고|이고|입니다만)")

_PHONE = re.compile(r"01[016789][-\s.]?\d{3,4}[-\s.]?(\d{4})(?!\d)")
_TAIL = re.compile(r"(?:끝|뒷)\s*(?:자리|번호|4자리|네\s*자리)\s*(?:는|은|가|이|:|：)?\s*(\d{4})(?!\d)")


def _is_name(w):
    if not (2 <= len(w) <= 4) or w in NOT_NAMES:
        return False
    return w[0] in SURNAMES or w.startswith(COMPOUND)


def _find_name(text):
    for rx in (_LABELED, _SELF):
        for m in rx.finditer(text):
            if _is_name(m.group(1)):
                return m.group(1), m.group(0).strip()
    return "", ""


def _find_phone(text):
    for rx in (_PHONE, _TAIL):
        m = rx.search(text)
        if m:
            return m.group(1), m.group(0).strip()
    return "", ""


def extract_author(text):
    """반환: {"name": 이름|"", "phone_last4": 끝 4자리|"", "found": ["이름: ... (근거: '...')", ...]}"""
    text = text or ""
    name, name_src = _find_name(text)
    last4, phone_src = _find_phone(text)
    found = []
    if name:
        found.append(f"이름 {name} (근거: '{name_src}')")
    if last4:
        found.append(f"연락처 끝 {last4} (근거: '{phone_src}')")
    return {"name": name, "phone_last4": last4, "found": found}
