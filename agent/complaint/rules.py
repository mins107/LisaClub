"""규칙 기반 판정. 모든 규칙은 매뉴얼 문구(anchor)와 연결되어 근거 검색에 쓰인다.

이 판정은 후보 제시용이며 최종 결정은 학교장(민원대응팀)이 한다.
정규식은 시작점일 뿐이므로 실제 민원 라벨 데이터로 정밀도와 재현율을 평가해야 한다.
"""
import re
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Rule:
    key: str
    label: str
    kind: str          # reject | malicious
    pattern: str
    anchor: str        # 매뉴얼에서 근거를 찾기 위한 질의(매뉴얼 표현 그대로)
    severity: int = 0  # 악성 유형의 위험도 1~5
    confident: bool = True


REJECT = [
    Rule("personal_contact", "교직원 개인 연락처·SNS로 제기", "reject",
         r"(개인 ?(휴대)?(전화|폰|번호)|사적인? ?번호|카카오톡|카톡|인스타|디엠|\bDM\b|SNS|밴드로)",
         "교직원 개인 휴대전화 또는 SNS로 민원을 제기하는 경우 거부가능"),
    Rule("private_life", "교직원 사생활 등 교육활동과 무관", "reject",
         r"(사생활|결혼|이혼|연애|남자 ?친구|여자 ?친구|나이가 ?몇|사는 ?곳|집 ?주소|사적인 ?(부탁|용무))",
         "교직원의 사생활 등 교육활동과 무관한 민원을 제기하는 경우"),
    Rule("personnel", "교직원 인사행정 사항 요구", "reject",
         r"(징계|파면|해임|해고|직위해제|전보|인사 ?조치|처벌해|그만두게|잘라)",
         "학교 소속 직원에 대한 인사행정상의 행위에 관한 사항을 요구하는 경우"),
    Rule("beyond_duty", "직무 범위 외·위법·부당 요구", "reject",
         r"(성적.{0,6}(올려|고쳐|바꿔)|점수.{0,6}(올려|고쳐|바꿔)|생활기록부.{0,8}(고쳐|지워|삭제)|봐 ?줘|봐 ?달라|특혜|특별히)",
         "교직원의 직무 범위 외 사항 및 위법 부당한 사항을 요구하는 경우", 0, False),
    Rule("ongoing_remedy", "불복 구제·조정 절차 진행 중", "reject",
         r"(소송|행정심판|재판|고소했|학폭위|심의위원회|조정 ?(중|신청)|재심)",
         "관련 법령에 따라 불복 구제 절차가 진행 중이거나 당사자 간 이해조정을 목적으로 하는 절차가 진행 중인 경우",
         0, False),
    Rule("anonymous", "성명·주소 불명확", "reject",
         r"(익명|이름은 ?(말|밝힐)|누군지 ?(는)? ?(말|밝)|성함은 ?(안|못))",
         "성명 주소 등이 불명확한 경우"),
]

MALICIOUS = [
    Rule("abuse", "폭언(욕설)", "malicious",
         r"(씨발|시발|ㅅㅂ|ㅆㅂ|(개|이)새끼|병신|븅신|ㅂㅅ|미친(놈|년|새끼)?|지랄|ㅈㄹ|좆|꺼져|닥쳐|썅)",
         "욕설 단순폭언 비속어 저속한 언어 등 직접적인 욕을 하는 것", 3),
    Rule("insult", "모욕", "malicious",
         r"(무능|자격(이)? ?(도)? ?없|한심|쓰레기|월급 ?도둑|밥버러지|꼴값|교사 ?(자격|할 ?자격))",
         "외모 신체 비하 등 담당자 인격을 부정하는 모욕적 발언", 3),
    Rule("threat", "협박", "malicious",
         r"(죽여|죽이겠|죽어버|가만(히)? ?(안|두지)|각오(해|하)|끝장|인생.{0,6}(망|끝)|두고 ?보|해코지|혼쭐|찾아가(서|겠)|퇴근길|"
         r"(언론|기자|맘카페|커뮤니티).{0,10}(터뜨|폭로|올리|알리))",
         "담당자에게 해악을 끼칠 것을 예고하며 공포심을 조장하는 행위", 4),
    Rule("sexual", "성희롱", "malicious",
         r"(몸매|예쁘|섹시|사귀|애인|만나자|(밤|술).{0,6}(만나|한잔)|야한|가슴|엉덩)",
         "담당자에게 성적 언동 등 통해 성적 굴욕감 등을 느끼게 하는 행위", 4),
    Rule("assault", "폭행", "malicious",
         r"(때리|때렸|때릴|멱살|밀쳤|밀치|뺨|주먹|발로 ?(찼|차)|폭행)",
         "담당자에게 물리적인 폭력을 사용하는 행위", 5),
    Rule("damage", "기물파손", "malicious",
         r"(부수|부쉈|집어 ?던|엎었|파손|박살)",
         "서류나 집기 등 공적 기물을 파손하는 행위", 4),
    Rule("weapon", "위험물 소지", "malicious",
         r"(흉기|휘발유|폭탄|도끼|몽둥이|식칼|(?<![가-힣])칼(을|로|이|도)?(?![가-힣])|(?<![가-힣])총(을|으로)?(?![가-힣]))",
         "무기 흉기 폭발물 등 위험한 물건의 소지", 5),
    Rule("stalking", "스토킹", "malicious",
         r"((계속|매일|수십|수차례).{0,8}(전화|연락|찾아|문자)|집 ?앞|교문 ?앞.{0,6}(기다|서 ?있)|따라다니)",
         "담당자 의사에 반하여 지속 반복적으로 접근하기 직장 주거지 등 찾아오기 전화 문자 등 반복 행위", 4),
    Rule("doxxing", "신상공개", "malicious",
         r"((실명|전화번호|사진|이름).{0,12}(올리|올릴|올려|공개|유포|퍼뜨|돌리)|(단톡|맘카페|오픈채팅|커뮤니티).{0,12}(공유|올리|올릴|올려|퍼뜨|돌리))",
         "SNS 인터넷 등에 담당자 명예훼손 정보 또는 담당자 개인 정보를 공개하는 행위", 4),
    Rule("unjust", "부당요구", "malicious",
         r"(담임.{0,6}(바꿔|교체)|성적.{0,6}(올려|고쳐)|생활기록부.{0,8}(고쳐|지워)|손해 ?배상.{0,8}선생님|선생님.{0,6}사비)",
         "담당자에게 위법하거나 사회통념상 부당한 행위를 강요하는 행위", 2, False),
]

EXCITED_WORDS = r"(어이없|황당|분통|당장|책임지|항의|화가|열받|최악|말이 ?돼|도대체|가만)"

DEPT = {
    "교무/학사": r"(성적|수행평가|시험|학사일정|출결|결석|생활기록부|생기부|전학|졸업|증명서|시간표|교육과정|방학|조퇴|체험학습)",
    "생활지도/상담": r"(학폭|학교폭력|따돌|괴롭|싸움|친구|상담|생활지도|훈육|벌점|왕따|정서|아이가 ?(울|힘들))",
    "학부모/교직원 소통": r"(면담|통화|연락|문자|카톡|회신|답장|답이 ?없|알림장)",
    "학교 운영": r"(급식|시설|통학|CCTV|방과후|돌봄|행사|운영위|예산|안전|냉난방|에어컨|건의|개선)",
}


def _spans(rules, text):
    hits = []
    for r in rules:
        ms = list(re.finditer(r.pattern, text))
        if ms:
            hits.append((r, [(m.start(), m.end()) for m in ms], ms[0].group(0)))
    return hits


def detect_reject(text, received_at=None, call_minutes=None, repeat_count=1):
    hits = _spans(REJECT, text)
    extra = []
    if received_at:
        dt = datetime.fromisoformat(received_at)
        if dt.weekday() >= 5 or not (8 <= dt.hour < 17):
            extra.append(Rule("after_hours", "업무시간 외 연락", "reject", "", "업무시간 외 연락하는 경우"))
    if call_minutes and call_minutes >= 20:
        extra.append(Rule("long_call", "권장 시간(20분) 초과", "reject", "",
                          "정당한 사유 없이 권장 시간(20분)을 초과하여 상담 면담이 지속되는 경우"))
    if repeat_count >= 3:
        extra.append(Rule("repeat", f"동일·유사 민원 {repeat_count}회 반복", "reject", "",
                          "합리적인 답변에도 불구하고 동일한 내용의 민원을 정당한 사유 없이 3회 이상 지속적 반복적으로 제기하는 경우"))
    return hits + [(r, [], r.label) for r in extra]


def detect_malicious(text, repeat_count=1):
    hits = _spans(MALICIOUS, text)
    if repeat_count >= 3:
        r = Rule("repeat_m", "반복형 부당민원", "malicious", "",
                 "적절한 민원 처리가 완료되었으나 정당한 사유 없이 반복적으로 전화 면담 요구", 2)
        hits.append((r, [], f"{repeat_count}회 반복"))
    return hits


def excitement(text, malicious_hits):
    ex = min(text.count("!"), 5)
    q = min(text.count("?"), 4)
    emo = len(re.findall(EXCITED_WORDS, text))
    swear = sum(1 for r, _, _ in malicious_hits if r.key in ("abuse", "insult", "threat"))
    loud = len(re.findall(r"(ㅡㅡ|;;|!{2,}|\?{2,}|ㅠㅠ{2,})", text))
    score = min(100, ex * 8 + q * 4 + emo * 10 + swear * 25 + loud * 10)
    level = "고위험" if score >= 55 else "주의" if score >= 25 else "낮음"
    return score, level


def urgency(malicious_hits, level):
    sev = max([r.severity for r, _, _ in malicious_hits], default=0)
    order = ["낮음", "보통", "높음", "긴급"]
    base = 3 if sev >= 5 else 2 if sev >= 3 else 1 if sev >= 2 else 0
    if level == "고위험":
        base = min(3, base + 1)
    return order[base]


def department(text):
    scores = {k: len(re.findall(p, text)) for k, p in DEPT.items()}
    best = max(scores, key=scores.get)
    return (best if scores[best] > 0 else "기타"), scores
