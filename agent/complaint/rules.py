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

GRADE_TEMPLATE = "학년부"          # 학생 학년에 따라 1·2·3학년부로 바뀐다(classify_department)
GRADE_DEPTS = ["1학년부", "2학년부", "3학년부"]
GRADE_UNKNOWN = "학년부(학년 확인 필요)"


def grade_department(class_no):
    """학년반(305 등)의 학년에 맞는 학년부 이름. 학생을 모르면 None."""
    g = (class_no or "")[:1]
    return f"{g}학년부" if g in ("1", "2", "3") else None


# 담당 부서(학교 내부 부서 체계). desc는 부서 업무 설명, kw는 민원에서 찾을 말, check는 담임 교사 전달문에 쓰는 확인 사항(권장 문구).
DEPARTMENTS = [
    {"name": "교무기획부", "desc": "학사행정·교무 운영, 교원 인사, 학적·출결, 학교생활기록부, 학교행사·학교평가·교육행정",
     "kw": r"(출결|출석|결석|지각|조퇴|결과 처리|학적|전학|전입|전출|졸업|입학|증명서|생활기록부|생기부|학사일정|학교 ?행사|행사|체험학습|수학여행|"
           r"학교평가|개학|방학|담임.{0,8}(교체|변경|배정|바꿔)|교원 ?(인사|전보)|교사 ?(교체|인사|전보))",
     "check": "출결·학적·생활기록부 등 학사 기록과 해당 행사·일정 현황을 확인해 주세요"},
    {"name": "교수학습지원부", "desc": "교수학습 개선·학력 향상, 정기고사·성적 평가·학업성적 관리, 방과후학교, 기초학력 보장, 교사 전문성 개발",
     "kw": r"(성적|수행평가|정기고사|중간고사|기말고사|지필|시험|채점|이의 ?신청|내신|등급|서술형|방과후|기초학력|보충 ?수업|학력|평가 기준|수업 방식)",
     "check": "해당 평가의 채점 기준과 성적 처리 기록을 확인해 주세요"},
    {"name": "고교학점제운영부", "desc": "고교학점제·교육과정 편성·운영, 선택과목·수업시간표·교과별 시수, 공동교육과정·자율적 교육과정·공강 프로그램",
     "kw": r"(학점제|선택 ?과목|수강 ?신청|수강|교육과정|시간표|공강|공동교육과정|이수 ?(학점|과목|기준|여부|조건)|미이수|시수|과목 ?개설|개설 ?과목|수업 ?시수)",
     "check": "학생의 선택과목·시간표·이수 현황을 확인해 주세요"},
    {"name": "학생생활안전부", "desc": "생활교육·학교 안전관리, 학교폭력 예방·사안 처리, 학생선도·학생자치활동, 위기학생 관리, 맞춤통합지원·안전교육",
     "kw": r"(학교폭력|학폭|따돌|왕따|괴롭|싸움|폭행|선도|벌점|생활교육|생활지도|훈육|흡연|안전사고|안전|위기|학생회|학생자치|CCTV|통학로|등하교|횡단보도|신호등|교통|스쿨존|위험|임원|선거|다퉈|다퉜|다툼|혼냈|혼났|혼내|체벌|욕설|욕했|스마트폰|복장|두발|휴대폰|핸드폰)",
     "check": "학생의 교우 관계와 생활 상황, 이전 지도·상담 내용을 확인해 주세요"},
    {"name": "교육정보부", "desc": "학교 정보화·디지털 교육환경, 개인정보보호·정보보안·ICT 활용교육, 교육용 기자재·스마트기기·학내망·서버",
     "kw": r"(와이파이|wifi|인터넷|컴퓨터|태블릿|노트북|스마트 ?기기|기자재|서버|개인정보|정보 ?보안|ICT|온라인 ?수업|학습터|클래스룸|홈페이지|계정|비밀번호|프로젝터|전자칠판|디지털)",
     "check": "관련 기기·계정·시스템 현황과 개인정보 처리 여부를 확인해 주세요"},
    {"name": "창의진로상담부", "desc": "진로탐색·진학설계, 진로진학상담·진로체험·대학 진학 프로그램, 심리·정서 상담, 학업중단 예방, 특수교육",
     "kw": r"(진로|진학|입시|대입|수시|정시|대학|진로체험|상담|심리|정서|우울|불안|학업 ?중단|자퇴|특수 ?교육|특수 ?학급|학교 ?적응|가기 ?싫|등교 ?거부|무기력|스트레스|힘들어|힘들다|수능)",
     "check": "학생의 진로·상담 기록과 정서 상태를 확인해 주세요"},
    {"name": "인문사회교육부", "desc": "인문사회교육·시민의식 함양, 독서·토론교육·인문학 프로그램·도서관, 외국어교육·교과서 관리·교원 연수",
     "kw": r"(도서관|독서|토론|인문|시민교육|시민의식|교과서|외국어|원어민|영어 ?회화|논술|연수)",
     "check": "관련 프로그램·도서관·교과서 운영 현황을 확인해 주세요"},
    {"name": "자연과학교육부", "desc": "수학·과학교육·탐구활동, 수학·과학 행사·탐구 프로젝트·영재교육, 과학실험실 운영·실험 안전·생태환경교육",
     "kw": r"(실험|과학실|실험실|탐구|영재|수학 ?경시|과학 ?행사|과학의 날|생태|환경 ?교육|화학 ?물질|약품)",
     "check": "관련 탐구·실험 활동과 안전 관리 현황을 확인해 주세요"},
    {"name": "예체능교육부", "desc": "예술·체육교육·학생 건강 증진, 동아리·학예제·문화예술행사·스포츠활동, 보건교육·감염병 예방·건강관리",
     "kw": r"(동아리|학예제|축제|체육대회|운동회|체육|음악|미술|예술|보건 ?교육|스포츠|문화예술)",
     "check": "관련 활동·행사 운영 현황을 확인해 주세요"},
    {"name": "행정실", "desc": "학교 시설·설비 관리, 예산·회계·계약, 학교비용(수업료·납부금·환불), 물품·재산 관리, 통학버스·주차·청소 등 학교 운영 지원",
     "kw": r"(시설|설비|냉난방|에어컨|히터|난방|화장실|고장|수리|공사|누수|청소|주차|통학버스|예산|회계|계약|납부|수업료|환불|비용|교복|졸업앨범|전기|소음|물품|비품|증명서 ?발급 ?수수료)",
     "check": "관련 시설·비용·물품 현황을 확인해 주세요"},
    {"name": "보건실", "desc": "학생 건강관리·응급처치, 질병·부상 대응, 감염병 예방·관리, 건강검진·투약 지원",
     "kw": r"(보건실|보건 ?선생|양호|응급|투약|건강 ?검진|건강검진|감염|독감|코로나|수족구|아파|아프|다쳤|다쳐|부상|열이|두통|복통|병원|질병|진단서)",
     "check": "학생의 건강 상태와 보건실 이용·응급처치 기록을 확인해 주세요"},
    {"name": "급식실", "desc": "급식 운영·식단 관리, 영양·위생 관리, 알레르기 식단 대응, 급식비 지원",
     "kw": r"(급식|식단|메뉴|영양|알레르기|도시락|식중독|배식|잔반|급식비|조리|반찬)",
     "check": "식단·배식·알레르기 대응 기록을 확인해 주세요"},
    {"name": GRADE_TEMPLATE, "desc": "학년 단위 학급 운영·담임 교사 협조, 학년 행사·학년 생활지도 조정, 담임 교사 등 학년 소속 교사의 언행·수업 태도 관련 민원 (업무 설명은 일반적인 학년부 업무 기준)",
     "kw": r"(담임|(?<!특수)(?<!특수 )학급|우리 반|아침 ?조회|종례|조례|자리 ?(배치|바꿈|바꾸)|학년 ?(운영|행사|부)|"
           r"(선생님|교사).{0,15}(소리|화를|화내|욕|막말|차별|편애|불친절|태도|언행|체벌|때렸|무시|비교))",
     "check": "담임 교사에게 사실관계를 확인하고 학년부에 공유해 주세요"},
]
UNASSIGNED = "미분류(부서 확인 필요)"
DEPT_DESC = {d["name"]: d["desc"] for d in DEPARTMENTS if d["name"] != GRADE_TEMPLATE}
DEPT_DESC.update({n: next(d["desc"] for d in DEPARTMENTS if d["name"] == GRADE_TEMPLATE) for n in GRADE_DEPTS + [GRADE_UNKNOWN]})
DEPT_NAMES = [d["name"] for d in DEPARTMENTS if d["name"] != GRADE_TEMPLATE] + GRADE_DEPTS + [GRADE_UNKNOWN, UNASSIGNED]
# 점수가 같을 때 앞선 부서를 택한다(안전·학교폭력 > 건강 > 성적 > 학사 ...).
_TIE_ORDER = ["학생생활안전부", "보건실", "급식실", "교수학습지원부", "고교학점제운영부", "교육정보부", "행정실", "교무기획부", GRADE_TEMPLATE, "창의진로상담부",
              "자연과학교육부", "인문사회교육부", "예체능교육부"]


def _spans(rules, text):
    hits = []
    for r in rules:
        ms = list(re.finditer(r.pattern, text))
        if ms:
            hits.append((r, [(m.start(), m.end()) for m in ms], ms[0].group(0)))
    return hits


def detect_reject(text, received_at=None, call_minutes=None, repeat_count=1, recontact=False):
    hits = _spans(REJECT, text)
    extra = []
    if recontact:
        extra.append(Rule("recontact", "종결 직후 재접촉", "reject", "",
                          "종결 민원으로 종결하였으나 바로 연락이 오는 등 특이민원이 계속 예상되는 경우", 0, False))
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


def urgency(malicious_hits):
    """악성(특이) 유형의 가장 높은 심각도로 정한다: 5 -> 긴급, 3~4 -> 높음, 2 -> 보통, 그 외 낮음."""
    sev = max([r.severity for r, _, _ in malicious_hits], default=0)
    order = ["낮음", "보통", "높음", "긴급"]
    return order[3 if sev >= 5 else 2 if sev >= 3 else 1 if sev >= 2 else 0]


def classify_department(text, class_no=None):
    """민원 내용에서 부서별 키워드를 세어 담당 부서를 정한다.
    반환: {name, matched, scores, candidates, reason, keywords}. keywords는 어느 부서 것이든 민원에 걸린 모든 키워드(시즌 분석용).
    걸린 말이 없으면 UNASSIGNED. 점수가 같으면 _TIE_ORDER가 앞선 부서.
    학년부 업무에 걸리면 학생의 학년에 맞는 1·2·3학년부로, 학생을 모르면 GRADE_UNKNOWN으로 정한다."""
    grade = grade_department(class_no) or GRADE_UNKNOWN
    rename = lambda n: grade if n == GRADE_TEMPLATE else n  # noqa: E731
    found = {}
    for d in DEPARTMENTS:
        kws = [m.group(0) for m in re.finditer(d["kw"], text, re.I)]
        if kws:
            found[d["name"]] = kws
    allkw = list(dict.fromkeys("".join(k.split()).lower() for ks in found.values() for k in ks))
    scores = {n: len(k) for n, k in found.items()}
    if not scores:
        return {"name": UNASSIGNED, "matched": [], "scores": {}, "candidates": [], "keywords": [],
                "reason": "민원에서 부서 업무와 맞는 표현을 찾지 못했습니다. 담당 부서를 직접 정해 주세요."}
    best = max(scores, key=lambda n: (scores[n], -_TIE_ORDER.index(n)))
    uniq = lambda xs: list(dict.fromkeys(xs))  # noqa: E731
    cands = [{"name": rename(n), "score": scores[n], "matched": uniq(found[n])[:4]}
             for n in sorted(scores, key=lambda n: (-scores[n], _TIE_ORDER.index(n)))][:3]
    name = rename(best)
    return {"name": name, "matched": uniq(found[best])[:4], "scores": {rename(n): v for n, v in scores.items()},
            "candidates": cands, "keywords": allkw,
            "reason": f"민원의 '{', '.join(uniq(found[best])[:4])}' → {name}: {DEPT_DESC[name]}"}


def department(text, class_no=None):
    r = classify_department(text, class_no)
    return r["name"], r["scores"]
