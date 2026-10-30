"""환경 변수 설정. 모두 선택 사항이며 없으면 규칙 기반 모드로 동작한다."""
import os
from dataclasses import dataclass

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


@dataclass
class Settings:
    llm_base_url: str
    llm_model: str
    llm_api_key: str
    embed_model: str      # 빈 문자열이면 BM25만 사용
    manual_pdf: str
    database_url: str     # SQLAlchemy 접속 주소 또는 SQLite 파일 경로
    history_window_days: int    # 반복·특이 이력을 세는 기간(일)
    recontact_hours: int        # 종결 후 '바로' 연락이 온 것으로 보는 시간
    repeat_sim_threshold: float  # 반복민원으로 볼 유사도 임계값(0~1)
    repeat_sim_samples: int      # LLM에게 유사도를 묻는 횟수(중앙값 사용)
    neis_api_key: str           # 나이스 학사일정 API 인증키(없으면 학사일정 직접 답변을 만들지 않음)
    neis_office_code: str       # 시도교육청코드 (ATPT_OFCDC_SC_CODE)
    neis_school_code: str       # 표준학교코드 (SD_SCHUL_CODE)
    school_name: str            # 이첩 보고서의 학교명(없으면 담당자가 입력)
    transfer_template: str      # 이첩 보고서 서식 파일(.hwpx)


def _env(name, default=""):
    """환경 변수 값. 없거나 비어 있으면(.env에 `NAME=`만 적은 경우, 호스팅 화면에서 비운 경우) 기본값을 쓴다."""
    return (os.environ.get(name) or "").strip() or default


def _code(name):
    """코드 값은 첫 단어만 쓴다(값 뒤에 설명을 붙여 적어도 깨지지 않게)."""
    return (_env(name).split() or [""])[0]


def load_settings() -> Settings:
    return Settings(
        llm_base_url=_env("LLM_BASE_URL", "http://localhost:11434/v1"),
        llm_model=_env("LLM_MODEL", "qwen2.5:7b-instruct"),
        llm_api_key=_env("LLM_API_KEY", "ollama"),
        embed_model=_env("EMBED_MODEL"),
        manual_pdf=_env("MANUAL_PDF", "data/학교민원처리매뉴얼.pdf"),
        database_url=_env("DATABASE_URL", "data/complaints.sqlite"),
        history_window_days=int(_env("HISTORY_WINDOW_DAYS", "180")),
        recontact_hours=int(_env("RECONTACT_HOURS", "24")),
        repeat_sim_threshold=float(_env("REPEAT_SIM_THRESHOLD", "0.8")),
        repeat_sim_samples=int(_env("REPEAT_SIM_SAMPLES", "3")),
        neis_api_key=_env("NEIS_API_KEY"),
        neis_office_code=_code("NEIS_OFFICE_CODE"),
        neis_school_code=_code("NEIS_SCHOOL_CODE"),
        school_name=_env("SCHOOL_NAME"),
        transfer_template=_env("TRANSFER_TEMPLATE", "data/특이민원_지원요청보고서_서식.hwpx"),
    )
