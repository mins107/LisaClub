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
    history_window_days: int    # 반복·악성 이력을 세는 기간(일)
    recontact_hours: int        # 종결 후 '바로' 연락이 온 것으로 보는 시간


def load_settings() -> Settings:
    return Settings(
        llm_base_url=os.environ.get("LLM_BASE_URL", "http://localhost:11434/v1"),
        llm_model=os.environ.get("LLM_MODEL", "qwen2.5:7b-instruct"),
        llm_api_key=os.environ.get("LLM_API_KEY", "ollama"),
        embed_model=os.environ.get("EMBED_MODEL", ""),
        manual_pdf=os.environ.get("MANUAL_PDF", "data/학교민원처리매뉴얼.pdf"),
        database_url=os.environ.get("DATABASE_URL", "data/complaints.sqlite"),
        history_window_days=int(os.environ.get("HISTORY_WINDOW_DAYS", "180")),
        recontact_hours=int(os.environ.get("RECONTACT_HOURS", "24")),
    )
