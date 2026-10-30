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
    db_path: str


def load_settings() -> Settings:
    return Settings(
        llm_base_url=os.environ.get("LLM_BASE_URL", "http://localhost:11434/v1"),
        llm_model=os.environ.get("LLM_MODEL", "qwen2.5:7b-instruct"),
        llm_api_key=os.environ.get("LLM_API_KEY", "ollama"),
        embed_model=os.environ.get("EMBED_MODEL", ""),
        manual_pdf=os.environ.get("MANUAL_PDF", "data/학교민원처리매뉴얼.pdf"),
        db_path=os.environ.get("DB_PATH", "data/complaints.sqlite"),
    )
