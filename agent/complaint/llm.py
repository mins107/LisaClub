"""OpenAI 호환 엔드포인트 클라이언트. Ollama(로컬 무료)가 기본이며,
LLM_BASE_URL만 바꾸면 Groq·Gemini 등 다른 호환 서버도 쓸 수 있다.
연결되지 않으면 NullLLM으로 떨어져 규칙 기반으로만 동작한다."""
import json
import re


class NullLLM:
    available = False

    def chat(self, system, user, json_mode=False):
        raise RuntimeError("LLM 미연결")

    def embed(self, texts):
        raise RuntimeError("LLM 미연결")


class LLM:
    available = True

    def __init__(self, base_url, model, api_key, embed_model="", timeout=60):
        from openai import OpenAI
        self.client = OpenAI(base_url=base_url, api_key=api_key, timeout=timeout)
        self.model, self.embed_model = model, embed_model

    def chat(self, system, user, json_mode=False):
        kw = {"response_format": {"type": "json_object"}} if json_mode else {}
        r = self.client.chat.completions.create(
            model=self.model, temperature=0.1,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}], **kw)
        return r.choices[0].message.content

    def embed(self, texts):
        r = self.client.embeddings.create(model=self.embed_model, input=texts)
        return [d.embedding for d in r.data]


def connect(settings, mode="auto"):
    if mode == "none":
        return NullLLM()
    try:
        llm = LLM(settings.llm_base_url, settings.llm_model, settings.llm_api_key, settings.embed_model)
        llm.client.models.list()      # 연결 확인
        return llm
    except Exception as e:  # noqa: BLE001
        if mode == "on":
            raise
        print(f"[안내] LLM에 연결하지 못해 규칙 기반으로 실행합니다: {type(e).__name__}")
        return NullLLM()


def parse_json(raw: str) -> dict:
    m = re.search(r"\{.*\}", raw or "", re.S)
    try:
        return json.loads(m.group(0)) if m else {}
    except json.JSONDecodeError:
        return {}
