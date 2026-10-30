"""한국 학교 민원 식별 에이전트 (근거 하이라이팅 포함).

구조: manual_index(PDF 근거 단위 색인) -> retriever(검색) -> rules(규칙 판정)
      -> pipeline(구조도 흐름) -> highlight(PDF 형광펜 + HTML 리포트)
"""
