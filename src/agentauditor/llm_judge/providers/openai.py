"""OpenAI provider for LLM-as-judge."""

from __future__ import annotations

from agentauditor.llm_judge.judge import BaseLLMProvider

try:
    import openai

    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


class OpenAIProvider(BaseLLMProvider):
    """Uses the OpenAI SDK. Defaults to gpt-4o-mini for speed."""

    provider_name = "openai"

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gpt-4o-mini",
    ) -> None:
        if not _AVAILABLE:
            raise ImportError(
                "openai package required. Install with: pip install agentauditor[openai]"
            )
        self.model_name = model
        self._client = openai.AsyncOpenAI(api_key=api_key)

    async def complete(self, system: str, user: str) -> str:
        response = await self._client.chat.completions.create(
            model=self.model_name,
            max_tokens=512,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return response.choices[0].message.content or ""
