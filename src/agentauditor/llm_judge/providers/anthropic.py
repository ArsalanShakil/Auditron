"""Anthropic Claude provider for LLM-as-judge."""

from __future__ import annotations

from agentauditor.llm_judge.judge import BaseLLMProvider

try:
    import anthropic

    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


class AnthropicProvider(BaseLLMProvider):
    """Uses the Anthropic SDK. Defaults to claude-sonnet-4-20250514 for speed."""

    provider_name = "anthropic"

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-20250514",
    ) -> None:
        if not _AVAILABLE:
            raise ImportError(
                "anthropic package required. Install with: pip install agentauditor[anthropic]"
            )
        self.model_name = model
        self._client = anthropic.AsyncAnthropic(api_key=api_key)

    async def complete(self, system: str, user: str) -> str:
        response = await self._client.messages.create(
            model=self.model_name,
            max_tokens=512,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return response.content[0].text
