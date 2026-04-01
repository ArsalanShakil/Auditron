"""Dataset-driven evasion detection tests."""

import json
from pathlib import Path

import pytest

from agentauditor.core.engine import AuditEngine
from agentauditor.core.models import Action, ActionType, Decision

_DATASETS_DIR = Path(__file__).parent / "datasets"


def _load_dataset(name: str) -> list[dict]:
    with open(_DATASETS_DIR / name) as f:
        return json.load(f)


_MALICIOUS = _load_dataset("malicious_prompts.json")

_ACTION_TYPE_MAP = {
    "prompt": ActionType.PROMPT,
    "shell_command": ActionType.SHELL_COMMAND,
    "code_execution": ActionType.CODE_EXECUTION,
    "output": ActionType.OUTPUT,
}


@pytest.mark.parametrize(
    "case",
    _MALICIOUS,
    ids=[c["id"] for c in _MALICIOUS],
)
@pytest.mark.asyncio
async def test_malicious_detected(case: dict, engine: AuditEngine):
    """Each malicious payload should be detected (not ALLOW)."""
    action_type = _ACTION_TYPE_MAP[case["action_type"]]
    expected = case["expected_decision"]

    if action_type == ActionType.PROMPT:
        verdict = await engine.scan_input(case["input"])
    elif action_type == ActionType.OUTPUT:
        verdict = await engine.scan_output(case["input"])
    elif action_type == ActionType.SHELL_COMMAND:
        verdict = await engine.intercept_tool_call("bash", {"command": case["input"]})
    elif action_type == ActionType.CODE_EXECUTION:
        verdict = await engine.intercept_tool_call("python", {"code": case["input"]})
    else:
        pytest.skip(f"Unsupported action type: {case['action_type']}")

    # The verdict decision should be at least as severe as expected
    expected_priority = Decision(expected).priority
    assert verdict.decision.priority >= expected_priority, (
        f"[{case['id']}] Expected >={expected}, got {verdict.decision.value} "
        f"for: {case['input'][:60]}"
    )
