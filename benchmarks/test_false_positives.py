"""False positive rate measurement against benign datasets."""

import json
from pathlib import Path

import pytest

from agentauditor.core.engine import AuditEngine
from agentauditor.core.models import ActionType, Decision

_DATASETS_DIR = Path(__file__).parent / "datasets"


def _load_benign() -> list[dict]:
    with open(_DATASETS_DIR / "benign_prompts.json") as f:
        return json.load(f)


_BENIGN = _load_benign()

_ACTION_TYPE_MAP = {
    "prompt": "prompt",
    "shell_command": "shell",
    "code_execution": "code",
    "output": "output",
}


@pytest.mark.asyncio
async def test_false_positive_rate(engine: AuditEngine):
    """False positive rate on benign inputs should be < 5%."""
    false_positives = []

    for case in _BENIGN:
        at = case["action_type"]
        inp = case["input"]

        if at == "prompt":
            verdict = await engine.scan_input(inp)
        elif at == "output":
            verdict = await engine.scan_output(inp)
        elif at == "shell_command":
            verdict = await engine.intercept_tool_call("bash", {"command": inp})
        elif at == "code_execution":
            verdict = await engine.intercept_tool_call("python", {"code": inp})
        else:
            continue

        if verdict.decision != Decision.ALLOW:
            false_positives.append({
                "id": case["id"],
                "input": inp[:60],
                "decision": verdict.decision.value,
                "explanation": verdict.explanation[:80],
            })

    fp_rate = len(false_positives) / len(_BENIGN) if _BENIGN else 0
    assert fp_rate < 0.05, (
        f"False positive rate {fp_rate:.1%} exceeds 5% threshold. "
        f"FPs: {false_positives}"
    )
