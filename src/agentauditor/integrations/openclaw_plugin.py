"""OpenClaw plugin integration for AgentAuditor.

This module provides an OpenClaw plugin that hooks into the `before_tool_call`
event to intercept and audit every tool call before execution — making security
mandatory rather than agent-voluntary.

Setup:
    1. Copy this plugin to ~/.openclaw/plugins/agentauditor/
    2. Create openclaw.plugin.json alongside it
    3. Enable in openclaw.json: {"plugins": {"enabled": ["agentauditor"]}}

Or use the Python library integration directly in a custom OpenClaw skill.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any


def create_openclaw_plugin_manifest() -> dict:
    """Returns the openclaw.plugin.json manifest for this plugin."""
    return {
        "name": "agentauditor",
        "version": "0.1.0",
        "description": "Runtime security auditor — intercepts tool calls, blocks threats",
        "hooks": ["before_tool_call", "tool_result_persist"],
        "settings": {
            "policy_path": {
                "type": "string",
                "description": "Path to custom policy YAML file",
                "default": "",
            },
            "block_on_error": {
                "type": "boolean",
                "description": "Block tool calls if auditor fails (fail-closed)",
                "default": True,
            },
        },
    }


class OpenClawAuditorPlugin:
    """OpenClaw plugin that audits every tool call via before_tool_call hook.

    This makes AgentAuditor enforcement MANDATORY — the agent cannot bypass it
    because the hook runs inside OpenClaw's gateway process before tool execution.

    Usage in OpenClaw plugin registration:

        from agentauditor.integrations.openclaw_plugin import OpenClawAuditorPlugin

        plugin = OpenClawAuditorPlugin()

        def register(api):
            api.on("before_tool_call", plugin.before_tool_call)
            api.on("tool_result_persist", plugin.tool_result_persist)
    """

    def __init__(self, policy_path: str | None = None, block_on_error: bool = True) -> None:
        self._engine = None
        self._policy_path = policy_path
        self._block_on_error = block_on_error

    def _get_engine(self):
        """Lazy-load engine to avoid import overhead at plugin discovery time."""
        if self._engine is None:
            from agentauditor.core.engine import AuditEngine

            self._engine = AuditEngine(policy_path=self._policy_path)
        return self._engine

    async def before_tool_call(self, tool_name: str, params: dict[str, Any], context: dict) -> dict:
        """Hook: intercept every tool call before execution.

        Returns:
            dict with keys:
                - "allow": bool — whether to proceed with the tool call
                - "reason": str — explanation if blocked
                - "modified_params": dict | None — redacted params if needed
        """
        try:
            engine = self._get_engine()
            agent_id = context.get("agent_id", context.get("session_id", "openclaw-agent"))
            user_goal = context.get("user_goal") or context.get("last_user_message")

            verdict = await engine.intercept_tool_call(
                tool_name=tool_name,
                parameters=params,
                agent_id=agent_id,
                user_goal=user_goal,
            )

            if verdict.decision.value == "block":
                return {
                    "allow": False,
                    "reason": f"[AgentAuditor] BLOCKED: {verdict.explanation}",
                    "modified_params": None,
                }
            elif verdict.decision.value == "escalate":
                # Log for human review but allow (OpenClaw can wire this to notifications)
                return {
                    "allow": True,
                    "reason": f"[AgentAuditor] ESCALATED: {verdict.explanation}",
                    "modified_params": None,
                }
            else:
                return {"allow": True, "reason": None, "modified_params": None}

        except Exception as e:
            if self._block_on_error:
                return {
                    "allow": False,
                    "reason": f"[AgentAuditor] Error during audit (fail-closed): {e}",
                    "modified_params": None,
                }
            return {"allow": True, "reason": None, "modified_params": None}

    async def tool_result_persist(self, tool_name: str, result: str, context: dict) -> str:
        """Hook: scan tool results for PII/secrets before persisting to session.

        This is synchronous in OpenClaw — wraps async engine in sync call.
        Returns the (potentially redacted) result string.
        """
        try:
            engine = self._get_engine()
            verdict = await engine.scan_output(result)

            if verdict.decision.value == "modify":
                # Return redacted output
                from agentauditor.layers.output_layer import redact_text

                return redact_text(result)

        except Exception:
            pass  # Don't block persistence on scan failure

        return result


# --- Convenience for direct Python integration ---


async def audit_openclaw_message(
    message: str,
    channel: str = "unknown",
    sender: str = "unknown",
    policy_path: str | None = None,
) -> dict:
    """Standalone function to audit an incoming OpenClaw message.

    Use this in a custom OpenClaw skill or webhook handler:

        from agentauditor.integrations.openclaw_plugin import audit_openclaw_message

        result = await audit_openclaw_message(
            message=incoming_text,
            channel="telegram",
            sender=user_id,
        )
        if not result["safe"]:
            return f"Message blocked: {result['reason']}"
    """
    from agentauditor.core.engine import AuditEngine

    engine = AuditEngine(policy_path=policy_path)
    verdict = await engine.scan_input(message, agent_id=f"openclaw-{channel}-{sender}")

    return {
        "safe": verdict.decision.value == "allow",
        "decision": verdict.decision.value,
        "risk_level": verdict.risk_level.value,
        "reason": verdict.explanation,
        "channel": channel,
        "sender": sender,
    }
