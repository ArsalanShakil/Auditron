"""AuditEngine — the single public API that wires all components together."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from agentauditor.core.chain_detector import ChainDetector
from agentauditor.core.enforcer import Enforcer
from agentauditor.core.evaluator import Evaluator
from agentauditor.core.normalizer import extract_raw_input, normalize_tool_name
from agentauditor.core.rate_limiter import AnomalyTracker
from agentauditor.core.models import (
    Action,
    ActionType,
    AgentIdentity,
    PolicyConfig,
    Verdict,
)
from agentauditor.layers.base import BaseLayer
from agentauditor.layers.execution_layer import ExecutionLayer
from agentauditor.layers.identity_layer import IdentityLayer
from agentauditor.layers.input_layer import InputLayer
from agentauditor.layers.output_layer import OutputLayer
from agentauditor.layers.tool_layer import ToolLayer
from agentauditor.logging.audit_logger import AuditLogger
from agentauditor.policies.loader import load_policy
from agentauditor.rules.rule_engine import RuleEngine


class AuditEngine:
    """Main orchestrator. Primary public API for both the MCP server and the CLI.

    Usage:
        engine = AuditEngine()
        verdict = await engine.intercept_tool_call("bash", {"command": "rm -rf /"})
        if verdict.decision == "block":
            print("Blocked:", verdict.explanation)
    """

    def __init__(
        self,
        policy_path: str | Path | None = None,
        on_block_callback: Callable[[Action, Verdict], None] | None = None,
    ) -> None:
        self.policy = load_policy(policy_path)
        self._rule_engine = RuleEngine(self.policy)
        self._identity_layer = IdentityLayer()

        self._layers: list[BaseLayer] = [
            InputLayer(),
            ToolLayer(),
            ExecutionLayer(),
            OutputLayer(),
            self._identity_layer,
        ]

        self._evaluator = Evaluator(
            policy=self.policy,
            rule_engine=self._rule_engine,
            layers=self._layers,
            llm_judge=None,
        )
        self._enforcer = Enforcer(self.policy)
        self._logger = AuditLogger()
        self._rate_limiter = AnomalyTracker(
            boundary_probe_threshold=self.policy.boundary_probe_threshold,
            repetition_threshold=self.policy.repetition_threshold,
        )
        self._chain_detector = ChainDetector(
            window_minutes=self.policy.chain_window_minutes,
            custom_chain_patterns=self.policy.chain_patterns,
        )

        # Stats
        self._audit_count = 0
        self._block_count = 0
        self._on_block_callback = on_block_callback

    async def audit_action(self, action: Action) -> Verdict:
        """Full audit pipeline: rate check -> evaluate -> enforce -> log -> return verdict."""
        # Check rate limiter lockout first (short-circuit)
        lockout = self._rate_limiter.check_lockout(action.agent_id)
        if lockout:
            verdict = Verdict(
                action_id=action.action_id,
                decision=lockout.decision,
                risk_level=lockout.risk_level,
                rule_matches=[lockout],
                explanation=lockout.description,
                latency_ms=0.0,
            )
            self._logger.log_verdict(action, verdict)
            self._audit_count += 1
            self._block_count += 1
            return verdict

        verdict = await self._evaluator.evaluate(action)
        verdict = await self._enforcer.enforce(verdict, action)

        # Record in rate limiter after enforcement
        was_blocked = verdict.decision.value == "block"
        self._rate_limiter.record_detailed(action.agent_id, action, was_blocked)

        # Check for boundary probing and repetition loops
        for anomaly_check in (
            self._rate_limiter.check_boundary_probing,
            self._rate_limiter.check_repetition,
        ):
            anomaly_match = anomaly_check(action.agent_id)
            if anomaly_match and anomaly_match.risk_level.severity > verdict.risk_level.severity:
                verdict = Verdict(
                    action_id=verdict.action_id,
                    decision=max(
                        verdict.decision, anomaly_match.decision, key=lambda d: d.priority
                    ),
                    risk_level=anomaly_match.risk_level,
                    rule_matches=verdict.rule_matches + [anomaly_match],
                    llm_judgments=verdict.llm_judgments,
                    explanation=f"{verdict.explanation} | {anomaly_match.description}",
                    layer=verdict.layer,
                    latency_ms=verdict.latency_ms,
                    redacted_output=verdict.redacted_output,
                    stage1_confidence=verdict.stage1_confidence,
                )

        # Check for multi-step attack chains
        chain_match = self._chain_detector.record(action.agent_id, action, verdict)
        if chain_match and chain_match.risk_level.severity > verdict.risk_level.severity:
            verdict = Verdict(
                action_id=verdict.action_id,
                decision=max(
                    verdict.decision, chain_match.decision, key=lambda d: d.priority
                ),
                risk_level=chain_match.risk_level,
                rule_matches=verdict.rule_matches + [chain_match],
                llm_judgments=verdict.llm_judgments,
                explanation=f"{verdict.explanation} | {chain_match.description}",
                layer=verdict.layer,
                latency_ms=verdict.latency_ms,
                redacted_output=verdict.redacted_output,
                stage1_confidence=verdict.stage1_confidence,
            )

        self._logger.log_verdict(action, verdict)
        self._audit_count += 1
        if verdict.decision.value == "block":
            self._block_count += 1
            if self._on_block_callback:
                try:
                    self._on_block_callback(action, verdict)
                except Exception:
                    pass  # Callback failure must not break the audit pipeline
        return verdict

    async def scan_input(self, text: str, agent_id: str | None = None) -> Verdict:
        """Scan input text for prompt injection and other threats."""
        action = Action(
            action_type=ActionType.PROMPT,
            raw_input=text,
            agent_id=agent_id,
        )
        return await self.audit_action(action)

    async def scan_output(self, text: str, agent_id: str | None = None) -> Verdict:
        """Scan output text for PII leaks and credential exposure."""
        action = Action(
            action_type=ActionType.OUTPUT,
            raw_output=text,
            agent_id=agent_id,
        )
        return await self.audit_action(action)

    async def intercept_tool_call(
        self,
        tool_name: str,
        parameters: dict[str, Any] | None = None,
        agent_id: str | None = None,
        user_goal: str | None = None,
    ) -> Verdict:
        """Intercept a tool call and return audit verdict."""
        context: dict[str, Any] = {}
        if user_goal:
            context["user_goal"] = user_goal

        # Normalize tool name and detect action type
        normalized_name = normalize_tool_name(tool_name)
        shell_tools = {"bash", "shell", "terminal", "execute_command", "run_command"}
        code_exec_tools = {"python", "node", "ruby", "perl", "lua", "julia", "rscript"}

        if normalized_name in shell_tools:
            action_type = ActionType.SHELL_COMMAND
        elif normalized_name in code_exec_tools:
            action_type = ActionType.CODE_EXECUTION
        else:
            action_type = ActionType.TOOL_CALL

        action = Action(
            action_type=action_type,
            tool_name=tool_name,
            parameters=parameters or {},
            agent_id=agent_id,
            context=context,
            raw_input=extract_raw_input(parameters),
        )
        return await self.audit_action(action)

    async def register_agent(self, identity: AgentIdentity) -> None:
        """Register an agent identity for permission tracking."""
        self._identity_layer.register_agent(
            identity.agent_id, set(identity.permissions)
        )

    def get_status(self) -> dict:
        """Return engine status."""
        return {
            "policy_name": self.policy.name,
            "policy_version": self.policy.version,
            "rules_loaded": len(self.policy.rules),
            "rules_enabled": sum(1 for r in self.policy.rules if r.enabled),
            "identity_policies": len(self.policy.identity_policies),
            "registered_agents": self._identity_layer.registry.count,
            "llm_judge_enabled": self.policy.llm_judge_enabled,
            "total_audits": self._audit_count,
            "total_blocks": self._block_count,
            "layers_active": [layer.layer.value for layer in self._layers],
        }

    def reload_policy(self, policy_path: str | Path) -> None:
        """Hot-reload policy from YAML file."""
        self.policy = load_policy(policy_path)
        self._rule_engine = RuleEngine(self.policy)
        self._evaluator = Evaluator(
            policy=self.policy,
            rule_engine=self._rule_engine,
            layers=self._layers,
            llm_judge=self._evaluator.llm_judge,
        )
        self._enforcer = Enforcer(self.policy)

    @property
    def logger(self) -> AuditLogger:
        return self._logger
