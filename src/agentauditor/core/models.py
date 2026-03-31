"""Core data models for AgentAuditor. Every component speaks in terms of these types."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


# --- Enums ---


class ActionType(str, enum.Enum):
    TOOL_CALL = "tool_call"
    CODE_EXECUTION = "code_execution"
    FILE_ACCESS = "file_access"
    API_CALL = "api_call"
    SHELL_COMMAND = "shell_command"
    PROMPT = "prompt"
    OUTPUT = "output"


class RiskLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def severity(self) -> int:
        return {
            RiskLevel.CRITICAL: 4,
            RiskLevel.HIGH: 3,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 1,
            RiskLevel.INFO: 0,
        }[self]

    def __ge__(self, other: RiskLevel) -> bool:
        return self.severity >= other.severity

    def __gt__(self, other: RiskLevel) -> bool:
        return self.severity > other.severity

    def __le__(self, other: RiskLevel) -> bool:
        return self.severity <= other.severity

    def __lt__(self, other: RiskLevel) -> bool:
        return self.severity < other.severity


class Decision(str, enum.Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE = "escalate"
    MODIFY = "modify"

    @property
    def priority(self) -> int:
        return {
            Decision.BLOCK: 3,
            Decision.ESCALATE: 2,
            Decision.MODIFY: 1,
            Decision.ALLOW: 0,
        }[self]


class DefenseLayer(str, enum.Enum):
    INPUT = "input"
    PLANNING = "planning"
    TOOL_SELECTION = "tool_selection"
    EXECUTION = "execution"
    OUTPUT = "output"
    INTER_AGENT = "inter_agent"
    MEMORY = "memory"
    IDENTITY = "identity"


# --- Core Data Models ---


class AgentIdentity(BaseModel):
    """Registered agent with its permissions."""

    agent_id: str
    name: str
    permissions: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)
    max_risk_level: RiskLevel = RiskLevel.MEDIUM
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Action(BaseModel):
    """A single agent action to be audited."""

    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent_id: str | None = None
    action_type: ActionType
    tool_name: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    raw_input: str | None = None
    raw_output: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class RuleMatch(BaseModel):
    """A single rule that matched during evaluation."""

    rule_id: str
    rule_name: str
    layer: DefenseLayer
    risk_level: RiskLevel
    description: str
    decision: Decision = Decision.BLOCK
    matched_pattern: str | None = None


class LLMJudgment(BaseModel):
    """Result from the LLM-as-judge evaluation."""

    provider: str
    model: str
    risk_level: RiskLevel
    reasoning: str
    aligned_with_goal: bool
    confidence: float = Field(ge=0.0, le=1.0)
    latency_ms: float


class Verdict(BaseModel):
    """Final audit verdict for an action."""

    action_id: str
    decision: Decision
    risk_level: RiskLevel
    rule_matches: list[RuleMatch] = Field(default_factory=list)
    llm_judgments: list[LLMJudgment] = Field(default_factory=list)
    explanation: str
    layer: DefenseLayer | None = None
    latency_ms: float
    redacted_output: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# --- Policy Models ---


class PatternMatch(BaseModel):
    """A single pattern to match against."""

    type: str = "regex"
    value: str
    case_sensitive: bool = False


class PolicyRule(BaseModel):
    """A single rule within a policy."""

    id: str
    name: str
    description: str
    layer: DefenseLayer
    risk_level: RiskLevel
    action_types: list[ActionType] = Field(default_factory=list)
    tool_names: list[str] = Field(default_factory=list)
    patterns: list[PatternMatch] = Field(default_factory=list)
    parameter_constraints: dict[str, Any] = Field(default_factory=dict)
    decision: Decision = Decision.BLOCK
    enabled: bool = True


class PolicyConfig(BaseModel):
    """Top-level policy configuration loaded from YAML."""

    version: str = "1.0"
    name: str = "default"
    description: str = ""
    default_decision: Decision = Decision.ALLOW
    llm_judge_enabled: bool = False
    llm_judge_threshold: RiskLevel = RiskLevel.MEDIUM
    ensemble_voting: bool = False
    max_latency_ms: float = 500.0
    rules: list[PolicyRule] = Field(default_factory=list)
    identity_policies: list[AgentIdentity] = Field(default_factory=list)
