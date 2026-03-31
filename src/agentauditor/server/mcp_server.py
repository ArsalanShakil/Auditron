"""FastMCP server exposing AgentAuditor as MCP tools and resources."""

from __future__ import annotations

import json
from typing import Annotated

from pydantic import Field

from agentauditor.core.engine import AuditEngine
from agentauditor.core.models import AgentIdentity, RiskLevel

try:
    from fastmcp import FastMCP
except ImportError:
    raise ImportError(
        "fastmcp is required for the MCP server. Install with: pip install agentauditor[mcp]"
    )

mcp = FastMCP(
    name="AgentAuditor",
    instructions=(
        "AgentAuditor is a runtime security agent. Use audit_intercept before executing "
        "any tool call to check if it's safe. Use audit_scan_input to check prompts for "
        "injection attacks. Use audit_scan_output to check responses for PII leaks."
    ),
)

_engine: AuditEngine | None = None


def _get_engine() -> AuditEngine:
    global _engine
    if _engine is None:
        _engine = AuditEngine()
    return _engine


@mcp.tool(
    description=(
        "Intercept and audit a tool call before execution. Returns a verdict with "
        "allow/block/escalate decision and explanation."
    ),
)
async def audit_intercept(
    tool_name: Annotated[str, Field(description="Name of the tool being called")],
    parameters: Annotated[
        dict, Field(description="Parameters being passed to the tool")
    ] = {},
    agent_id: Annotated[
        str | None, Field(description="ID of the calling agent")
    ] = None,
    user_goal: Annotated[
        str | None, Field(description="The user's stated goal for context")
    ] = None,
) -> dict:
    """Intercept a tool call and return audit verdict."""
    engine = _get_engine()
    verdict = await engine.intercept_tool_call(
        tool_name=tool_name,
        parameters=parameters,
        agent_id=agent_id,
        user_goal=user_goal,
    )
    return verdict.model_dump(mode="json")


@mcp.tool(
    description=(
        "Scan input text for prompt injection, malicious instructions, "
        "or policy violations."
    ),
)
async def audit_scan_input(
    text: Annotated[str, Field(description="Input text to scan")],
    agent_id: Annotated[
        str | None, Field(description="ID of the calling agent")
    ] = None,
) -> dict:
    """Scan input for prompt injection and other threats."""
    engine = _get_engine()
    verdict = await engine.scan_input(text, agent_id=agent_id)
    return verdict.model_dump(mode="json")


@mcp.tool(
    description=(
        "Scan output text for PII leaks, credential exposure, "
        "or data exfiltration."
    ),
)
async def audit_scan_output(
    text: Annotated[str, Field(description="Output text to scan")],
    agent_id: Annotated[
        str | None, Field(description="ID of the calling agent")
    ] = None,
) -> dict:
    """Scan output for PII and data leaks."""
    engine = _get_engine()
    verdict = await engine.scan_output(text, agent_id=agent_id)
    return verdict.model_dump(mode="json")


@mcp.tool(
    description="Register an agent identity with permissions and tool access controls.",
)
async def audit_register_agent(
    agent_id: Annotated[str, Field(description="Unique agent identifier")],
    name: Annotated[str, Field(description="Human-readable agent name")],
    permissions: Annotated[
        list[str], Field(description="List of permissions")
    ] = ["read"],
    allowed_tools: Annotated[
        list[str],
        Field(description="Tools this agent is allowed to use (empty=all)"),
    ] = [],
    denied_tools: Annotated[
        list[str], Field(description="Tools this agent is denied from using")
    ] = [],
    max_risk_level: Annotated[
        str,
        Field(description="Maximum risk level: critical/high/medium/low/info"),
    ] = "medium",
) -> dict:
    """Register an agent with the auditor."""
    engine = _get_engine()
    identity = AgentIdentity(
        agent_id=agent_id,
        name=name,
        permissions=permissions,
        allowed_tools=allowed_tools,
        denied_tools=denied_tools,
        max_risk_level=RiskLevel(max_risk_level),
    )
    await engine.register_agent(identity)
    return {"status": "registered", "agent_id": agent_id}


@mcp.tool(
    description=(
        "Get the current status of the AgentAuditor engine including "
        "policy info, rule counts, and audit statistics."
    ),
)
async def audit_get_status() -> dict:
    """Get auditor engine status."""
    engine = _get_engine()
    return engine.get_status()


@mcp.resource("agentauditor://policy/current")
async def get_current_policy() -> str:
    """Returns the current active policy as YAML."""
    import yaml

    engine = _get_engine()
    return yaml.dump(engine.policy.model_dump(mode="json"), sort_keys=False)


@mcp.resource("agentauditor://logs/recent")
async def get_recent_logs() -> str:
    """Returns recent audit log entries as JSON."""
    engine = _get_engine()
    return json.dumps(engine.logger.get_recent_logs(), indent=2, default=str)


def create_server(policy_path: str | None = None) -> FastMCP:
    """Factory function to create a configured MCP server instance."""
    global _engine
    _engine = AuditEngine(policy_path=policy_path)
    return mcp
