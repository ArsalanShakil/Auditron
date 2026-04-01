"""Typer CLI application for AgentAuditor."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agentauditor.core.engine import AuditEngine
from agentauditor.core.models import Decision
from agentauditor.policies.loader import validate_policy

app = typer.Typer(
    name="agentauditor",
    help="Runtime security agent for AI systems",
    no_args_is_help=True,
)
console = Console()


def _decision_color(decision: Decision) -> str:
    return {
        Decision.BLOCK: "red",
        Decision.ESCALATE: "yellow",
        Decision.MODIFY: "cyan",
        Decision.ALLOW: "green",
    }[decision]


@app.command()
def scan(
    text: str = typer.Argument(help="Text or command to scan"),
    mode: str = typer.Option(
        "auto", "--mode", "-m", help="Scan mode: input/output/tool/auto"
    ),
    policy: Optional[Path] = typer.Option(
        None, "--policy", "-p", help="Path to policy YAML"
    ),
    agent_id: Optional[str] = typer.Option(
        None, "--agent-id", "-a", help="Agent ID for identity checks"
    ),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
) -> None:
    """Scan text, prompt, or command for security threats."""
    engine = AuditEngine(policy_path=policy)

    async def _scan():
        if mode == "input":
            return await engine.scan_input(text, agent_id=agent_id)
        elif mode == "output":
            return await engine.scan_output(text, agent_id=agent_id)
        elif mode == "tool":
            # Parse as "tool_name param1=val1 param2=val2" or just treat as shell
            parts = text.split(maxsplit=1)
            tool_name = parts[0]
            params = {"command": parts[1]} if len(parts) > 1 else {}
            return await engine.intercept_tool_call(
                tool_name, params, agent_id=agent_id
            )
        else:
            # Auto-detect
            shell_indicators = ["rm ", "curl ", "wget ", "chmod ", "sudo ", "dd ", "mkfs"]
            if any(text.strip().startswith(ind) or f" {ind}" in text for ind in shell_indicators):
                return await engine.intercept_tool_call(
                    "bash", {"command": text}, agent_id=agent_id
                )
            return await engine.scan_input(text, agent_id=agent_id)

    verdict = asyncio.run(_scan())

    if json_output:
        console.print_json(json.dumps(verdict.model_dump(mode="json"), default=str))
        return

    color = _decision_color(verdict.decision)
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Decision", f"[{color}]{verdict.decision.value.upper()}[/{color}]")
    table.add_row("Risk Level", verdict.risk_level.value)
    table.add_row("Explanation", verdict.explanation)
    table.add_row("Latency", f"{verdict.latency_ms:.1f}ms")

    if verdict.rule_matches:
        table.add_row("Rules Matched", str(len(verdict.rule_matches)))
        for m in verdict.rule_matches:
            table.add_row(
                f"  {m.rule_id}",
                f"[dim]{m.description}[/dim]",
            )

    panel = Panel(table, title="AgentAuditor Scan Result", border_style=color)
    console.print(panel)

    if verdict.decision == Decision.BLOCK:
        raise typer.Exit(code=1)


@app.command()
def serve(
    policy: Optional[Path] = typer.Option(
        None, "--policy", "-p", help="Path to policy YAML"
    ),
    transport: str = typer.Option(
        "stdio", "--transport", "-t", help="Transport: stdio or http"
    ),
    port: int = typer.Option(8000, "--port", help="Port for HTTP transport"),
) -> None:
    """Start the AgentAuditor MCP server."""
    try:
        from agentauditor.server.mcp_server import create_server
    except ImportError:
        console.print(
            "[red]fastmcp is required for the MCP server.[/red]\n"
            "Install with: pip install agentauditor[mcp]"
        )
        raise typer.Exit(code=1)

    server = create_server(policy_path=str(policy) if policy else None)
    console.print(f"Starting AgentAuditor MCP server ({transport})...")

    if transport == "http":
        server.run(transport="streamable-http", port=port)
    else:
        server.run(transport="stdio")


@app.command(name="validate-policy")
def validate_policy_cmd(
    policy_path: Path = typer.Argument(help="Path to policy YAML file"),
) -> None:
    """Validate a policy YAML file."""
    errors = validate_policy(policy_path)

    if errors:
        console.print(f"[red]Policy validation failed with {len(errors)} error(s):[/red]")
        for err in errors:
            console.print(f"  - {err}")
        raise typer.Exit(code=1)

    from agentauditor.policies.loader import load_policy

    policy = load_policy(policy_path)
    console.print(f"[green]Policy '{policy.name}' is valid.[/green]")
    console.print(f"  Rules: {len(policy.rules)} ({sum(1 for r in policy.rules if r.enabled)} enabled)")
    console.print(f"  Identity policies: {len(policy.identity_policies)}")
    console.print(f"  LLM judge: {'enabled' if policy.llm_judge_enabled else 'disabled'}")


@app.command()
def verify(
    policy: Optional[Path] = typer.Option(
        None, "--policy", "-p", help="Path to policy YAML"
    ),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show all test details"),
) -> None:
    """Run adversarial self-test against current policy."""
    from agentauditor.testing.adversarial import AdversarialVerifier

    engine = AuditEngine(policy_path=policy)
    verifier = AdversarialVerifier(engine)

    console.print("[bold]Running adversarial verification suite...[/bold]")
    report = asyncio.run(verifier.run_full_suite())

    if json_output:
        import dataclasses
        console.print_json(json.dumps(dataclasses.asdict(report), default=str))
        return

    # Summary
    pass_color = "green" if report.pass_rate >= 0.8 else "yellow" if report.pass_rate >= 0.5 else "red"
    console.print(f"\n[bold]Results:[/bold] [{pass_color}]{report.passed}/{report.total_tests} passed ({report.pass_rate:.0%})[/{pass_color}]")

    # Failed tests
    failed = [r for r in report.results if not r.passed]
    if failed:
        console.print(f"\n[red]Failed tests ({len(failed)}):[/red]")
        for r in failed:
            console.print(f"  [red]FAIL[/red] {r.test_name}: {r.details}")

    # Evasion gaps
    if report.evasion_gaps:
        console.print(f"\n[yellow]Evasion gaps ({len(report.evasion_gaps)}):[/yellow]")
        for gap in report.evasion_gaps:
            console.print(f"  - {gap}")

    # Verbose: all results
    if verbose:
        console.print("\n[bold]All tests:[/bold]")
        for r in report.results:
            status = "[green]PASS[/green]" if r.passed else "[red]FAIL[/red]"
            console.print(f"  {status} {r.test_name}: {r.details}")

    if report.failed > 0:
        raise typer.Exit(code=1)


@app.command()
def status(
    policy: Optional[Path] = typer.Option(
        None, "--policy", "-p", help="Path to policy YAML"
    ),
) -> None:
    """Show engine status and loaded policy summary."""
    engine = AuditEngine(policy_path=policy)
    info = engine.get_status()

    table = Table(title="AgentAuditor Status", show_header=False)
    table.add_column("Key", style="bold")
    table.add_column("Value")

    for key, value in info.items():
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        table.add_row(key.replace("_", " ").title(), str(value))

    console.print(table)
