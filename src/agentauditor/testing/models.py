"""Data models for adversarial testing results."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TestResult:
    """Result of a single adversarial test case."""

    test_name: str
    technique: str
    expected_decision: str
    actual_decision: str
    passed: bool
    details: str


@dataclass
class VerificationReport:
    """Aggregated results from an adversarial verification run."""

    total_tests: int
    passed: int
    failed: int
    coverage_by_rule: dict[str, bool] = field(default_factory=dict)
    evasion_gaps: list[str] = field(default_factory=list)
    results: list[TestResult] = field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        return self.passed / self.total_tests if self.total_tests > 0 else 0.0

    def summary(self) -> str:
        lines = [
            f"Adversarial Verification Report",
            f"{'=' * 40}",
            f"Total tests: {self.total_tests}",
            f"Passed: {self.passed} ({self.pass_rate:.0%})",
            f"Failed: {self.failed}",
        ]
        if self.evasion_gaps:
            lines.append(f"\nEvasion gaps found:")
            for gap in self.evasion_gaps:
                lines.append(f"  - {gap}")
        if self.coverage_by_rule:
            covered = sum(1 for v in self.coverage_by_rule.values() if v)
            total = len(self.coverage_by_rule)
            lines.append(f"\nRule coverage: {covered}/{total}")
            for rule_id, hit in self.coverage_by_rule.items():
                status = "COVERED" if hit else "NOT TESTED"
                lines.append(f"  [{status}] {rule_id}")
        return "\n".join(lines)
