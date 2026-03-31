"""Tests for the adversarial self-test mode."""

import pytest

from agentauditor.core.engine import AuditEngine
from agentauditor.testing.adversarial import AdversarialVerifier
from agentauditor.testing.models import VerificationReport


@pytest.mark.asyncio
class TestAdversarialVerifier:
    async def test_run_full_suite_returns_report(self):
        engine = AuditEngine()
        verifier = AdversarialVerifier(engine)
        report = await verifier.run_full_suite()
        assert isinstance(report, VerificationReport)
        assert report.total_tests > 0
        assert report.passed + report.failed == report.total_tests

    async def test_rule_coverage_tests(self):
        engine = AuditEngine()
        verifier = AdversarialVerifier(engine)
        results = await verifier.test_rule_coverage()
        assert len(results) > 0
        # At least some rules should be covered
        passed = sum(1 for r in results if r.passed)
        assert passed > 0

    async def test_evasion_tests(self):
        engine = AuditEngine()
        verifier = AdversarialVerifier(engine)
        results = await verifier.test_evasion_techniques()
        assert len(results) > 0
        # Command substitution evasions should be caught
        cmd_sub_results = [r for r in results if "cmdsub" in r.test_name]
        assert len(cmd_sub_results) > 0

    async def test_chain_detection_tests(self):
        engine = AuditEngine()
        verifier = AdversarialVerifier(engine)
        results = await verifier.test_chain_detection()
        assert len(results) > 0

    async def test_boundary_probing_tests(self):
        engine = AuditEngine()
        verifier = AdversarialVerifier(engine)
        results = await verifier.test_boundary_probing()
        assert len(results) > 0

    async def test_report_summary(self):
        engine = AuditEngine()
        verifier = AdversarialVerifier(engine)
        report = await verifier.run_full_suite()
        summary = report.summary()
        assert "Adversarial Verification Report" in summary
        assert "Total tests:" in summary

    async def test_pass_rate_calculation(self):
        report = VerificationReport(total_tests=10, passed=7, failed=3)
        assert report.pass_rate == 0.7

    async def test_empty_report(self):
        report = VerificationReport(total_tests=0, passed=0, failed=0)
        assert report.pass_rate == 0.0
