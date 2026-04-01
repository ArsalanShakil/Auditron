"""Latency benchmarks for the audit pipeline."""

import asyncio
import time

import pytest

from agentauditor.core.engine import AuditEngine


@pytest.mark.asyncio
async def test_deterministic_latency_clean(engine: AuditEngine):
    """Clean input should evaluate in < 2ms."""
    times = []
    for _ in range(100):
        start = time.monotonic()
        await engine.scan_input("Help me write a Python function")
        elapsed = (time.monotonic() - start) * 1000
        times.append(elapsed)

    avg = sum(times) / len(times)
    p95 = sorted(times)[94]
    assert avg < 2.0, f"Average latency {avg:.2f}ms exceeds 2ms"
    assert p95 < 5.0, f"P95 latency {p95:.2f}ms exceeds 5ms"


@pytest.mark.asyncio
async def test_deterministic_latency_malicious(engine: AuditEngine):
    """Malicious input should evaluate in < 2ms (deterministic path)."""
    times = []
    for _ in range(100):
        start = time.monotonic()
        await engine.intercept_tool_call("bash", {"command": "rm -rf /"})
        elapsed = (time.monotonic() - start) * 1000
        times.append(elapsed)

    avg = sum(times) / len(times)
    p95 = sorted(times)[94]
    assert avg < 2.0, f"Average latency {avg:.2f}ms exceeds 2ms"
    assert p95 < 5.0, f"P95 latency {p95:.2f}ms exceeds 5ms"


@pytest.mark.asyncio
async def test_throughput_sequential(engine: AuditEngine):
    """Measure sequential throughput (actions/second)."""
    count = 500
    start = time.monotonic()
    for _ in range(count):
        await engine.scan_input("Hello world")
    elapsed = time.monotonic() - start

    throughput = count / elapsed
    assert throughput > 1000, f"Throughput {throughput:.0f} ops/s below 1000"


@pytest.mark.asyncio
async def test_throughput_concurrent(engine: AuditEngine):
    """Measure concurrent throughput."""
    count = 100
    start = time.monotonic()
    tasks = [engine.scan_input("Hello world") for _ in range(count)]
    await asyncio.gather(*tasks)
    elapsed = time.monotonic() - start

    throughput = count / elapsed
    assert throughput > 500, f"Concurrent throughput {throughput:.0f} ops/s below 500"
