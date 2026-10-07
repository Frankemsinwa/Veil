"""Veil Benchmark Suite — Latency, Throughput, and ReDoS Immunity Profiler."""
import time
import statistics
from typing import List, Dict, Any
from dataclasses import dataclass

from app.engine.pipeline import InspectionPipeline
from app.engine.redactor import Redactor
from app.vault.session_vault import SessionVault


@dataclass
class BenchmarkReport:
    total_prompts: int
    total_characters: int
    duration_seconds: float
    prompts_per_sec: float
    characters_per_sec: float
    mean_latency_ms: float
    median_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    redos_immune: bool
    redos_test_duration_ms: float


class VeilBenchmark:
    """Profiles latency and tests linear-time execution against ReDoS attacks."""

    SAMPLE_PROMPTS = [
        "What is the time complexity of merge sort in computer science?",
        "Please send the confidential invoice to accounting-dept@enterprise-corp.com today.",
        "Can you help me write an API client for https://api.example.com using Python httpx?",
        "Please update phone record for user 442 to +1-555-839-2041 before tomorrow morning.",
        "In our test suite, make sure to assert that user@example.com connects to 127.0.0.1.",
        "Here is the billing card to process the subscription: 4532-0151-1283-0366 expiring 12/28.",
        "Explain the fundamental difference between TCP flow control and congestion avoidance.",
        "Contact Sarah at sarah.connor@cyberdyne.net or call +1-555-837-2918 regarding the system.",
    ]

    def __init__(self):
        self.pipeline = InspectionPipeline()
        self.redactor = Redactor()

    def run_benchmark(self, iterations: int = 50) -> BenchmarkReport:
        """Runs iterative inspection benchmark measuring latency distributions and throughput."""
        vault = SessionVault("benchmark_session")
        latencies_ms: List[float] = []
        total_chars = 0
        total_runs = len(self.SAMPLE_PROMPTS) * iterations

        start_time = time.perf_counter()

        for _ in range(iterations):
            for prompt in self.SAMPLE_PROMPTS:
                total_chars += len(prompt)
                t0 = time.perf_counter()
                decisions, redact_spans = self.pipeline.inspect(prompt)
                if redact_spans:
                    self.redactor.redact_text(prompt, redact_spans, vault)
                latencies_ms.append((time.perf_counter() - t0) * 1000.0)

        total_duration = time.perf_counter() - start_time
        prompts_per_sec = total_runs / total_duration if total_duration > 0 else 0.0
        chars_per_sec = total_chars / total_duration if total_duration > 0 else 0.0

        sorted_latencies = sorted(latencies_ms)
        p95_idx = int(len(sorted_latencies) * 0.95)
        p99_idx = int(len(sorted_latencies) * 0.99)

        # ReDoS Immunity test: Large pathological nested string of 50,000 characters
        redos_immune, redos_ms = self.test_redos_immunity()

        return BenchmarkReport(
            total_prompts=total_runs,
            total_characters=total_chars,
            duration_seconds=total_duration,
            prompts_per_sec=round(prompts_per_sec, 1),
            characters_per_sec=round(chars_per_sec, 1),
            mean_latency_ms=round(statistics.mean(latencies_ms), 3),
            median_latency_ms=round(statistics.median(latencies_ms), 3),
            p95_latency_ms=round(sorted_latencies[p95_idx], 3),
            p99_latency_ms=round(sorted_latencies[p99_idx], 3),
            redos_immune=redos_immune,
            redos_test_duration_ms=round(redos_ms, 2)
        )

    def test_redos_immunity(self) -> (bool, float):
        """Validates that regex engine does not exhibit catastrophic backtracking on large strings."""
        # 50,000 chars of repeated prefix designed to trigger catastrophic backtracking in unanchored regexes
        pathological_input = ("a" * 1000 + "!") * 50
        t0 = time.perf_counter()
        self.pipeline.inspect(pathological_input)
        duration_ms = (time.perf_counter() - t0) * 1000.0

        # Linear-time scan of 50k chars should easily execute under 500ms
        is_immune = duration_ms < 500.0
        return is_immune, duration_ms
