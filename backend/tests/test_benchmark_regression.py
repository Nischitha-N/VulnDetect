"""
Automated Benchmark Regression Test Suite.
Guarantees that future code changes maintain high precision and recall
without silent detection regression or precision collapse.
"""

import pytest
import os
import sys

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.benchmark.runner import BenchmarkRunner
from tests.benchmark.manifest import BENCHMARK_FIXTURES


class TestBenchmarkRegression:
    """Regression gates for VulnDetect engine architectures."""

    @pytest.fixture(scope="module")
    def benchmark_results(self):
        runner = BenchmarkRunner()
        return runner.run_all(BENCHMARK_FIXTURES)

    def test_full_engine_high_recall_and_precision(self, benchmark_results):
        full = benchmark_results["FULL_ENGINE"]
        
        # High quality gates:
        assert full.precision >= 0.85, f"Full engine precision ({full.precision:.2f}) dropped below 85%"
        assert full.recall >= 0.85, f"Full engine recall ({full.recall:.2f}) dropped below 85%"
        assert full.f1 >= 0.85, f"Full engine F1 score ({full.f1:.2f}) dropped below 85%"
        assert full.parser_failures == 0, f"Encountered {full.parser_failures} parser failures in benchmark corpus"

    def test_full_engine_outperforms_regex_baseline(self, benchmark_results):
        full = benchmark_results["FULL_ENGINE"]
        regex = benchmark_results["BASELINE_REGEX"]

        # Full engine must significantly outperform simplistic regex rules in F1 and recall
        assert full.f1 > regex.f1, f"Full engine F1 ({full.f1:.2f}) did not beat regex baseline ({regex.f1:.2f})"
        assert full.recall > regex.recall, f"Full engine recall ({full.recall:.2f}) did not beat regex baseline ({regex.recall:.2f})"
        assert full.precision >= 0.85, f"Full engine precision ({full.precision:.2f}) dropped below 85%"

    def test_layer_progression_metrics(self, benchmark_results):
        ast_only = benchmark_results["AST_ONLY"]
        cfg = benchmark_results["AST_CFG"]
        full = benchmark_results["FULL_ENGINE"]

        # Full engine should have higher detection capability than AST only
        assert full.tp >= ast_only.tp
