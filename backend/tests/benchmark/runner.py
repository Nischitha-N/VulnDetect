"""
VulnDetect Security Benchmark Evaluator.
Executes benchmark manifest across 6 architectural engine configurations,
computing Precision, Recall, F1, Findings/KLOC, Uncertainty Rate, and Latency.
"""

import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from app.engine.parser import parse_source
from app.engine.base import Finding, AnalysisStatus, AnalyzerSource
from app.engine.rule_analyzer import RuleAnalyzer
from app.engine.ast_analyzer import ASTAnalyzer
from app.engine.advanced_ast_analyzer import AdvancedASTAnalyzer
from app.engine.taint_analyzer import TaintAnalyzer
from app.engine.range_analyzer import RangeAnalyzer
from app.engine.cfg_analyzer import CFGAnalyzer
from app.engine.ipa_analyzer import InterProceduralAnalyzer
from app.engine.cpp_analyzer import CppAnalyzer
from app.engine.deduplicator import FindingDeduplicator
from app.engine.orchestrator import orchestrator
from tests.benchmark.manifest import BENCHMARK_FIXTURES, BenchmarkFixture


@dataclass
class BenchmarkMetrics:
    config_name: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    total_findings: int = 0
    needs_review_count: int = 0
    total_lines: int = 0
    elapsed_ms: float = 0.0
    parser_failures: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return (self.tp / denom) if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return (self.tp / denom) if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) > 0 else 0.0

    @property
    def findings_per_kloc(self) -> float:
        kloc = self.total_lines / 1000.0
        return (self.total_findings / kloc) if kloc > 0 else 0.0

    @property
    def uncertainty_rate(self) -> float:
        return (self.needs_review_count / self.total_findings) if self.total_findings > 0 else 0.0


class BenchmarkRunner:
    """Runs benchmark evaluation across multiple engine configurations."""

    CONFIGURATIONS = [
        "BASELINE_REGEX",
        "AST_ONLY",
        "AST_CFG",
        "AST_TAINT",
        "AST_IPA",
        "FULL_ENGINE",
    ]

    def _get_analyzers_for_config(self, config_name: str) -> List[Any]:
        if config_name == "BASELINE_REGEX":
            return [RuleAnalyzer()]
        elif config_name == "AST_ONLY":
            return [RuleAnalyzer(), ASTAnalyzer(), AdvancedASTAnalyzer()]
        elif config_name == "AST_CFG":
            return [ASTAnalyzer(), AdvancedASTAnalyzer(), CFGAnalyzer()]
        elif config_name == "AST_TAINT":
            return [ASTAnalyzer(), AdvancedASTAnalyzer(), TaintAnalyzer()]
        elif config_name == "AST_IPA":
            return [ASTAnalyzer(), AdvancedASTAnalyzer(), InterProceduralAnalyzer()]
        elif config_name == "FULL_ENGINE":
            return orchestrator.analyzers
        return []

    def evaluate_configuration(self, config_name: str, fixtures: List[BenchmarkFixture]) -> BenchmarkMetrics:
        metrics = BenchmarkMetrics(config_name=config_name)
        analyzers = self._get_analyzers_for_config(config_name)
        deduplicator = FindingDeduplicator()

        start_time = time.perf_counter()

        for fix in fixtures:
            code = fix.code.strip()
            lines = code.splitlines()
            metrics.total_lines += len(lines)

            # Parse source
            file_ext = "cpp" if fix.is_cpp else "c"
            file_name = f"{fix.name}.{file_ext}"
            ctx = parse_source(code, file_name)
            if not ctx.ast_root:
                metrics.parser_failures += 1

            # Run analyzers
            raw_findings: List[Finding] = []
            if config_name == "FULL_ENGINE":
                raw_findings = orchestrator.analyze_file(file_name, code)
            else:
                for analyzer in analyzers:
                    try:
                        raw_findings.extend(analyzer.analyze(ctx))
                    except Exception:
                        pass
                raw_findings = deduplicator.deduplicate(raw_findings)

            metrics.total_findings += len(raw_findings)
            metrics.needs_review_count += sum(1 for f in raw_findings if f.analysis_status == AnalysisStatus.NEEDS_REVIEW)

            if fix.is_vulnerable:
                has_detection = any(f.cwe == fix.cwe for f in raw_findings) if fix.cwe else len(raw_findings) > 0
                if has_detection:
                    metrics.tp += 1
                else:
                    metrics.fn += 1
            else:
                has_detection = len(raw_findings) > 0
                if has_detection:
                    metrics.fp += 1
                else:
                    metrics.tn += 1

        metrics.elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return metrics

    def run_all(self, fixtures: Optional[List[BenchmarkFixture]] = None) -> Dict[str, BenchmarkMetrics]:
        fix_list = fixtures or BENCHMARK_FIXTURES
        results: Dict[str, BenchmarkMetrics] = {}

        for cfg in self.CONFIGURATIONS:
            results[cfg] = self.evaluate_configuration(cfg, fix_list)

        return results

    def generate_markdown_report(self, results: Dict[str, BenchmarkMetrics]) -> str:
        lines = [
            "# VulnDetect Security Benchmarking Report",
            "",
            "| Architecture Configuration | TP | FP | FN | TN | Precision | Recall | F1 Score | Findings/KLOC | Uncertainty Rate | Latency (ms) |",
            "|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|",
        ]

        for name, m in results.items():
            lines.append(
                f"| **{name}** | {m.tp} | {m.fp} | {m.fn} | {m.tn} | "
                f"{m.precision * 100:.1f}% | {m.recall * 100:.1f}% | {m.f1 * 100:.1f}% | "
                f"{m.findings_per_kloc:.1f} | {m.uncertainty_rate * 100:.1f}% | {m.elapsed_ms:.1f}ms |"
            )

        return "\n".join(lines)


if __name__ == "__main__":
    runner = BenchmarkRunner()
    res = runner.run_all()
    report = runner.generate_markdown_report(res)
    print(report)
