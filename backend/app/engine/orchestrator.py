"""
Pluggable Analysis Orchestrator for VulnDetect.
Coordinates parsing, multi-layer analyzers, deduplication, and risk prioritization.
"""

from typing import List, Tuple, Optional
from app.engine.base import Finding, AnalysisContext
from app.engine.parser import parse_source
from app.engine.rule_analyzer import RuleAnalyzer
from app.engine.ast_analyzer import ASTAnalyzer
from app.engine.advanced_ast_analyzer import AdvancedASTAnalyzer
from app.engine.taint_analyzer import TaintAnalyzer
from app.engine.range_analyzer import RangeAnalyzer
from app.engine.cfg_analyzer import CFGAnalyzer
from app.engine.ipa_analyzer import InterProceduralAnalyzer
from app.engine.cpp_analyzer import CppAnalyzer
from app.engine.deduplicator import FindingDeduplicator
from app.engine.uncertainty_analyzer import UncertaintyAnalyzer
from app.engine.heuristic_reviewer import HeuristicAmbiguityReviewer
from app.engine.scorer import FindingScorer
from app.ml.predictor import get_ml_predictor


class AnalysisOrchestrator:
    """Master pipeline orchestrating all static analysis layers and uncertainty reasoning."""

    def __init__(self):
        self.analyzers = [
            RuleAnalyzer(),
            ASTAnalyzer(),
            AdvancedASTAnalyzer(),
            TaintAnalyzer(),
            RangeAnalyzer(),
            CFGAnalyzer(),
            InterProceduralAnalyzer(),
            CppAnalyzer(),
        ]
        self.deduplicator = FindingDeduplicator()
        self.uncertainty_analyzer = UncertaintyAnalyzer()
        self.heuristic_reviewer = HeuristicAmbiguityReviewer(enabled=True)
        self.ml_predictor = get_ml_predictor()
        self.scorer = FindingScorer()

    def analyze_file(self, file_path: str, source_code: str) -> List[Finding]:
        """Execute full multi-layer analysis pipeline on a single C/C++ source file."""
        # 1. Parse source into Tree-sitter AST & AnalysisContext
        context: AnalysisContext = parse_source(source_code, file_path)

        # 2. Collect findings from all registered analyzers
        raw_findings: List[Finding] = []
        for analyzer in self.analyzers:
            try:
                results = analyzer.analyze(context)
                raw_findings.extend(results)
            except Exception as e:
                # Fault-tolerant: log error and continue with other analyzers
                print(f"[Orchestrator] Warning: Analyzer '{analyzer.name}' failed on {file_path}: {e}")

        # 3. Deduplicate and correlate multi-analyzer findings
        deduped_findings = self.deduplicator.deduplicate(raw_findings)

        # 4. Uncertainty & Unknown Behavior Analysis (classify CONFIRMED / LIKELY / NEEDS_REVIEW)
        evaluated_findings = self.uncertainty_analyzer.evaluate_findings(deduped_findings, context)

        # 5. Heuristic review of ambiguous findings (preserves deterministic facts)
        reviewed_findings = self.heuristic_reviewer.review_findings(evaluated_findings, context)

        # 6. ML finding-level auxiliary verification (preserves all findings, non-destructive)
        verified_findings = self.ml_predictor.verify_findings(reviewed_findings)

        # 7. Score and calibrate risk levels
        final_findings = self.scorer.score_findings(verified_findings)

        return final_findings

    def analyze_project(self, files: List[Tuple[str, str]]) -> List[Finding]:
        """
        Execute multi-file project analysis:
        Phase 1: Parse all files and compute bottom-up project-wide function summaries.
        Phase 2: Execute multi-layer analyzers per file using project summaries for cross-file reasoning.
        """
        # 1. Parse all files into AnalysisContext objects
        contexts: List[AnalysisContext] = []
        for file_path, source_code in files:
            ctx = parse_source(source_code, file_path)
            contexts.append(ctx)

        # 2. Phase 1: Build project-wide summaries across all compilation units
        ipa: Optional[InterProceduralAnalyzer] = None
        for a in self.analyzers:
            if isinstance(a, InterProceduralAnalyzer):
                ipa = a
                break

        if ipa:
            ipa.build_project_summaries(contexts)

        # 3. Phase 2: Analyze each file using the shared project summaries
        all_final_findings: List[Finding] = []
        try:
            for context in contexts:
                raw_findings: List[Finding] = []
                for analyzer in self.analyzers:
                    try:
                        results = analyzer.analyze(context)
                        raw_findings.extend(results)
                    except Exception as e:
                        print(f"[Orchestrator] Warning: Analyzer '{analyzer.name}' failed on {context.file_path}: {e}")

                deduped_findings = self.deduplicator.deduplicate(raw_findings)
                evaluated_findings = self.uncertainty_analyzer.evaluate_findings(deduped_findings, context)
                reviewed_findings = self.heuristic_reviewer.review_findings(evaluated_findings, context)
                verified_findings = self.ml_predictor.verify_findings(reviewed_findings)
                final_findings = self.scorer.score_findings(verified_findings)
                all_final_findings.extend(final_findings)
        finally:
            # Guarantee project store isolation across scans
            if ipa:
                ipa.clear_project_summaries()

        return all_final_findings


# Global orchestrator singleton
orchestrator = AnalysisOrchestrator()


