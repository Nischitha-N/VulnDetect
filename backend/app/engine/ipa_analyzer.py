"""
Inter-Procedural Security Analyzer for VulnDetect.
Pluggable static analysis layer using bottom-up function summaries to discover
cross-function vulnerabilities (Inter-procedural Command Injection, UAF, Double Free, Leaks).
"""

from typing import List, Optional
from app.engine.base import BaseAnalyzer, AnalyzerSource, Finding, AnalysisContext
from app.engine.ipa.engine import InterProceduralEngine
from app.engine.taint.spec import TaintConfigManager


class InterProceduralAnalyzer(BaseAnalyzer):
    """
    Function-Summary based Inter-Procedural Static Analyzer.
    """

    name: str = "ipa_analyzer"
    source_type: AnalyzerSource = AnalyzerSource.IPA

    def __init__(self, taint_config: Optional[TaintConfigManager] = None):
        self.taint_config: TaintConfigManager = taint_config or TaintConfigManager()
        self.engine: InterProceduralEngine = InterProceduralEngine(self.taint_config)

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        return self.engine.analyze(context)

    def build_project_summaries(self, contexts: List[AnalysisContext]):
        self.engine.build_project_summaries(contexts)

    def clear_project_summaries(self):
        self.engine.clear_project_summaries()

