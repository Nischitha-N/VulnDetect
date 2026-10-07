"""
Semantic Taint Analysis Layer for VulnDetect.
Pluggable multi-layer static analysis component tracking SOURCE -> PROPAGATION -> TRANSFORMATION -> SANITIZER -> SINK.
"""

from typing import List, Optional
from app.engine.base import BaseAnalyzer, AnalyzerSource, Finding, AnalysisContext
from app.engine.taint.spec import TaintConfigManager
from app.engine.taint.engine import SemanticTaintEngine


class TaintAnalyzer(BaseAnalyzer):
    """
    Configurable Semantic Taint Analysis layer.
    """

    name: str = "taint_analyzer"
    source_type: AnalyzerSource = AnalyzerSource.TAINT

    def __init__(self, config_manager: Optional[TaintConfigManager] = None):
        self.config_manager: TaintConfigManager = config_manager or TaintConfigManager()
        self.engine: SemanticTaintEngine = SemanticTaintEngine(self.config_manager)

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        return self.engine.analyze(context)
