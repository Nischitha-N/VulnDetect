"""
C++ Semantic Security Analyzer for VulnDetect.
Pluggable static analysis layer dedicated to modern C++ RAII, move semantics,
smart pointers, iterator invalidation, polymorphic destruction, and new/delete mismatches.
"""

from typing import List
from app.engine.base import BaseAnalyzer, AnalyzerSource, Finding, AnalysisContext
from app.engine.cpp.analyzer_engine import CppSemanticEngine


class CppAnalyzer(BaseAnalyzer):
    """
    Dedicated C++ Semantic Static Analyzer.
    """

    name: str = "cpp_analyzer"
    source_type: AnalyzerSource = AnalyzerSource.CPP

    def __init__(self):
        self.engine: CppSemanticEngine = CppSemanticEngine()

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        # Trigger on C++ files or files containing C++ constructs
        source = context.source_code
        is_cpp_code = (
            context.is_cpp or
            any(k in source for k in ("class ", "namespace ", "std::", "template<", "new ", "delete ", "virtual ", "reinterpret_cast"))
        )

        if not is_cpp_code:
            return []

        return self.engine.analyze(context)
