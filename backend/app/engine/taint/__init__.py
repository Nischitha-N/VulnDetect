"""
VulnDetect Semantic Taint Analysis Package.
"""

from app.engine.taint.spec import (
    TaintState,
    TaintSourceSpec,
    TaintSinkSpec,
    TaintSanitizerSpec,
    TaintConfigManager,
)
from app.engine.taint.tracker import TaintTrackedValue, TaintEnvironment
from app.engine.taint.engine import SemanticTaintEngine

__all__ = [
    "TaintState",
    "TaintSourceSpec",
    "TaintSinkSpec",
    "TaintSanitizerSpec",
    "TaintConfigManager",
    "TaintTrackedValue",
    "TaintEnvironment",
    "SemanticTaintEngine",
]
