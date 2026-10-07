"""
VulnDetect Inter-Procedural Analysis (IPA) Package.
"""

from app.engine.ipa.summary import FunctionSummary, ParameterEffect
from app.engine.ipa.callgraph import CallSite, CallGraph
from app.engine.ipa.summarizer import FunctionSummarizer
from app.engine.ipa.engine import InterProceduralEngine

__all__ = [
    "FunctionSummary",
    "ParameterEffect",
    "CallSite",
    "CallGraph",
    "FunctionSummarizer",
    "InterProceduralEngine",
]
