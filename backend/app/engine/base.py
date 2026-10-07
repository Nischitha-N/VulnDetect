"""
Base abstractions, finding data model, and analyzer interface for VulnDetect engine.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional


class AnalyzerSource(str, Enum):
    REGEX = "regex"
    AST = "ast"
    DATAFLOW = "dataflow"
    TAINT = "taint"
    RANGE = "range"
    CFG = "cfg"
    IPA = "ipa"
    CPP = "cpp"
    ML = "ml"
    LLM = "llm"
    MULTI_ANALYZER = "multi_analyzer"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AnalysisStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    NEEDS_REVIEW = "NEEDS_REVIEW"


@dataclass
class DataflowStep:
    step_type: str  # "SOURCE", "PROPAGATION", "SANITIZER", "SINK"
    line: int
    column: Optional[int]
    code: str
    description: str


@dataclass
class EvidenceItem:
    analyzer_source: AnalyzerSource
    description: str
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMAssessment:
    reviewed: bool = False
    verdict: str = "inconclusive"  # "likely_vulnerable", "likely_benign", "inconclusive", "INSUFFICIENT_CONTEXT"
    confidence_adjustment: float = 0.0  # Bounded strictly within [-0.20, +0.10]
    what_is_proven: str = ""
    what_is_suggested: str = ""
    assumptions: List[str] = field(default_factory=list)
    missing_context: List[str] = field(default_factory=list)
    sanitizer_evidence: Optional[str] = None
    sink_sensitive_in_context: bool = True
    potential_false_positive: bool = False
    potential_false_positive_reason: str = ""
    human_inspection_targets: List[str] = field(default_factory=list)
    remediation_advice: str = ""
    recommended_test: str = ""
    supporting_evidence: List[str] = field(default_factory=list)
    contradicting_evidence: List[str] = field(default_factory=list)
    missing_information: List[str] = field(default_factory=list)
    human_inspection_advice: List[str] = field(default_factory=list)
    raw_explanation: str = ""


@dataclass
class Finding:
    rule_id: str
    cwe: str
    vulnerability_type: str
    severity: Severity
    confidence: float  # 0.0 to 1.0 (calibrated)
    file: str
    line: int
    column: Optional[int] = None
    message: str = ""
    remediation: str = ""
    code_snippet: Optional[str] = None
    analyzer_source: AnalyzerSource = AnalyzerSource.REGEX
    analysis_status: AnalysisStatus = AnalysisStatus.LIKELY
    evidence: List[EvidenceItem] = field(default_factory=list)
    dataflow_path: List[DataflowStep] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    analysis_limitations: List[str] = field(default_factory=list)
    recommended_manual_verification: List[str] = field(default_factory=list)
    deterministic_result: Dict[str, Any] = field(default_factory=dict)
    llm_assessment: Optional[LLMAssessment] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.5  # Calculated by scorer



@dataclass
class AnalysisContext:
    file_path: str
    source_code: str
    lines: List[str]
    is_cpp: bool = False
    ast_root: Any = None  # Tree-sitter tree or Node
    tree_sitter_tree: Any = None


class BaseAnalyzer:
    """Base class for all pluggable static analyzers."""

    name: str = "base_analyzer"
    source_type: AnalyzerSource = AnalyzerSource.REGEX

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """Analyze the source code context and return detected findings."""
        raise NotImplementedError
