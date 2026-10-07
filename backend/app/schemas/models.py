from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class VulnerabilityResult(BaseModel):
    file: str
    line: int
    vulnerability: str
    risk_score: float = Field(ge=0.0, le=1.0)
    explanation: str
    fix: str
    code_snippet: Optional[str] = None
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    rule_id: Optional[str] = None
    cwe: Optional[str] = None
    column: Optional[int] = None
    analyzer_source: Optional[str] = None  # regex, ast, taint, dataflow, multi_analyzer
    analysis_status: Optional[str] = "LIKELY"  # CONFIRMED, LIKELY, NEEDS_REVIEW
    confidence: Optional[float] = None
    dataflow_path: Optional[List[Dict[str, Any]]] = None
    evidence: Optional[List[Dict[str, Any]]] = None
    assumptions: Optional[List[str]] = None
    unknowns: Optional[List[str]] = None
    analysis_limitations: Optional[List[str]] = None
    recommended_manual_verification: Optional[List[str]] = None
    deterministic_result: Optional[Dict[str, Any]] = None
    llm_assessment: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None



class ScanSummary(BaseModel):
    total_files: int
    total_vulnerabilities: int
    high_risk: int
    medium_risk: int
    low_risk: int
    scan_duration_ms: int
    vulnerability_types: dict
    analyzer_breakdown: Optional[Dict[str, int]] = None


class ScanResponse(BaseModel):
    scan_id: str
    timestamp: datetime
    results: List[VulnerabilityResult]
    summary: ScanSummary


class ScanRecord(BaseModel):
    scan_id: str
    timestamp: datetime
    results: List[dict]
    summary: dict
