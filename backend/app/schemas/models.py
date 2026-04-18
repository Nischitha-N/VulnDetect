from pydantic import BaseModel, Field
from typing import List, Optional
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

class ScanSummary(BaseModel):
    total_files: int
    total_vulnerabilities: int
    high_risk: int
    medium_risk: int
    low_risk: int
    scan_duration_ms: int
    vulnerability_types: dict

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
