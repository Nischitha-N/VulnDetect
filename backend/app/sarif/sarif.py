"""
OASIS SARIF v2.1.0 report generator for VulnDetect findings.
Compatible with GitHub Advanced Security, VS Code SARIF Viewer, and CI/CD pipelines.
"""

from typing import List, Dict, Any
from app.schemas.models import VulnerabilityResult


def generate_sarif_report(results: List[VulnerabilityResult], scan_id: str) -> Dict[str, Any]:
    """Convert scan findings to OASIS SARIF v2.1.0 format."""
    rules_dict: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []

    for r in results:
        rule_id = getattr(r, "rule_id", None) or f"VULN-{r.vulnerability.replace(' ', '-').upper()}"
        cwe = getattr(r, "cwe", None) or "CWE-119"

        # Build markdown help including uncertainty and manual verification
        help_md = f"### Remediation\n{r.fix}\n\n**CWE:** [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html)"
        if getattr(r, "analysis_limitations", None):
            lims = "\n".join(f"- {lim}" for lim in r.analysis_limitations)
            help_md += f"\n\n### Analysis Limitations\n{lims}"
        if getattr(r, "recommended_manual_verification", None):
            verifs = "\n".join(f"- [ ] {step}" for step in r.recommended_manual_verification)
            help_md += f"\n\n### Recommended Manual Verification\n{verifs}"

        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": r.vulnerability,
                "shortDescription": {"text": r.vulnerability},
                "fullDescription": {"text": r.explanation},
                "help": {
                    "text": f"Remediation: {r.fix}",
                    "markdown": help_md,
                },
                "properties": {
                    "tags": ["security", "c-cpp", cwe.lower()],
                    "precision": "high" if getattr(r, "analysis_status", "LIKELY") == "CONFIRMED" else "medium",
                },
            }

        # Map severity to SARIF level
        level_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }
        level = level_map.get(r.severity.upper(), "warning")

        sarif_results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"[{getattr(r, 'analysis_status', 'LIKELY')}] {r.explanation} (Fix: {r.fix})",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": r.file,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": r.line,
                            "startColumn": getattr(r, "column", 1) or 1,
                        },
                    },
                }
            ],
            "properties": {
                "cwe": cwe,
                "risk_score": r.risk_score,
                "analyzer_source": getattr(r, "analyzer_source", "ast"),
                "analysis_status": getattr(r, "analysis_status", "LIKELY"),
                "assumptions": getattr(r, "assumptions", []),
                "unknowns": getattr(r, "unknowns", []),
                "analysis_limitations": getattr(r, "analysis_limitations", []),
                "recommended_manual_verification": getattr(r, "recommended_manual_verification", []),
                "llm_assessment": getattr(r, "llm_assessment", None),
            },
        })


    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VulnDetect",
                        "semanticVersion": "2.0.0",
                        "informationUri": "https://github.com/Nischitha-N/VulnDetect",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": sarif_results,
                "properties": {
                    "scan_id": scan_id,
                },
            }
        ],
    }
