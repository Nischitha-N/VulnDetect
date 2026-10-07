"""
Layer 6: Finding Deduplication & Multi-Analyzer Correlation Engine.
Correlates overlapping findings across Regex, AST, and Taint engines, aggregating evidence and boosting confidence.
"""

from typing import List, Dict, Tuple
from app.engine.base import Finding, AnalyzerSource, Severity


class FindingDeduplicator:
    """Merges and correlates findings from multiple analyzer sources."""

    @staticmethod
    def _cwe_root(cwe: str) -> str:
        return cwe.upper().strip()

    def deduplicate(self, findings: List[Finding]) -> List[Finding]:
        if not findings:
            return []

        # Group findings by (file, line, root CWE category)
        groups: Dict[Tuple[str, int, str], List[Finding]] = {}

        for f in findings:
            key = (f.file, f.line, self._cwe_root(f.cwe))
            groups.setdefault(key, []).append(f)

        consolidated: List[Finding] = []

        for key, group in groups.items():
            if len(group) == 1:
                consolidated.append(group[0])
                continue

            # Multi-analyzer agreement: Select primary finding with highest severity and confidence
            primary = max(group, key=lambda x: (self._severity_rank(x.severity), x.confidence, x.risk_score))

            # Collect unique evidence items
            all_evidence = []
            seen_evidence = set()
            sources_present = set()
            dataflow_path = primary.dataflow_path

            for item in group:
                sources_present.add(item.analyzer_source)
                if not dataflow_path and item.dataflow_path:
                    dataflow_path = item.dataflow_path
                for ev in item.evidence:
                    ev_key = (ev.analyzer_source, ev.description)
                    if ev_key not in seen_evidence:
                        seen_evidence.add(ev_key)
                        all_evidence.append(ev)

            # If findings came from different analyzers, promote source to MULTI_ANALYZER
            if len(sources_present) > 1:
                primary.analyzer_source = AnalyzerSource.MULTI_ANALYZER
                # Boost confidence based on multi-analyzer consensus
                boosted_conf = min(0.99, primary.confidence + (0.05 * (len(sources_present) - 1)))
                boosted_risk = min(1.0, primary.risk_score * 1.10)
                primary.confidence = round(boosted_conf, 2)
                primary.risk_score = round(boosted_risk, 2)
                primary.vulnerability_type = primary.vulnerability_type.replace("AST: ", "").replace("Taint: ", "")

            primary.evidence = all_evidence
            primary.dataflow_path = dataflow_path
            consolidated.append(primary)

        # Sort findings by line number
        consolidated.sort(key=lambda f: (f.line, -f.risk_score))
        return consolidated

    @staticmethod
    def _severity_rank(sev: Severity) -> int:
        ranks = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return ranks.get(sev, 1)
