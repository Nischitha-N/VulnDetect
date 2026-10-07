"""
Layer 1: Rule-based & Lexical Analyzer.
Preserves existing regex rules and adds high-confidence lexical checks behind the BaseAnalyzer interface.
"""

import re
import os
from typing import List, Dict, Any
from app.engine.base import BaseAnalyzer, Finding, AnalyzerSource, Severity, EvidenceItem, AnalysisContext


class RuleAnalyzer(BaseAnalyzer):
    name = "rule_analyzer"
    source_type = AnalyzerSource.REGEX

    def __init__(self):
        self.rules = [
            {
                "rule_id": "RULE-GETS-001",
                "cwe": "CWE-242",
                "pattern": re.compile(r'\bgets\s*\('),
                "vuln_type": "Unsafe API: gets()",
                "severity": Severity.CRITICAL,
                "confidence": 0.98,
                "risk_score": 0.95,
                "message": "gets() performs no bounds checking on user input and was removed from C11.",
                "remediation": "Replace gets(buf) with fgets(buf, sizeof(buf), stdin).",
            },
            {
                "rule_id": "RULE-STRCPY-002",
                "cwe": "CWE-120",
                "pattern": re.compile(r'\bstrcpy\s*\('),
                "vuln_type": "Unsafe API: strcpy()",
                "severity": Severity.HIGH,
                "confidence": 0.85,
                "risk_score": 0.82,
                "message": "strcpy() copies strings without destination buffer size enforcement.",
                "remediation": "Replace with strncpy(dst, src, sizeof(dst)-1) and ensure null termination, or use snprintf().",
            },
            {
                "rule_id": "RULE-STRCAT-003",
                "cwe": "CWE-120",
                "pattern": re.compile(r'\bstrcat\s*\('),
                "vuln_type": "Unsafe API: strcat()",
                "severity": Severity.HIGH,
                "confidence": 0.85,
                "risk_score": 0.80,
                "message": "strcat() appends without bounds checking, risking destination buffer overflow.",
                "remediation": "Replace with strncat(dst, src, sizeof(dst)-strlen(dst)-1).",
            },
            {
                "rule_id": "RULE-SPRINTF-004",
                "cwe": "CWE-134",
                "pattern": re.compile(r'\bsprintf\s*\('),
                "vuln_type": "Unsafe API: sprintf()",
                "severity": Severity.HIGH,
                "confidence": 0.85,
                "risk_score": 0.78,
                "message": "sprintf() writes unbounded output into destination buffer.",
                "remediation": "Replace sprintf(buf, fmt, ...) with snprintf(buf, sizeof(buf), fmt, ...).",
            },
            {
                "rule_id": "RULE-SCANF-005",
                "cwe": "CWE-120",
                "pattern": re.compile(r'\bscanf\s*\(\s*"[^"]*%s'),
                "vuln_type": "Unsafe API: scanf() with %s",
                "severity": Severity.HIGH,
                "confidence": 0.90,
                "risk_score": 0.85,
                "message": "scanf() with %s reads unbounded input into target buffer.",
                "remediation": "Use scanf(\"%255s\", buf) with explicit maximum field width or fgets().",
            },
            {
                "rule_id": "RULE-SYSTEM-006",
                "cwe": "CWE-78",
                "pattern": re.compile(r'\bsystem\s*\(\s*(?!\"|\')'),
                "vuln_type": "Command Injection Risk: system()",
                "severity": Severity.HIGH,
                "confidence": 0.80,
                "risk_score": 0.88,
                "message": "system() executes shell commands. If input contains user data, arbitrary command execution is possible.",
                "remediation": "Use execve() or POSIX spawn APIs with separated argument arrays and strict input validation.",
            },
            {
                "rule_id": "RULE-MALLOC-CHECK-007",
                "cwe": "CWE-476",
                "pattern": re.compile(r'\b(?:char|int|void|\w+)\s*\*\s*\w+\s*=\s*(?:\([^\)]*\)\s*)?malloc\s*\([^)]*\)\s*;(?!\s*(if|NULL))'),
                "vuln_type": "Memory: Unchecked malloc()",
                "severity": Severity.MEDIUM,
                "confidence": 0.65,
                "risk_score": 0.55,
                "message": "malloc() return value may be NULL upon allocation failure; dereferencing without check causes crash.",
                "remediation": "Always check for NULL: if (!ptr) { perror(\"malloc\"); exit(EXIT_FAILURE); }",
            },
            {
                "rule_id": "RULE-FORMAT-008",
                "cwe": "CWE-134",
                "pattern": re.compile(r'\bprintf\s*\(\s*[a-zA-Z_]\w*\s*\)'),
                "vuln_type": "Format String Vulnerability",
                "severity": Severity.CRITICAL,
                "confidence": 0.92,
                "risk_score": 0.90,
                "message": "Direct format string argument passed to printf() allows memory inspection and arbitrary writes.",
                "remediation": "Always use a constant format specifier: printf(\"%s\", user_str).",
            },
            {
                "rule_id": "RULE-TMPNAM-009",
                "cwe": "CWE-377",
                "pattern": re.compile(r'\b(?:tmpnam|tempnam)\s*\('),
                "vuln_type": "Insecure Temporary File: tmpnam()",
                "severity": Severity.HIGH,
                "confidence": 0.95,
                "risk_score": 0.82,
                "message": "tmpnam() creates predictable temporary filenames susceptible to TOCTOU race conditions.",
                "remediation": "Use mkstemp() or mkdtemp() which safely create and open unique temporary files atomically.",
            },
            {
                "rule_id": "RULE-RAND-010",
                "cwe": "CWE-338",
                "pattern": re.compile(r'\b(?:rand|srand|drand48)\s*\('),
                "vuln_type": "Insecure Randomness: rand()",
                "severity": Severity.LOW,
                "confidence": 0.70,
                "risk_score": 0.35,
                "message": "Standard rand() is pseudo-random and cryptographically insecure.",
                "remediation": "Use arc4random_buf(), getrandom(), or OpenSSL RAND_bytes() for security-sensitive operations.",
            },
            {
                "rule_id": "RULE-CHMOD-011",
                "cwe": "CWE-732",
                "pattern": re.compile(r'\bchmod\s*\([^,]+,\s*(?:0777|777|S_IRWXU\s*\|\s*S_IRWXG\s*\|\s*S_IRWXO)\s*\)'),
                "vuln_type": "Insecure File Permissions: chmod 777",
                "severity": Severity.MEDIUM,
                "confidence": 0.90,
                "risk_score": 0.65,
                "message": "Setting world-writable permissions (0777) allows any local user to modify or execute the file.",
                "remediation": "Restrict permissions to minimum required privileges (e.g., 0600 or 0750).",
            },
            {
                "rule_id": "RULE-SECRET-012",
                "cwe": "CWE-798",
                "pattern": re.compile(r'(?i)(?:password|passwd|secret|api_key|private_key)\s*=\s*"[^"]{6,}"'),
                "vuln_type": "Hardcoded Credential",
                "severity": Severity.HIGH,
                "confidence": 0.80,
                "risk_score": 0.78,
                "message": "Hardcoded password or private secret discovered in source code.",
                "remediation": "Store secrets in environment variables or a dedicated key management service (KMS).",
            },
        ]

    def _get_snippet(self, lines: List[str], line_idx: int) -> str:
        start = max(0, line_idx - 2)
        end = min(len(lines), line_idx + 3)
        return "\n".join(f"{start + i + 1}: {l}" for i, l in enumerate(lines[start:end]))

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        findings: List[Finding] = []
        filename = os.path.basename(context.file_path)

        for line_no, line in enumerate(context.lines, start=1):
            stripped = line.strip()
            # Ignore pure comment lines
            if not stripped or stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            for rule in self.rules:
                match = rule["pattern"].search(line)
                if match:
                    snippet = self._get_snippet(context.lines, line_no - 1)
                    evidence = EvidenceItem(
                        analyzer_source=self.source_type,
                        description=f"Matched regex pattern: `{rule['pattern'].pattern}`",
                        confidence=rule["confidence"],
                        metadata={"matched_text": match.group(0)},
                    )
                    findings.append(Finding(
                        rule_id=rule["rule_id"],
                        cwe=rule["cwe"],
                        vulnerability_type=rule["vuln_type"],
                        severity=rule["severity"],
                        confidence=rule["confidence"],
                        file=filename,
                        line=line_no,
                        column=match.start() + 1,
                        message=rule["message"],
                        remediation=rule["remediation"],
                        code_snippet=snippet,
                        analyzer_source=self.source_type,
                        evidence=[evidence],
                        risk_score=rule["risk_score"],
                    ))

        return findings
