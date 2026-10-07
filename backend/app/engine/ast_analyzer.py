"""
Layer 3: AST Security Rules Analyzer.
Queries Tree-sitter Concrete Syntax Trees to perform structural code inspection.
"""

import os
from typing import List, Optional, Set
from tree_sitter import Node

from app.engine.base import BaseAnalyzer, Finding, AnalyzerSource, Severity, EvidenceItem, AnalysisContext
from app.engine.parser import (
    get_node_text,
    get_node_location,
    get_call_expressions,
    get_call_name,
    get_call_arguments,
    find_nodes_by_type,
    get_function_definitions,
)


class ASTAnalyzer(BaseAnalyzer):
    name = "ast_analyzer"
    source_type = AnalyzerSource.AST

    def _get_snippet(self, lines: List[str], line_idx: int) -> str:
        start = max(0, line_idx - 2)
        end = min(len(lines), line_idx + 3)
        return "\n".join(f"{start + i + 1}: {l}" for i, l in enumerate(lines[start:end]))

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        if not context.ast_root:
            return []

        findings: List[Finding] = []
        filename = os.path.basename(context.file_path)
        source = context.source_code
        root: Node = context.ast_root

        # ─── 1. Check Function Calls (Format strings, Unsafe APIs, Command Execution, Allocations) ─
        call_nodes = get_call_expressions(root)

        for call in call_nodes:
            fn_name = get_call_name(call, source)
            if not fn_name:
                continue

            args = get_call_arguments(call)
            line, col = get_node_location(call)
            snippet = self._get_snippet(context.lines, line - 1)

            # Rule AST-FORMAT-001: Direct format string argument to printf/fprintf/syslog
            if fn_name in {"printf", "fprintf", "dprintf", "syslog"} and args:
                fmt_arg_idx = 1 if fn_name in {"fprintf", "dprintf"} else 0
                if len(args) > fmt_arg_idx:
                    fmt_node = args[fmt_arg_idx]
                    # If format arg is NOT a string_literal (e.g., identifier or expression)
                    if fmt_node.type not in {"string_literal", "concatenated_string"}:
                        arg_text = get_node_text(fmt_node, source)
                        findings.append(Finding(
                            rule_id="AST-FORMAT-001",
                            cwe="CWE-134",
                            vulnerability_type="AST: Non-Literal Format String",
                            severity=Severity.CRITICAL,
                            confidence=0.96,
                            file=filename,
                            line=line,
                            column=col,
                            message=f"Non-literal format string argument '{arg_text}' passed to {fn_name}().",
                            remediation=f"Pass a format string literal: {fn_name}(\"%s\", {arg_text});",
                            code_snippet=snippet,
                            analyzer_source=self.source_type,
                            evidence=[EvidenceItem(
                                analyzer_source=self.source_type,
                                description=f"AST call_expression to '{fn_name}' with non-string_literal node type '{fmt_node.type}'",
                                confidence=0.96,
                                metadata={"arg_type": fmt_node.type, "arg_text": arg_text},
                            )],
                            risk_score=0.92,
                        ))

            # Rule AST-CMD-002: Dynamic command execution with variable/expression
            if fn_name in {"system", "popen", "execlp", "execvp"} and args:
                cmd_node = args[0]
                if cmd_node.type not in {"string_literal"}:
                    cmd_text = get_node_text(cmd_node, source)
                    findings.append(Finding(
                        rule_id="AST-CMD-002",
                        cwe="CWE-78",
                        vulnerability_type="AST: Dynamic Command Execution",
                        severity=Severity.CRITICAL,
                        confidence=0.93,
                        file=filename,
                        line=line,
                        column=col,
                        message=f"Dynamic non-constant expression '{cmd_text}' passed to command executor {fn_name}().",
                        remediation="Avoid shell command strings. Use execve() with strict argument vectors and whitelist validation.",
                        code_snippet=snippet,
                        analyzer_source=self.source_type,
                        evidence=[EvidenceItem(
                            analyzer_source=self.source_type,
                            description=f"AST node '{cmd_node.type}' supplied to shell executor {fn_name}()",
                            confidence=0.93,
                            metadata={"cmd_expression": cmd_text},
                        )],
                        risk_score=0.91,
                    ))

            # Rule AST-ALLOC-003: Allocation without +1 for null terminator or sizeof pointer mismatch
            if fn_name in {"malloc", "calloc", "realloc"} and args:
                arg_text = get_node_text(args[0], source)
                # Check for strlen without + 1 in malloc(strlen(s))
                if "strlen" in arg_text and "+ 1" not in arg_text and "+1" not in arg_text:
                    findings.append(Finding(
                        rule_id="AST-ALLOC-003",
                        cwe="CWE-131",
                        vulnerability_type="AST: Allocation Missing Space for Null Terminator",
                        severity=Severity.HIGH,
                        confidence=0.90,
                        file=filename,
                        line=line,
                        column=col,
                        message=f"Memory allocation '{arg_text}' calls strlen() without adding 1 byte for the null terminator.",
                        remediation=f"Add 1 byte for null byte termination: malloc({arg_text} + 1);",
                        code_snippet=snippet,
                        analyzer_source=self.source_type,
                        evidence=[EvidenceItem(
                            analyzer_source=self.source_type,
                            description="AST allocation size expression uses strlen() without + 1 byte adjustment",
                            confidence=0.90,
                        )],
                        risk_score=0.85,
                    ))

            # Rule AST-STRCPY-004: strcpy/strcat AST detection with constant vs variable distinction
            if fn_name in {"strcpy", "strcat"} and len(args) >= 2:
                dst_text = get_node_text(args[0], source)
                src_text = get_node_text(args[1], source)
                is_constant_src = args[1].type == "string_literal"
                severity = Severity.MEDIUM if is_constant_src else Severity.HIGH
                findings.append(Finding(
                    rule_id="AST-STRCPY-004",
                    cwe="CWE-120",
                    vulnerability_type=f"AST: Unsafe String Operation ({fn_name})",
                    severity=severity,
                    confidence=0.92,
                    file=filename,
                    line=line,
                    column=col,
                    message=f"{fn_name}() copies from '{src_text}' to '{dst_text}' without explicit destination bounds.",
                    remediation=f"Replace with strncpy({dst_text}, {src_text}, sizeof({dst_text})-1); or snprintf().",
                    code_snippet=snippet,
                    analyzer_source=self.source_type,
                    evidence=[EvidenceItem(
                        analyzer_source=self.source_type,
                        description=f"AST {fn_name} invocation with source type '{args[1].type}'",
                        confidence=0.92,
                        metadata={"dst": dst_text, "src": src_text, "constant_src": is_constant_src},
                    )],
                    risk_score=0.75 if is_constant_src else 0.88,
                ))

        # ─── 2. Unchecked Return Values for Critical Security Functions ────────────────
        # If call is directly inside an expression_statement (return value unused)
        for call in call_nodes:
            fn_name = get_call_name(call, source)
            if fn_name in {"setuid", "seteuid", "setgid", "setegid", "realloc"}:
                parent = call.parent
                if parent and parent.type == "expression_statement":
                    line, col = get_node_location(call)
                    snippet = self._get_snippet(context.lines, line - 1)
                    findings.append(Finding(
                        rule_id="AST-UNCHECKED-005",
                        cwe="CWE-252",
                        vulnerability_type="AST: Unchecked Critical Return Value",
                        severity=Severity.HIGH,
                        confidence=0.91,
                        file=filename,
                        line=line,
                        column=col,
                        message=f"Return value of security-critical function '{fn_name}()' is ignored.",
                        remediation=f"Check return value: if ({fn_name}(...) != 0) {{ /* handle error */ }}",
                        code_snippet=snippet,
                        analyzer_source=self.source_type,
                        evidence=[EvidenceItem(
                            analyzer_source=self.source_type,
                            description=f"AST expression_statement ignores return value of {fn_name}()",
                            confidence=0.91,
                        )],
                        risk_score=0.82,
                    ))

        # ─── 3. Function-Scoped Double Free Analysis ──────────────────────────────────
        # Check if same identifier is freed multiple times inside the same function AST body
        func_defs = get_function_definitions(root)
        for func in func_defs:
            func_calls = get_call_expressions(func)
            freed_vars: Set[str] = set()

            for call in func_calls:
                if get_call_name(call, source) == "free":
                    args = get_call_arguments(call)
                    if args and args[0].type == "identifier":
                        var_name = get_node_text(args[0], source)
                        line, col = get_node_location(call)
                        snippet = self._get_snippet(context.lines, line - 1)

                        if var_name in freed_vars:
                            findings.append(Finding(
                                rule_id="AST-DOUBLE-FREE-006",
                                cwe="CWE-415",
                                vulnerability_type="AST: Double Free Vulnerability",
                                severity=Severity.HIGH,
                                confidence=0.88,
                                file=filename,
                                line=line,
                                column=col,
                                message=f"Pointer variable '{var_name}' is freed more than once in the same function scope.",
                                remediation=f"Set pointer to NULL immediately after freeing: free({var_name}); {var_name} = NULL;",
                                code_snippet=snippet,
                                analyzer_source=self.source_type,
                                evidence=[EvidenceItem(
                                    analyzer_source=self.source_type,
                                    description=f"AST function body contains repeated free({var_name}) calls without reset",
                                    confidence=0.88,
                                )],
                                risk_score=0.86,
                            ))
                        else:
                            freed_vars.add(var_name)

        return findings
