"""
CFG & Path-Sensitive Security Analyzer for VulnDetect.
Evaluates control-flow graphs and path-sensitive states to discover
null pointer dereferences, use-after-free, double frees, resource leaks,
and uninitialized variable reads across branching paths.
"""

from typing import List, Optional
from app.engine.base import (
    BaseAnalyzer, AnalyzerSource, Finding, AnalysisStatus, Severity,
    AnalysisContext, EvidenceItem, DataflowStep
)
from app.engine.parser import get_function_definitions
from app.engine.cfg.builder import CFGBuilder
from app.engine.cfg.propagator import PathPropagator
from app.engine.cfg.state import Nullness, Lifetime, InitStatus, ResourceStatus


class CFGAnalyzer(BaseAnalyzer):
    """
    Intra-procedural Control-Flow Graph and Path-Sensitive Static Analyzer.
    """

    name: str = "cfg_analyzer"
    source_type: AnalyzerSource = AnalyzerSource.CFG

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        if not context.ast_root:
            return []

        findings: List[Finding] = []
        func_nodes = get_function_definitions(context.ast_root)

        for func_node in func_nodes:
            # 1. Build CFG for function
            builder = CFGBuilder(func_node, context.source_code)
            cfg = builder.build()

            # 2. Run path-sensitive propagator over CFG
            propagator = PathPropagator(cfg, context.source_code)
            propagator.propagate()

            # 3. Analyze path events
            self._check_null_dereferences(propagator.deref_events, context, findings)
            self._check_uaf(propagator.deref_events, context, findings)
            self._check_double_free(propagator.free_events, context, findings)
            self._check_resource_leaks(propagator.exit_resources, context, findings)
            self._check_uninitialized_reads(propagator.read_events, context, findings)
            self._check_unchecked_calls(propagator.unchecked_calls, context, findings)

        return findings

    def _check_null_dereferences(self, events, context: AnalysisContext, findings: List[Finding]):
        for ev in events:
            ptr_info = ev.state_at_deref.pointers.get(ev.ptr_name)
            if not ptr_info:
                continue

            # A. Definite Null: CONFIRMED
            if ptr_info.nullness == Nullness.NULL:
                msg = (
                    f"Path-sensitive Null Pointer Dereference: pointer '{ev.ptr_name}' is definitely NULL "
                    f"along this execution path."
                )
                f = Finding(
                    rule_id="CFG-NULL-CONFIRMED-001",
                    cwe="CWE-476",
                    vulnerability_type="NULL Pointer Dereference",
                    severity=Severity.CRITICAL,
                    risk_score=0.92,
                    confidence=0.98,
                    file=context.file_path,
                    line=ev.line,
                    column=ev.column,
                    message=msg,
                    remediation=f"Add null check 'if ({ev.ptr_name} != NULL)' or verify initialization before dereference.",
                    code_snippet=ev.code_snippet,
                    analyzer_source=AnalyzerSource.CFG,
                    analysis_status=AnalysisStatus.CONFIRMED,
                    evidence=[
                        EvidenceItem(
                            analyzer_source=AnalyzerSource.CFG,
                            description=f"Control-Flow analysis: pointer '{ev.ptr_name}' has state NULL at block B{ev.block_id}",
                            confidence=0.98,
                            metadata={"pointer": ev.ptr_name, "block_id": ev.block_id}
                        )
                    ],
                    dataflow_path=[
                        DataflowStep("SINK", ev.line, ev.column, ev.code_snippet, f"Dereference of NULL pointer '{ev.ptr_name}'")
                    ]
                )
                findings.append(f)

            # B. Potentially Null (e.g. unchecked malloc or non-returning error log path): LIKELY
            elif ptr_info.nullness in (Nullness.POTENTIALLY_NULL, Nullness.UNCHECKED_ALLOCATION):
                msg = (
                    f"Potential Null Pointer Dereference: pointer '{ev.ptr_name}' is dereferenced without prior "
                    f"null-check along an execution path."
                )
                f = Finding(
                    rule_id="CFG-NULL-POTENTIAL-002",
                    cwe="CWE-476",
                    vulnerability_type="NULL Pointer Dereference",
                    severity=Severity.HIGH,
                    risk_score=0.82,
                    confidence=0.85,
                    file=context.file_path,
                    line=ev.line,
                    column=ev.column,
                    message=msg,
                    remediation=f"Ensure '{ev.ptr_name}' is non-null before dereference (e.g. 'if (!{ev.ptr_name}) return;').",
                    code_snippet=ev.code_snippet,
                    analyzer_source=AnalyzerSource.CFG,
                    analysis_status=AnalysisStatus.LIKELY,
                    evidence=[
                        EvidenceItem(
                            analyzer_source=AnalyzerSource.CFG,
                            description=f"Path join at block B{ev.block_id} contains potentially null state for '{ev.ptr_name}'",
                            confidence=0.85,
                            metadata={"pointer": ev.ptr_name, "state": ptr_info.nullness.value}
                        )
                    ],
                    dataflow_path=[
                        DataflowStep("SOURCE", ptr_info.alloc_line or ev.line, None, "", f"Allocation of '{ev.ptr_name}'"),
                        DataflowStep("SINK", ev.line, ev.column, ev.code_snippet, f"Dereference of potentially null '{ev.ptr_name}'")
                    ]
                )
                findings.append(f)

    def _check_uaf(self, events, context: AnalysisContext, findings: List[Finding]):
        for ev in events:
            ptr_info = ev.state_at_deref.pointers.get(ev.ptr_name)
            if not ptr_info:
                continue

            if ptr_info.lifetime == Lifetime.FREED:
                msg = (
                    f"Path-sensitive Use-After-Free: pointer '{ev.ptr_name}' was freed on line {ptr_info.free_line} "
                    f"and subsequently dereferenced along this execution path."
                )
                f = Finding(
                    rule_id="CFG-UAF-CONFIRMED-001",
                    cwe="CWE-416",
                    vulnerability_type="Use After Free",
                    severity=Severity.CRITICAL,
                    risk_score=0.95,
                    confidence=0.98,
                    file=context.file_path,
                    line=ev.line,
                    column=ev.column,
                    message=msg,
                    remediation=f"Set '{ev.ptr_name} = NULL;' immediately after free, or avoid accessing it after release.",
                    code_snippet=ev.code_snippet,
                    analyzer_source=AnalyzerSource.CFG,
                    analysis_status=AnalysisStatus.CONFIRMED,
                    evidence=[
                        EvidenceItem(
                            analyzer_source=AnalyzerSource.CFG,
                            description=f"Control-Flow path proof: pointer '{ev.ptr_name}' was freed on L{ptr_info.free_line}",
                            confidence=0.98,
                            metadata={"free_line": ptr_info.free_line}
                        )
                    ],
                    dataflow_path=[
                        DataflowStep("SOURCE", ptr_info.free_line or ev.line, None, f"free({ev.ptr_name})", f"Memory freed here"),
                        DataflowStep("SINK", ev.line, ev.column, ev.code_snippet, f"Use after free of '{ev.ptr_name}'")
                    ]
                )
                findings.append(f)

            elif ptr_info.lifetime == Lifetime.POTENTIALLY_FREED:
                msg = (
                    f"Potential Use-After-Free: pointer '{ev.ptr_name}' was freed along a merged control-flow branch "
                    f"and may be used after release."
                )
                f = Finding(
                    rule_id="CFG-UAF-POTENTIAL-002",
                    cwe="CWE-416",
                    vulnerability_type="Use After Free",
                    severity=Severity.HIGH,
                    risk_score=0.88,
                    confidence=0.85,
                    file=context.file_path,
                    line=ev.line,
                    column=ev.column,
                    message=msg,
                    remediation=f"Ensure '{ev.ptr_name}' is not accessed after conditional free.",
                    code_snippet=ev.code_snippet,
                    analyzer_source=AnalyzerSource.CFG,
                    analysis_status=AnalysisStatus.LIKELY,
                    evidence=[
                        EvidenceItem(
                            analyzer_source=AnalyzerSource.CFG,
                            description=f"Path join at B{ev.block_id} contains potentially freed state for '{ev.ptr_name}'",
                            confidence=0.85
                        )
                    ]
                )
                findings.append(f)

    def _check_double_free(self, events, context: AnalysisContext, findings: List[Finding]):
        for ev in events:
            ptr_info = ev.state_at_free.pointers.get(ev.ptr_name)
            if not ptr_info:
                continue

            if ptr_info.lifetime == Lifetime.FREED:
                msg = (
                    f"Path-sensitive Double Free: pointer '{ev.ptr_name}' was already freed on line {ptr_info.free_line} "
                    f"and is freed again along this execution path."
                )
                f = Finding(
                    rule_id="CFG-DOUBLE-FREE-CONFIRMED-001",
                    cwe="CWE-415",
                    vulnerability_type="Double Free",
                    severity=Severity.CRITICAL,
                    risk_score=0.95,
                    confidence=0.98,
                    file=context.file_path,
                    line=ev.line,
                    column=ev.column,
                    message=msg,
                    remediation=f"Set '{ev.ptr_name} = NULL;' after free and guard against duplicate free calls.",
                    code_snippet=ev.code_snippet,
                    analyzer_source=AnalyzerSource.CFG,
                    analysis_status=AnalysisStatus.CONFIRMED,
                    evidence=[
                        EvidenceItem(
                            analyzer_source=AnalyzerSource.CFG,
                            description=f"CFG path proof: duplicate free of '{ev.ptr_name}' previously freed on L{ptr_info.free_line}",
                            confidence=0.98
                        )
                    ],
                    dataflow_path=[
                        DataflowStep("SOURCE", ptr_info.free_line or ev.line, None, f"free({ev.ptr_name})", "Initial free"),
                        DataflowStep("SINK", ev.line, ev.column, ev.code_snippet, "Second free on same pointer")
                    ]
                )
                findings.append(f)

    def _check_resource_leaks(self, exit_resources, context: AnalysisContext, findings: List[Finding]):
        for res in exit_resources:
            msg = (
                f"Path-sensitive Resource Leak: handle '{res.resource_name}' opened on line {res.open_line} "
                f"is not closed on control-flow path exiting the function at line {res.exit_line}."
            )
            f = Finding(
                rule_id="CFG-RESOURCE-LEAK-001",
                cwe="CWE-775",
                vulnerability_type="Missing Release of Resource after Effective Lifetime",
                severity=Severity.HIGH,
                risk_score=0.82,
                confidence=0.90,
                file=context.file_path,
                line=res.exit_line,
                message=msg,
                remediation=f"Close '{res.resource_name}' (e.g. fclose/close) before all exit/return paths.",
                analyzer_source=AnalyzerSource.CFG,
                analysis_status=AnalysisStatus.CONFIRMED if res.status == ResourceStatus.OPEN else AnalysisStatus.LIKELY,
                evidence=[
                    EvidenceItem(
                        analyzer_source=AnalyzerSource.CFG,
                        description=f"CFG Exit block reached with resource '{res.resource_name}' in state {res.status.value}",
                        confidence=0.90
                    )
                ],
                dataflow_path=[
                    DataflowStep("SOURCE", res.open_line or res.exit_line, None, "", f"Resource opened"),
                    DataflowStep("SINK", res.exit_line, None, "", f"Function exit without closing resource")
                ]
            )
            findings.append(f)

    def _check_uninitialized_reads(self, events, context: AnalysisContext, findings: List[Finding]):
        for ev in events:
            var_info = ev.state_at_read.variables.get(ev.var_name)
            if not var_info:
                continue

            if var_info.init_status == InitStatus.UNINITIALIZED:
                msg = (
                    f"Use of Uninitialized Variable: '{ev.var_name}' is read before being initialized "
                    f"along this execution path."
                )
                f = Finding(
                    rule_id="CFG-UNINIT-CONFIRMED-001",
                    cwe="CWE-457",
                    vulnerability_type="Use of Uninitialized Variable",
                    severity=Severity.HIGH,
                    risk_score=0.85,
                    confidence=0.95,
                    file=context.file_path,
                    line=ev.line,
                    column=ev.column,
                    message=msg,
                    remediation=f"Initialize '{ev.var_name}' at its declaration (e.g. '{ev.var_name} = 0;').",
                    code_snippet=ev.code_snippet,
                    analyzer_source=AnalyzerSource.CFG,
                    analysis_status=AnalysisStatus.CONFIRMED,
                    evidence=[
                        EvidenceItem(
                            analyzer_source=AnalyzerSource.CFG,
                            description=f"CFG path analysis: variable '{ev.var_name}' is UNINITIALIZED at block B{ev.block_id}",
                            confidence=0.95
                        )
                    ]
                )
                findings.append(f)
            elif var_info.init_status == InitStatus.POTENTIALLY_UNINITIALIZED:
                msg = (
                    f"Potential Use of Uninitialized Variable: '{ev.var_name}' may be uninitialized "
                    f"along some control-flow paths reaching this statement."
                )
                f = Finding(
                    rule_id="CFG-UNINIT-POTENTIAL-002",
                    cwe="CWE-457",
                    vulnerability_type="Use of Uninitialized Variable",
                    severity=Severity.MEDIUM,
                    risk_score=0.75,
                    confidence=0.80,
                    file=context.file_path,
                    line=ev.line,
                    column=ev.column,
                    message=msg,
                    remediation=f"Ensure '{ev.var_name}' is initialized in all branches before use.",
                    code_snippet=ev.code_snippet,
                    analyzer_source=AnalyzerSource.CFG,
                    analysis_status=AnalysisStatus.LIKELY,
                    evidence=[
                        EvidenceItem(
                            analyzer_source=AnalyzerSource.CFG,
                            description=f"Path join at B{ev.block_id} contains potentially uninitialized state for '{ev.var_name}'",
                            confidence=0.80
                        )
                    ]
                )
                findings.append(f)

    def _check_unchecked_calls(self, calls, context: AnalysisContext, findings: List[Finding]):
        for call in calls:
            msg = (
                f"Unchecked Return Value on security-critical function '{call.func_name}()': "
                f"return value is discarded along this path."
            )
            f = Finding(
                rule_id="CFG-UNCHECKED-RETURN-001",
                cwe="CWE-252",
                vulnerability_type="Unchecked Return Value",
                severity=Severity.MEDIUM,
                risk_score=0.65,
                confidence=0.90,
                file=context.file_path,
                line=call.line,
                column=call.column,
                message=msg,
                remediation=f"Check return value: 'if ({call.func_name}(...) != 0) {{ handle_error(); }}'.",
                code_snippet=call.code_snippet,
                analyzer_source=AnalyzerSource.CFG,
                analysis_status=AnalysisStatus.LIKELY,
                evidence=[
                    EvidenceItem(
                        analyzer_source=AnalyzerSource.CFG,
                        description=f"Critical API '{call.func_name}' called without return value check",
                        confidence=0.90
                    )
                ]
            )
            findings.append(f)
