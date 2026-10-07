"""
Range & Interval Security Analyzer for VulnDetect.
Evaluates semantic value bounds, buffer capacities, loop limits, and signedness
to discover array bounds violations, buffer overflows, integer overflows, and
conversion defects.
"""

from typing import List, Optional
from app.engine.base import BaseAnalyzer, AnalyzerSource, Finding, AnalysisStatus, Severity, AnalysisContext, EvidenceItem, DataflowStep
from app.engine.parser import get_function_definitions
from app.engine.range.interval import Interval, INF, INT32_MAX, INT32_MIN, UINT32_MAX
from app.engine.range.analyzer_engine import FunctionRangeAnalyzer, ArrayAccessFact, MemoryCallFact, IntOverflowFact, ConversionFact


class RangeAnalyzer(BaseAnalyzer):
    """
    Semantic value and interval analysis layer for C/C++.
    Proves safety or flags confirmed/likely/uncertain vulnerabilities based on mathematical ranges.
    """

    name: str = "range_analyzer"
    source_type: AnalyzerSource = AnalyzerSource.RANGE

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        if not context.ast_root:
            return []

        findings: List[Finding] = []
        func_nodes = get_function_definitions(context.ast_root)

        for func_node in func_nodes:
            fn_analyzer = FunctionRangeAnalyzer(func_node, context.source_code, context.file_path).analyze()
            
            # 1. Array Bounds & Out-of-Bounds Indexing
            self._check_array_bounds(fn_analyzer.array_accesses, context, findings)

            # 2. Buffer Overflows in Memory Transfer APIs (memcpy, memmove, etc.)
            self._check_memory_transfers(fn_analyzer.memory_calls, context, findings)

            # 3. Dynamic Allocation Sizes (malloc, calloc, realloc)
            self._check_allocations(fn_analyzer.memory_calls, context, findings)

            # 4. Signed-to-Unsigned Conversion Hazards
            self._check_conversions(fn_analyzer.memory_calls, fn_analyzer.conversion_facts, context, findings)

            # 5. Arithmetic Overflows
            self._check_arithmetic_overflows(fn_analyzer.overflow_facts, context, findings)

        return findings

    def _check_array_bounds(self, accesses: List[ArrayAccessFact], context: AnalysisContext, findings: List[Finding]):
        for acc in accesses:
            if acc.array_size is None:
                continue

            cap = acc.array_size
            iv = acc.index_interval

            # A. Definitely Safe: min >= 0 and max < cap
            if iv.is_definitely_in_bounds(0, cap - 1):
                # Proved mathematically safe - do NOT report
                continue

            # B. Definitely Out of Bounds: max < 0 or min >= cap
            if iv.is_definitely_out_of_bounds(0, cap - 1):
                is_negative = iv.max < 0
                cwe = "CWE-129" if is_negative else ("CWE-787" if acc.is_write else "CWE-125")
                rule_id = "RANGE-ARRAY-OOB-CONFIRMED"
                msg = (
                    f"Out-of-bounds array access on '{acc.array_name}': inferred index range is {iv}, "
                    f"which is completely outside array capacity of {cap} elements (valid indices: 0..{cap - 1})."
                )
                remediation = f"Ensure index is within [0, {cap - 1}] before accessing '{acc.array_name}'."
                
                f = Finding(
                    rule_id=rule_id,
                    cwe=cwe,
                    vulnerability_type="Out-of-Bounds Array Access" if not is_negative else "Negative Array Index Access",
                    severity=Severity.CRITICAL if acc.is_write else Severity.HIGH,
                    risk_score=0.92 if acc.is_write else 0.88,
                    confidence=0.98,
                    file=context.file_path,
                    line=acc.line,
                    column=acc.column,
                    message=msg,
                    remediation=remediation,
                    code_snippet=acc.code_snippet,
                    analyzer_source=AnalyzerSource.RANGE,
                    analysis_status=AnalysisStatus.CONFIRMED,
                    evidence=[
                        EvidenceItem(
                            analyzer_source=AnalyzerSource.RANGE,
                            description=f"Abstract range analysis: index '{acc.index_expr}' in range {iv}, capacity = {cap}",
                            confidence=0.98,
                            metadata={"inferred_interval": str(iv), "array_capacity": cap, "element_size": acc.element_size}
                        )
                    ],
                    dataflow_path=[
                        DataflowStep("SOURCE", acc.line, acc.column, acc.code_snippet, f"Array access with out-of-bounds index {iv}")
                    ]
                )
                findings.append(f)
                continue

            # C. Off-by-one in loop or conditional: max == cap (e.g. i in [0, 10] on array of size 10)
            if iv.min >= 0 and iv.max == cap:
                cwe = "CWE-193"
                rule_id = "RANGE-LOOP-OFFBYONE"
                msg = (
                    f"Off-by-one array boundary violation on '{acc.array_name}': inferred index upper bound is {iv.max}, "
                    f"exceeding maximum valid index {cap - 1} (capacity: {cap} elements)."
                )
                remediation = f"Change loop/comparison bound from '<=' to '< {cap}' or check 'index < {cap}'."

                f = Finding(
                    rule_id=rule_id,
                    cwe=cwe,
                    vulnerability_type="Off-by-One Array Indexing",
                    severity=Severity.HIGH,
                    risk_score=0.85,
                    confidence=0.95,
                    file=context.file_path,
                    line=acc.line,
                    column=acc.column,
                    message=msg,
                    remediation=remediation,
                    code_snippet=acc.code_snippet,
                    analyzer_source=AnalyzerSource.RANGE,
                    analysis_status=AnalysisStatus.CONFIRMED,
                    evidence=[
                        EvidenceItem(
                            analyzer_source=AnalyzerSource.RANGE,
                            description=f"Off-by-one bound detected: index range is {iv}, exceeding upper limit {cap - 1}",
                            confidence=0.95,
                            metadata={"inferred_interval": str(iv), "array_capacity": cap}
                        )
                    ],
                    dataflow_path=[
                        DataflowStep("SINK", acc.line, acc.column, acc.code_snippet, f"Off-by-one index access at upper bound {iv.max}")
                    ]
                )
                findings.append(f)
                continue

            # D. Potential Out-of-bounds (Upper limit could exceed or negative index possible)
            if iv.could_exceed(cap - 1) or iv.could_be_negative():
                is_unconstrained = iv.is_top
                status = AnalysisStatus.NEEDS_REVIEW if is_unconstrained else AnalysisStatus.LIKELY
                rule_id = "RANGE-ARRAY-UNCHECKED-INDEX" if is_unconstrained else "RANGE-ARRAY-POTENTIAL-OOB"
                cwe = "CWE-129"
                msg = (
                    f"Potential out-of-bounds array access on '{acc.array_name}': inferred index range is {iv}, "
                    f"which can exceed array bounds (capacity: {cap} elements)."
                )
                remediation = f"Add explicit bounds verification: 'if ({acc.index_expr} >= 0 && {acc.index_expr} < {cap})'."

                f = Finding(
                    rule_id=rule_id,
                    cwe=cwe,
                    vulnerability_type="Improper Index Validation",
                    severity=Severity.HIGH if acc.is_write else Severity.MEDIUM,
                    confidence=0.85 if status == AnalysisStatus.LIKELY else 0.65,
                    file=context.file_path,
                    line=acc.line,
                    column=acc.column,
                    message=msg,
                    remediation=remediation,
                    code_snippet=acc.code_snippet,
                    analyzer_source=AnalyzerSource.RANGE,
                    analysis_status=status,
                    evidence=[
                        EvidenceItem(
                            analyzer_source=AnalyzerSource.RANGE,
                            description=f"Inferred index range {iv} not guaranteed within [0, {cap - 1}]",
                            confidence=0.85 if status == AnalysisStatus.LIKELY else 0.65,
                            metadata={"inferred_interval": str(iv), "array_capacity": cap}
                        )
                    ],
                    assumptions=[f"Assumes '{acc.index_expr}' can take any value in range {iv}"],
                    unknowns=["Unconstrained caller or external input values"] if is_unconstrained else [],
                    analysis_limitations=["Path-sensitivity without inter-procedural caller bounds"]
                )
                findings.append(f)

    def _check_memory_transfers(self, calls: List[MemoryCallFact], context: AnalysisContext, findings: List[Finding]):
        for call in calls:
            if call.call_name in ("memcpy", "memmove", "memset", "strncpy", "snprintf"):
                if len(call.arg_intervals) < 3 or call.dest_size is None:
                    continue

                dest_size = call.dest_size
                n_iv = call.arg_intervals[2] if call.call_name in ("memcpy", "memmove", "memset") else (
                    call.arg_intervals[2] if call.call_name == "strncpy" else call.arg_intervals[1]
                )

                if n_iv.is_definitely_in_bounds(0, dest_size):
                    # Proved safe
                    continue

                if n_iv.is_definitely_exceeding(dest_size):
                    # Definite buffer overflow
                    msg = (
                        f"Buffer overflow in '{call.call_name}()': copy size is {n_iv}, "
                        f"definitely exceeding destination buffer capacity of {dest_size} bytes."
                    )
                    f = Finding(
                        rule_id="RANGE-MEMCPY-OVERFLOW",
                        cwe="CWE-120",
                        vulnerability_type="Buffer Copy without Checking Size of Input",
                        severity=Severity.CRITICAL,
                        confidence=0.98,
                        file=context.file_path,
                        line=call.line,
                        column=call.column,
                        message=msg,
                        remediation=f"Ensure copy length does not exceed destination buffer size ({dest_size} bytes).",
                        code_snippet=call.code_snippet,
                        analyzer_source=AnalyzerSource.RANGE,
                        analysis_status=AnalysisStatus.CONFIRMED,
                        evidence=[
                            EvidenceItem(
                                analyzer_source=AnalyzerSource.RANGE,
                                description=f"Transfer size range {n_iv} exceeds destination buffer capacity {dest_size} bytes",
                                confidence=0.98,
                                metadata={"copy_size_range": str(n_iv), "dest_size": dest_size}
                            )
                        ]
                    )
                    findings.append(f)
                elif n_iv.could_exceed(dest_size):
                    msg = (
                        f"Potential buffer overflow in '{call.call_name}()': copy size is {n_iv}, "
                        f"which could exceed destination buffer capacity of {dest_size} bytes."
                    )
                    f = Finding(
                        rule_id="RANGE-MEMCPY-POTENTIAL-OVERFLOW",
                        cwe="CWE-120",
                        vulnerability_type="Buffer Copy without Checking Size of Input",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        file=context.file_path,
                        line=call.line,
                        column=call.column,
                        message=msg,
                        remediation=f"Add bounds guard: 'if (len <= {dest_size}) {call.call_name}(...);'.",
                        code_snippet=call.code_snippet,
                        analyzer_source=AnalyzerSource.RANGE,
                        analysis_status=AnalysisStatus.LIKELY,
                        evidence=[
                            EvidenceItem(
                                analyzer_source=AnalyzerSource.RANGE,
                                description=f"Transfer size range {n_iv} can exceed destination capacity {dest_size} bytes",
                                confidence=0.85,
                                metadata={"copy_size_range": str(n_iv), "dest_size": dest_size}
                            )
                        ]
                    )
                    findings.append(f)

    def _check_allocations(self, calls: List[MemoryCallFact], context: AnalysisContext, findings: List[Finding]):
        for call in calls:
            if call.call_name in ("malloc", "realloc") and call.arg_intervals:
                sz_iv = call.arg_intervals[-1]
                if sz_iv.is_definitely_negative():
                    msg = f"Allocation with negative size {sz_iv} in '{call.call_name}()'."
                    f = Finding(
                        rule_id="RANGE-ALLOC-NEGATIVE",
                        cwe="CWE-131",
                        vulnerability_type="Negative Allocation Size",
                        severity=Severity.HIGH,
                        confidence=0.95,
                        file=context.file_path,
                        line=call.line,
                        column=call.column,
                        message=msg,
                        remediation="Verify allocation size is strictly positive before calling malloc.",
                        code_snippet=call.code_snippet,
                        analyzer_source=AnalyzerSource.RANGE,
                        analysis_status=AnalysisStatus.CONFIRMED,
                        evidence=[
                            EvidenceItem(
                                analyzer_source=AnalyzerSource.RANGE,
                                description=f"Allocation size interval is negative: {sz_iv}",
                                confidence=0.95,
                            )
                        ]
                    )
                    findings.append(f)
                elif sz_iv.is_constant and sz_iv.constant_value == 0:
                    msg = f"Allocation with zero size in '{call.call_name}()'."
                    f = Finding(
                        rule_id="RANGE-ALLOC-ZERO",
                        cwe="CWE-131",
                        vulnerability_type="Zero Size Allocation",
                        severity=Severity.LOW,
                        confidence=0.90,
                        file=context.file_path,
                        line=call.line,
                        column=call.column,
                        message=msg,
                        remediation="Ensure allocation size is at least 1 byte.",
                        code_snippet=call.code_snippet,
                        analyzer_source=AnalyzerSource.RANGE,
                        analysis_status=AnalysisStatus.LIKELY,
                    )
                    findings.append(f)

    def _check_conversions(self, calls: List[MemoryCallFact], conversions: List[ConversionFact], context: AnalysisContext, findings: List[Finding]):
        # Check signed negative values passed to size_t arguments in standard calls
        for call in calls:
            if call.call_name in ("memcpy", "memmove", "memset", "malloc", "read", "strncpy"):
                # Size argument is usually last
                if call.arg_intervals:
                    size_iv = call.arg_intervals[-1]
                    if size_iv.could_be_negative() and not size_iv.is_definitely_non_negative():
                        msg = (
                            f"Signed to unsigned conversion error in call to '{call.call_name}()': "
                            f"argument has potential negative value range {size_iv}, which converts to a large positive size_t value."
                        )
                        f = Finding(
                            rule_id="RANGE-SIGNED-UNSIGNED-CONV",
                            cwe="CWE-195",
                            vulnerability_type="Signed to Unsigned Conversion Error",
                            severity=Severity.HIGH,
                            confidence=0.88,
                            file=context.file_path,
                            line=call.line,
                            column=call.column,
                            message=msg,
                            remediation="Ensure the size argument is validated non-negative before passing to unsigned parameters.",
                            code_snippet=call.code_snippet,
                            analyzer_source=AnalyzerSource.RANGE,
                            analysis_status=AnalysisStatus.LIKELY,
                            evidence=[
                                EvidenceItem(
                                    analyzer_source=AnalyzerSource.RANGE,
                                    description=f"Size parameter range {size_iv} contains negative values",
                                    confidence=0.88,
                                    metadata={"interval": str(size_iv)}
                                )
                            ]
                        )
                        findings.append(f)

    def _check_arithmetic_overflows(self, overflows: List[IntOverflowFact], context: AnalysisContext, findings: List[Finding]):
        for ov in overflows:
            if ov.result_interval.could_overflow_signed_32():
                # Report if operands are unconstrained or can exceed INT32 limits
                msg = (
                    f"Potential integer overflow in arithmetic expression '{ov.expr_text}': "
                    f"result range is {ov.result_interval}, which exceeds 32-bit signed integer limits."
                )
                f = Finding(
                    rule_id="RANGE-INTEGER-OVERFLOW",
                    cwe="CWE-190",
                    vulnerability_type="Integer Overflow or Wraparound",
                    severity=Severity.MEDIUM,
                    confidence=0.80,
                    file=context.file_path,
                    line=ov.line,
                    column=ov.column,
                    message=msg,
                    remediation="Add upper bound validation or use safe arithmetic helper functions before performing operations.",
                    code_snippet=ov.code_snippet,
                    analyzer_source=AnalyzerSource.RANGE,
                    analysis_status=AnalysisStatus.LIKELY,
                    evidence=[
                        EvidenceItem(
                            analyzer_source=AnalyzerSource.RANGE,
                            description=f"Arithmetic operation '{ov.op}' result range {ov.result_interval} exceeds INT32 limits",
                            confidence=0.80,
                            metadata={"left": str(ov.left_interval), "right": str(ov.right_interval), "result": str(ov.result_interval)}
                        )
                    ]
                )
                findings.append(f)
