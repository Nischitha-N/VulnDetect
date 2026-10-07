"""
Semantic Taint Engine.
Performs semantic dataflow propagation from Sources through Transformations
and Sanitizers to Sinks, constructing full explainable dataflow paths.
"""

from dataclasses import dataclass
from typing import List, Dict, Set, Optional, Tuple
from tree_sitter import Node

from app.engine.base import (
    Finding,
    AnalyzerSource,
    Severity,
    AnalysisStatus,
    EvidenceItem,
    DataflowStep,
    AnalysisContext,
)
from app.engine.parser import (
    get_node_text,
    get_node_location,
    get_function_definitions,
    find_nodes_by_type,
    get_call_expressions,
    get_call_name,
    get_call_arguments,
)
from app.engine.taint.spec import TaintState, TaintConfigManager, TaintSourceSpec, TaintSinkSpec, TaintSanitizerSpec
from app.engine.taint.tracker import TaintTrackedValue, TaintEnvironment


class SemanticTaintEngine:
    """
    Core semantic taint analysis engine.
    """

    def __init__(self, config_manager: Optional[TaintConfigManager] = None):
        self.config: TaintConfigManager = config_manager or TaintConfigManager()

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        if not context.ast_root:
            return []

        findings: List[Finding] = []
        source_code = context.source_code
        func_nodes = get_function_definitions(context.ast_root)

        for func in func_nodes:
            env = TaintEnvironment()
            self._init_function_scope(func, env, source_code)
            self._walk_function(func, env, source_code, context, findings)

        return findings

    def _init_function_scope(self, func_node: Node, env: TaintEnvironment, source_code: str):
        """Identifies parameter sources (e.g. main's argv, or untrusted parameter names)."""
        decl = func_node.child_by_field_name("declarator")
        if not decl:
            return

        params = find_nodes_by_type(decl, ["parameter_declaration"])
        for p in params:
            d_node = p.child_by_field_name("declarator")
            if not d_node:
                continue

            param_name = get_node_text(d_node, source_code).lstrip("*&").strip()
            line, col = get_node_location(p)

            # Check if argv or explicitly tainted parameter
            if param_name in ("argv", "args") or param_name in {"user_input", "input", "msg", "name", "password", "cmd", "user_id"}:
                tracked = TaintTrackedValue(
                    state=TaintState.DEFINITELY_TAINTED,
                    source_desc=f"Function parameter '{param_name}'",
                    source_line=line,
                    source_col=col,
                )
                tracked.add_step("SOURCE", line, col, get_node_text(p, source_code).strip(), f"Untrusted input received via parameter '{param_name}'")
                env.set_tracked(param_name, tracked)

    def _walk_function(
        self,
        func_node: Node,
        env: TaintEnvironment,
        source_code: str,
        context: AnalysisContext,
        findings: List[Finding]
    ):
        body = func_node.child_by_field_name("body")
        if not body:
            return

        # Sequential statements traversal
        stmts = find_nodes_by_type(body, ["declaration", "expression_statement", "return_statement"])
        for stmt in stmts:
            self._process_statement(stmt, env, source_code, context, findings)

    def _process_statement(
        self,
        stmt: Node,
        env: TaintEnvironment,
        source_code: str,
        context: AnalysisContext,
        findings: List[Finding]
    ):
        stype = stmt.type
        line, col = get_node_location(stmt)
        code_text = get_node_text(stmt, source_code).strip()

        # 1. Declarations: char *p = getenv("PATH"); or char *p = q;
        if stype == "declaration":
            init_decls = find_nodes_by_type(stmt, ["init_declarator"])
            for d in init_decls:
                var_decl = d.child_by_field_name("declarator")
                val_node = d.child_by_field_name("value")
                var_name = get_node_text(var_decl, source_code).lstrip("*&").strip() if var_decl else ""

                if var_name and val_node:
                    self._process_assignment(var_name, val_node, env, source_code, line, col, code_text, context, findings)

        # 2. Expression statements
        elif stype == "expression_statement":
            # Check if assignment expression
            assign_nodes = find_nodes_by_type(stmt, ["assignment_expression"])
            if assign_nodes:
                for a in assign_nodes:
                    left = a.child_by_field_name("left")
                    right = a.child_by_field_name("right")
                    left_text = get_node_text(left, source_code).strip() if left else ""
                    if left_text and right:
                        self._process_assignment(left_text, right, env, source_code, line, col, code_text, context, findings)
            else:
                # Bare function calls (e.g. gets(buf), system(cmd), sanitize(input))
                calls = get_call_expressions(stmt)
                for call in calls:
                    self._process_call(call, env, source_code, line, col, code_text, context, findings)

        # 3. Return statement
        elif stype == "return_statement":
            ret_expr = stmt.named_children[0] if stmt.named_children else None
            if ret_expr:
                tracked = self._evaluate_expression_taint(ret_expr, env, source_code)
                if tracked:
                    env.return_taint = tracked

    def _process_assignment(
        self,
        dest_name: str,
        rhs_node: Node,
        env: TaintEnvironment,
        source_code: str,
        line: int,
        col: int,
        code_text: str,
        context: AnalysisContext,
        findings: List[Finding]
    ):
        # 1. If RHS is a function call (e.g. p = getenv("VAR") or p = sanitize(user_input))
        if rhs_node.type == "call_expression":
            self._process_call(rhs_node, env, source_code, line, col, code_text, context, findings, assign_target=dest_name)
            return

        # 2. If RHS is a pointer / variable / struct field
        tracked_rhs = self._evaluate_expression_taint(rhs_node, env, source_code)
        if tracked_rhs:
            new_tracked = tracked_rhs.copy()
            new_tracked.add_step("PROPAGATION", line, col, code_text, f"Taint assigned to '{dest_name}'")
            env.set_tracked(dest_name, new_tracked)

            # Check if pointer alias
            rhs_text = get_node_text(rhs_node, source_code).strip()
            if rhs_text.isidentifier():
                env.add_alias(dest_name, rhs_text)
        else:
            # If assigned a constant or clean value, clear taint
            if TaintEnvironment.is_constant_expression(rhs_node, source_code):
                if dest_name in env.variables:
                    del env.variables[dest_name]

    def _process_call(
        self,
        call_node: Node,
        env: TaintEnvironment,
        source_code: str,
        line: int,
        col: int,
        code_text: str,
        context: AnalysisContext,
        findings: List[Finding],
        assign_target: Optional[str] = None
    ):
        fn_name = get_call_name(call_node, source_code) or ""
        args = get_call_arguments(call_node)
        arg_texts = [get_node_text(a, source_code).strip() for a in args]

        # ─── A. Check if Source ───────────────────────────────────────────────
        if fn_name in self.config.sources:
            src_spec = self.config.sources[fn_name]

            # Function returns tainted buffer: e.g. p = getenv(...)
            if src_spec.returns_tainted and assign_target:
                tracked = TaintTrackedValue(
                    state=TaintState.DEFINITELY_TAINTED,
                    source_desc=src_spec.description,
                    source_line=line,
                    source_col=col,
                )
                tracked.add_step("SOURCE", line, col, code_text, f"Untrusted input originating from '{fn_name}()'")
                env.set_tracked(assign_target, tracked)

            # Function taints specific argument buffers: e.g. gets(buf), read(fd, buf, sz), recv(...)
            for arg_idx in src_spec.tainted_args:
                if arg_idx < len(arg_texts):
                    target_arg = arg_texts[arg_idx].lstrip("&*").strip()
                    tracked = TaintTrackedValue(
                        state=TaintState.DEFINITELY_TAINTED,
                        source_desc=src_spec.description,
                        source_line=line,
                        source_col=col,
                    )
                    tracked.add_step("SOURCE", line, col, code_text, f"Buffer '{target_arg}' tainted by '{fn_name}()'")
                    env.set_tracked(target_arg, tracked)

            return

        # ─── B. Check if Sanitizer ───────────────────────────────────────────
        if fn_name in self.config.sanitizers:
            san_spec = self.config.sanitizers[fn_name]

            # If sanitizer returns sanitized value: e.g. clean = sanitize(tainted)
            if san_spec.returns_sanitized and assign_target and args:
                src_tracked = self._evaluate_expression_taint(args[0], env, source_code)
                if src_tracked:
                    sanitized_val = src_tracked.copy()
                    sanitized_val.mark_sanitized(fn_name, line, col, code_text, san_spec.is_trusted)
                    env.set_tracked(assign_target, sanitized_val)

            # If sanitizer modifies in-place argument: e.g. sanitize_cmd(buf)
            for san_idx in san_spec.sanitized_args:
                if san_idx < len(args):
                    target_arg = arg_texts[san_idx].lstrip("&*").strip()
                    src_tracked = env.get_tracked(target_arg)
                    if src_tracked:
                        src_tracked.mark_sanitized(fn_name, line, col, code_text, san_spec.is_trusted)

            return

        # ─── C. Check String Transformations / Formats (sprintf, strcpy, etc.)
        if fn_name in ("sprintf", "snprintf", "strcpy", "strncpy", "strcat", "strncat", "memcpy", "memmove"):
            if fn_name in ("sprintf", "snprintf") and len(args) >= 2:
                dst = arg_texts[0].lstrip("&*").strip()
                # Check format arguments
                for idx in range(1 if fn_name == "sprintf" else 2, len(args)):
                    tracked = self._evaluate_expression_taint(args[idx], env, source_code)
                    if tracked:
                        new_tracked = tracked.copy()
                        new_tracked.add_step("TRANSFORMATION", line, col, code_text, f"Formatted string constructed via {fn_name}() into '{dst}'")
                        env.set_tracked(dst, new_tracked)
                        break

            elif fn_name in ("strcpy", "strncpy", "strcat", "strncat", "memcpy", "memmove") and len(args) >= 2:
                dst = arg_texts[0].lstrip("&*").strip()
                src_arg = args[1]
                tracked = self._evaluate_expression_taint(src_arg, env, source_code)
                if tracked:
                    new_tracked = tracked.copy()
                    new_tracked.add_step("PROPAGATION", line, col, code_text, f"Data copied via {fn_name}() to '{dst}'")
                    env.set_tracked(dst, new_tracked)

        # ─── D. Check if Sink ────────────────────────────────────────────────
        if fn_name in self.config.sinks:
            sink_spec = self.config.sinks[fn_name]

            for sink_idx in sink_spec.sink_args:
                if sink_idx < len(args):
                    sink_arg_node = args[sink_idx]

                    # If compile-time constant string, definitely safe!
                    if TaintEnvironment.is_constant_expression(sink_arg_node, source_code):
                        continue

                    # Evaluate taint on the argument expression
                    tracked = self._evaluate_expression_taint(sink_arg_node, env, source_code)
                    if not tracked:
                        continue

                    # Check taint status:
                    if tracked.state == TaintState.DEFINITELY_SANITIZED:
                        # Safely sanitized by trusted sanitizer -> Suppress!
                        continue

                    is_custom_sanitizer = (tracked.state == TaintState.POSSIBLY_TAINTED and not tracked.is_trusted_sanitizer)
                    status = AnalysisStatus.NEEDS_REVIEW if is_custom_sanitizer else AnalysisStatus.CONFIRMED

                    # Build complete dataflow path
                    steps = list(tracked.steps)
                    steps.append(
                        DataflowStep(
                            step_type="SINK",
                            line=line,
                            column=col,
                            code=code_text,
                            description=f"Untrusted data reaches dangerous sink '{fn_name}()'",
                        )
                    )

                    evidence = EvidenceItem(
                        analyzer_source=AnalyzerSource.TAINT,
                        description=f"Semantic Taint Path: {tracked.source_desc} -> Sink '{fn_name}()'",
                        confidence=0.95 if status == AnalysisStatus.CONFIRMED else 0.70,
                        metadata={
                            "source": tracked.source_desc,
                            "sink": fn_name,
                            "path_steps": len(steps),
                            "sanitizer": tracked.sanitizer_name,
                        },
                    )

                    f = Finding(
                        rule_id=f"TAINT-{fn_name.upper()}-001",
                        cwe=sink_spec.cwe,
                        vulnerability_type=sink_spec.vuln_type,
                        severity=sink_spec.severity,
                        confidence=0.95 if status == AnalysisStatus.CONFIRMED else 0.70,
                        file=context.file_path,
                        line=line,
                        column=col,
                        message=f"{sink_spec.message} (Source: {tracked.source_desc})",
                        remediation=sink_spec.remediation,
                        code_snippet=code_text,
                        analyzer_source=AnalyzerSource.TAINT,
                        analysis_status=status,
                        evidence=[evidence],
                        dataflow_path=steps,
                        risk_score=sink_spec.risk_score,
                    )

                    if is_custom_sanitizer:
                        f.assumptions.append(f"Assumes custom sanitizer '{tracked.sanitizer_name}()' does not handle all edge cases.")
                        f.unknowns.append(f"Security validation contract for '{tracked.sanitizer_name}()' is external.")
                        f.analysis_limitations.append(f"Custom sanitizer '{tracked.sanitizer_name}()' requires manual review.")
                        f.recommended_manual_verification.append(f"Inspect '{tracked.sanitizer_name}()' to verify complete payload neutralization.")

                    findings.append(f)

    def _evaluate_expression_taint(self, node: Node, env: TaintEnvironment, source_code: str) -> Optional[TaintTrackedValue]:
        """Evaluates whether an expression contains or references any tainted variable/field."""
        if not node:
            return None

        # Check if constant
        if TaintEnvironment.is_constant_expression(node, source_code):
            return None

        # Extract all exact identifiers / field expressions
        idents = TaintEnvironment.extract_identifiers(node, source_code)
        for name, _ in idents:
            tracked = env.get_tracked(name)
            if tracked:
                return tracked

        return None
