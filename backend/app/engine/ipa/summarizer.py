"""
Function Summarizer.
Extracts semantic summaries for C/C++ functions bottom-up, recording return contracts,
memory/resource release, and sink destinations for parameters.
"""

from typing import Dict, List, Set, Optional, Tuple
from tree_sitter import Node

from app.engine.ipa.summary import FunctionSummary
from app.engine.parser import (
    get_node_text,
    get_node_location,
    find_nodes_by_type,
    get_call_expressions,
    get_call_name,
    get_call_arguments,
)
from app.engine.taint.spec import TaintConfigManager


class FunctionSummarizer:
    """
    Computes a FunctionSummary from a function definition AST node and known callee summaries.
    """

    def __init__(self, taint_config: Optional[TaintConfigManager] = None):
        self.taint_config: TaintConfigManager = taint_config or TaintConfigManager()

    def summarize(
        self,
        func_name: str,
        func_node: Node,
        source_code: str,
        file_path: str = "",
        known_summaries: Optional[Dict[str, FunctionSummary]] = None
    ) -> FunctionSummary:
        known = known_summaries or {}
        param_names = self._extract_parameter_names(func_node, source_code)
        summary = FunctionSummary(function_name=func_name, file_path=file_path, param_names=param_names)

        body = func_node.child_by_field_name("body")
        if not body:
            return summary

        # 1. Analyze return statements
        ret_stmts = find_nodes_by_type(body, ["return_statement"])
        for ret in ret_stmts:
            if ret.named_children:
                ret_expr = ret.named_children[0]
                self._analyze_return_expression(ret_expr, summary, param_names, source_code, known)

        # 2. Analyze function calls inside body (memory frees, sinks, resource closes)
        calls = get_call_expressions(body)
        for call in calls:
            self._analyze_call_expression(call, summary, param_names, source_code, known)

        return summary

    def _extract_parameter_names(self, func_node: Node, source_code: str) -> List[str]:
        decl = func_node.child_by_field_name("declarator")
        if not decl:
            return []
        params = find_nodes_by_type(decl, ["parameter_declaration"])
        names = []
        for p in params:
            d_node = p.child_by_field_name("declarator")
            if d_node:
                pname = get_node_text(d_node, source_code).lstrip("*&").strip()
                names.append(pname)
        return names

    def _analyze_return_expression(
        self,
        expr_node: Node,
        summary: FunctionSummary,
        param_names: List[str],
        source_code: str,
        known: Dict[str, FunctionSummary]
    ):
        # Unwrap C-style casts (e.g. return (char *)malloc(32);)
        while expr_node and expr_node.type == "cast_expression":
            val = expr_node.child_by_field_name("value")
            if val:
                expr_node = val
            else:
                break

        etype = expr_node.type
        text = get_node_text(expr_node, source_code).strip()

        # A. Return is a call (e.g. return getenv("CMD"); or return helper();)
        if etype == "call_expression":
            callee_name = get_call_name(expr_node, source_code)
            if callee_name:
                # Direct taint source call
                if callee_name in self.taint_config.sources:
                    src_spec = self.taint_config.sources[callee_name]
                    summary.return_is_source = True
                    summary.return_source_desc = f"Returns output of {callee_name}()"

                # Allocation call
                elif callee_name in ("malloc", "calloc", "realloc"):
                    summary.return_allocated_memory = True
                    summary.return_can_be_null = True

                # Resource acquisition call
                elif callee_name in ("fopen", "open", "socket"):
                    summary.return_resource_acquired = "FILE*" if callee_name == "fopen" else "descriptor"
                    summary.return_can_be_null = True

                # Known callee summary propagation
                elif callee_name in known:
                    callee_summary = known[callee_name]
                    if callee_summary.return_is_source:
                        summary.return_is_source = True
                        summary.return_source_desc = callee_summary.return_source_desc
                    if callee_summary.return_can_be_null:
                        summary.return_can_be_null = True
                    if callee_summary.return_allocated_memory:
                        summary.return_allocated_memory = True

        # B. Return is an identifier (e.g. return p; or return NULL;)
        elif etype == "identifier":
            if text in ("NULL", "0", "nullptr"):
                summary.return_can_be_null = True
            elif text in param_names:
                summary.return_tainted_from_params.add(param_names.index(text))

    def _analyze_call_expression(
        self,
        call_node: Node,
        summary: FunctionSummary,
        param_names: List[str],
        source_code: str,
        known: Dict[str, FunctionSummary]
    ):
        callee_name = get_call_name(call_node, source_code)
        if not callee_name:
            return

        args = get_call_arguments(call_node)
        arg_texts = [get_node_text(a, source_code).lstrip("*&").strip() for a in args]

        # A. Direct free(param)
        if callee_name == "free" and arg_texts:
            target = arg_texts[0]
            if target in param_names:
                summary.freed_params.add(param_names.index(target))

        # B. Direct fclose(param) / close(param)
        elif callee_name in ("fclose", "close") and arg_texts:
            target = arg_texts[0]
            if target in param_names:
                summary.closed_resource_params.add(param_names.index(target))

        # C. Direct sink call: system(param), popen(param), etc.
        elif callee_name in self.taint_config.sinks:
            sink_spec = self.taint_config.sinks[callee_name]
            for s_idx in sink_spec.sink_args:
                if s_idx < len(arg_texts):
                    target = arg_texts[s_idx]
                    if target in param_names:
                        summary.sink_calls.append((callee_name, param_names.index(target), sink_spec.cwe))

        # D. Callee with known summary
        elif callee_name in known:
            callee_sum = known[callee_name]

            # Callee frees parameter
            for freed_idx in callee_sum.freed_params:
                if freed_idx < len(arg_texts):
                    target = arg_texts[freed_idx]
                    if target in param_names:
                        summary.freed_params.add(param_names.index(target))

            # Callee closes resource parameter
            for closed_idx in callee_sum.closed_resource_params:
                if closed_idx < len(arg_texts):
                    target = arg_texts[closed_idx]
                    if target in param_names:
                        summary.closed_resource_params.add(param_names.index(target))

            # Callee passes parameter to sink
            for sink_name, sink_p_idx, cwe in callee_sum.sink_calls:
                if sink_p_idx < len(arg_texts):
                    target = arg_texts[sink_p_idx]
                    if target in param_names:
                        summary.sink_calls.append((sink_name, param_names.index(target), cwe))
