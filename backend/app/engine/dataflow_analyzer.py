"""
Layer 4: Intra-procedural Data-Flow Analyzer.
Tracks variable assignments, parameter propagation, and reaching definitions within function scopes.
"""

import os
from typing import List, Dict, Set, Tuple, Optional
from tree_sitter import Node

from app.engine.base import (
    BaseAnalyzer,
    Finding,
    AnalyzerSource,
    Severity,
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


class DataFlowGraph:
    """Intra-procedural assignment graph for a single function."""

    def __init__(self, function_node: Node, source_code: str):
        self.function_node = function_node
        self.source_code = source_code
        self.assignments: Dict[str, List[Tuple[str, int, int]]] = {}  # var -> list of (rhs_expr, line, col)
        self.parameters: List[str] = []
        self._build()

    def _build(self):
        # Extract parameter names
        param_list = find_nodes_by_type(self.function_node, ["parameter_declaration"])
        for p in param_list:
            decl_name = find_nodes_by_type(p, ["identifier"])
            if decl_name:
                self.parameters.append(get_node_text(decl_name[-1], self.source_code))

        # Extract assignment_expression nodes
        assign_nodes = find_nodes_by_type(self.function_node, ["assignment_expression"])
        for a in assign_nodes:
            lhs = a.child_by_field_name("left")
            rhs = a.child_by_field_name("right")
            if lhs and rhs:
                lhs_text = get_node_text(lhs, self.source_code).strip()
                rhs_text = get_node_text(rhs, self.source_code).strip()
                line, col = get_node_location(a)
                self.assignments.setdefault(lhs_text, []).append((rhs_text, line, col))

        # Extract init_declarator nodes (e.g. char *x = argv[1];)
        init_nodes = find_nodes_by_type(self.function_node, ["init_declarator"])
        for init in init_nodes:
            declarator = init.child_by_field_name("declarator")
            value = init.child_by_field_name("value")
            if declarator and value:
                lhs_text = get_node_text(declarator, self.source_code).strip().lstrip("*")
                rhs_text = get_node_text(value, self.source_code).strip()
                line, col = get_node_location(init)
                self.assignments.setdefault(lhs_text, []).append((rhs_text, line, col))

    def trace_origins(self, var_name: str, max_depth: int = 5) -> List[Tuple[str, int, int]]:
        """Trace the chain of expressions that flowed into `var_name`."""
        history = []
        visited = set()
        current = var_name

        for _ in range(max_depth):
            if current in visited:
                break
            visited.add(current)

            if current in self.assignments:
                # Take the most recent assignment before usage
                rhs_text, line, col = self.assignments[current][-1]
                history.append((f"{current} = {rhs_text}", line, col))
                # Check if rhs is another simple variable identifier
                tokens = [t for t in rhs_text.replace("(", " ").replace(")", " ").split() if t.isidentifier()]
                if tokens:
                    current = tokens[0]
                else:
                    break
            else:
                break

        return history


class DataFlowAnalyzer(BaseAnalyzer):
    name = "dataflow_analyzer"
    source_type = AnalyzerSource.DATAFLOW

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        # Dataflow findings are primarily surfaced through TaintAnalyzer and Multi-Analyzer Correlation
        return []
