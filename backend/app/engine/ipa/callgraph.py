"""
Call Graph Construction and Bottom-Up Topological Traversal.
Maps call sites across the analyzed source unit to compute optimal summarization order.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from tree_sitter import Node

from app.engine.parser import (
    get_node_text,
    get_node_location,
    get_function_definitions,
    get_call_expressions,
    get_call_name,
    get_call_arguments,
)


@dataclass
class CallSite:
    caller_name: str
    callee_name: str
    line: int
    column: int
    arg_nodes: List[Node]
    call_node: Node


class CallGraph:
    """
    Inter-procedural Call Graph for functions within a translation unit / project.
    """

    def __init__(self):
        self.functions: Dict[str, Node] = {}  # func_name -> func_def_node
        self.call_sites: List[CallSite] = []
        self.callees: Dict[str, Set[str]] = {}  # caller -> set of callee names
        self.callers: Dict[str, Set[str]] = {}  # callee -> set of caller names

    @staticmethod
    def _extract_func_name(func_node: Node, source_code: str) -> str:
        decl = func_node.child_by_field_name("declarator")
        if not decl:
            return "anonymous"
        curr = decl
        while curr and curr.type in ("function_declarator", "pointer_declarator"):
            child = curr.child_by_field_name("declarator")
            if child:
                curr = child
            else:
                break
        return get_node_text(curr, source_code).strip() or "anonymous"

    def build_from_ast(self, root: Node, source_code: str):
        """Extract all function definitions and call sites to build the graph."""
        func_nodes = get_function_definitions(root)

        for fn in func_nodes:
            fn_name = self._extract_func_name(fn, source_code)
            self.functions[fn_name] = fn
            self.callees.setdefault(fn_name, set())

        for fn_name, fn_node in self.functions.items():
            calls = get_call_expressions(fn_node)
            for c in calls:
                callee_name = get_call_name(c, source_code)
                if not callee_name:
                    continue

                args = get_call_arguments(c)
                line, col = get_node_location(c)

                site = CallSite(
                    caller_name=fn_name,
                    callee_name=callee_name,
                    line=line,
                    column=col,
                    arg_nodes=args,
                    call_node=c,
                )
                self.call_sites.append(site)
                self.callees[fn_name].add(callee_name)
                self.callers.setdefault(callee_name, set()).add(fn_name)

    def bottom_up_order(self) -> List[str]:
        """
        Returns functions in bottom-up topological order (leaves/callees first, callers later).
        """
        visited: Set[str] = set()
        order: List[str] = []

        def _dfs(name: str, path: Set[str]):
            if name in path or name in visited:
                return
            path.add(name)
            for callee in self.callees.get(name, set()):
                if callee in self.functions:
                    _dfs(callee, path)
            path.remove(name)
            visited.add(name)
            order.append(name)

        for fn in self.functions:
            if fn not in visited:
                _dfs(fn, set())

        return order
