"""
Taint State Tracking Domain and Environment.
Maintains dataflow steps, variable and struct field mappings, pointer aliases,
and precise AST identifier extraction.
"""

from typing import Dict, Set, List, Optional, Tuple
from tree_sitter import Node

from app.engine.base import DataflowStep
from app.engine.taint.spec import TaintState
from app.engine.parser import get_node_text, find_nodes_by_type


class TaintTrackedValue:
    """
    Represents a value tracked by the taint engine with its full dataflow history.
    """

    def __init__(
        self,
        state: TaintState = TaintState.UNKNOWN,
        source_desc: str = "",
        source_line: int = 1,
        source_col: int = 1,
        steps: Optional[List[DataflowStep]] = None,
        sanitizer_name: Optional[str] = None,
        is_trusted_sanitizer: bool = True,
    ):
        self.state: TaintState = state
        self.source_desc: str = source_desc
        self.source_line: int = source_line
        self.source_col: int = source_col
        self.steps: List[DataflowStep] = list(steps) if steps else []
        self.sanitizer_name: Optional[str] = sanitizer_name
        self.is_trusted_sanitizer: bool = is_trusted_sanitizer

    def copy(self) -> "TaintTrackedValue":
        return TaintTrackedValue(
            state=self.state,
            source_desc=self.source_desc,
            source_line=self.source_line,
            source_col=self.source_col,
            steps=[DataflowStep(s.step_type, s.line, s.column, s.code, s.description) for s in self.steps],
            sanitizer_name=self.sanitizer_name,
            is_trusted_sanitizer=self.is_trusted_sanitizer,
        )

    def add_step(self, step_type: str, line: int, column: Optional[int], code: str, desc: str):
        self.steps.append(DataflowStep(step_type, line, column, code, desc))

    def mark_sanitized(self, sanitizer_name: str, line: int, column: Optional[int], code: str, is_trusted: bool):
        self.sanitizer_name = sanitizer_name
        self.is_trusted_sanitizer = is_trusted
        if is_trusted:
            self.state = TaintState.DEFINITELY_SANITIZED
        else:
            self.state = TaintState.POSSIBLY_TAINTED
        self.add_step("SANITIZER", line, column, code, f"Passed through sanitizer '{sanitizer_name}()' (trusted={is_trusted})")


class TaintEnvironment:
    """
    Tracks taint state across variables, struct fields, pointer aliases, and return values.
    """

    def __init__(self):
        # name -> TaintTrackedValue (e.g. "x", "req.url", "*p", "arr[0]")
        self.variables: Dict[str, TaintTrackedValue] = {}
        # var -> Set[alias_vars]
        self.aliases: Dict[str, Set[str]] = {}
        # Return expression taint
        self.return_taint: Optional[TaintTrackedValue] = None

    def copy(self) -> "TaintEnvironment":
        clone = TaintEnvironment()
        clone.variables = {k: v.copy() for k, v in self.variables.items()}
        clone.aliases = {k: set(v) for k, v in self.aliases.items()}
        clone.return_taint = self.return_taint.copy() if self.return_taint else None
        return clone

    def set_tracked(self, name: str, val: TaintTrackedValue):
        cleaned = name.strip()
        if cleaned:
            self.variables[cleaned] = val
            # If alias exists, propagate
            for alias in self.aliases.get(cleaned, set()):
                self.variables[alias] = val.copy()

    def get_tracked(self, name: str) -> Optional[TaintTrackedValue]:
        cleaned = name.strip()
        if cleaned in self.variables:
            return self.variables[cleaned]
        # Check aliases
        for alias in self.aliases.get(cleaned, set()):
            if alias in self.variables:
                return self.variables[alias]
        return None

    def add_alias(self, v1: str, v2: str):
        c1, c2 = v1.strip(), v2.strip()
        if not c1 or not c2 or c1 == c2:
            return
        self.aliases.setdefault(c1, set()).add(c2)
        self.aliases.setdefault(c2, set()).add(c1)

    @staticmethod
    def extract_identifiers(node: Optional[Node], source_code: str) -> List[Tuple[str, Node]]:
        """
        Extracts exact AST identifier tokens from an expression.
        Prevents dangerous substring false positives!
        """
        if not node:
            return []

        results: List[Tuple[str, Node]] = []
        ident_nodes = find_nodes_by_type(node, ["identifier", "field_expression", "subscript_expression", "pointer_expression"])
        
        for n in ident_nodes:
            txt = get_node_text(n, source_code).strip()
            if txt:
                results.append((txt, n))

        return results

    @staticmethod
    def is_constant_expression(node: Optional[Node], source_code: str) -> bool:
        """
        Checks if an expression node is a compile-time safe constant / string literal.
        """
        if not node:
            return False
        if node.type in ("string_literal", "number_literal", "char_literal"):
            return True
        if node.type == "parenthesized_expression":
            for child in node.named_children:
                return TaintEnvironment.is_constant_expression(child, source_code)
        return False
