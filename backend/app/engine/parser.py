"""
Tree-sitter AST parser and query helpers for C and C++ source code.
"""

import os
from typing import List, Optional, Tuple, Any
import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser, Node, Tree

from app.engine.base import AnalysisContext

C_LANGUAGE = Language(tsc.language())
CPP_LANGUAGE = Language(tscpp.language())

_c_parser = Parser(C_LANGUAGE)
_cpp_parser = Parser(CPP_LANGUAGE)


def is_cpp_file(file_path: str) -> bool:
    ext = os.path.splitext(file_path)[1].lower()
    return ext in {".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".hh"}


def parse_source(source_code: str, file_path: str = "source.c") -> AnalysisContext:
    """Parse C/C++ source code using Tree-sitter into an AnalysisContext."""
    cpp_flag = is_cpp_file(file_path)
    parser = _cpp_parser if cpp_flag else _c_parser
    source_bytes = source_code.encode("utf-8", errors="replace")
    tree: Tree = parser.parse(source_bytes)

    lines = source_code.splitlines()

    return AnalysisContext(
        file_path=file_path,
        source_code=source_code,
        lines=lines,
        is_cpp=cpp_flag,
        ast_root=tree.root_node,
        tree_sitter_tree=tree,
    )


def get_node_text(node: Node, source_code: str) -> str:
    """Extract source text corresponding to an AST node."""
    if not node:
        return ""
    start_byte = node.start_byte
    end_byte = node.end_byte
    return source_code.encode("utf-8", errors="replace")[start_byte:end_byte].decode("utf-8", errors="replace")


def get_node_location(node: Node) -> Tuple[int, int]:
    """Return 1-indexed (line, column) for the start of an AST node."""
    return (node.start_point.row + 1, node.start_point.column + 1)


def find_nodes_by_type(root: Node, node_types: List[str]) -> List[Node]:
    """Recursively find all AST nodes matching any of the specified type names."""
    results: List[Node] = []
    types_set = set(node_types)

    def _traverse(n: Node):
        if n.type in types_set:
            results.append(n)
        for child in n.children:
            _traverse(child)

    _traverse(root)
    return results


def get_call_expressions(root: Node) -> List[Node]:
    """Retrieve all function call expressions in the AST."""
    return find_nodes_by_type(root, ["call_expression"])


def get_call_name(call_node: Node, source_code: str) -> Optional[str]:
    """Extract the function name from a call_expression node."""
    if call_node.type != "call_expression":
        return None
    func_node = call_node.child_by_field_name("function")
    if not func_node:
        # Fallback to first named child
        if call_node.named_children:
            func_node = call_node.named_children[0]
        else:
            return None
    return get_node_text(func_node, source_code).strip()


def get_call_arguments(call_node: Node) -> List[Node]:
    """Retrieve argument nodes from a call_expression node."""
    if call_node.type != "call_expression":
        return []
    args_node = call_node.child_by_field_name("arguments")
    if not args_node:
        return []
    # Return all named children of arguments (excluding parentheses/commas)
    return [child for child in args_node.named_children]


def find_parent_of_type(node: Node, parent_types: List[str]) -> Optional[Node]:
    """Traverse upwards to find the closest ancestor of any specified type."""
    types_set = set(parent_types)
    curr = node.parent
    while curr:
        if curr.type in types_set:
            return curr
        curr = curr.parent
    return None


def get_function_definitions(root: Node) -> List[Node]:
    """Retrieve all top-level and nested function definitions."""
    return find_nodes_by_type(root, ["function_definition"])
