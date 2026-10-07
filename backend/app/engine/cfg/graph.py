"""
Control-Flow Graph (CFG) Data Structures.
Defines Basic Blocks, Directed Edges with branching kinds, and the CFG container.
"""

from enum import Enum
from typing import List, Dict, Set, Optional, Any, Tuple
from tree_sitter import Node


class EdgeKind(str, Enum):
    FALLTHROUGH = "FALLTHROUGH"
    TRUE_BRANCH = "TRUE_BRANCH"
    FALSE_BRANCH = "FALSE_BRANCH"
    LOOP_BODY = "LOOP_BODY"
    LOOP_EXIT = "LOOP_EXIT"
    LOOP_BACK = "LOOP_BACK"
    SWITCH_CASE = "SWITCH_CASE"
    DEFAULT_CASE = "DEFAULT_CASE"
    UNCONDITIONAL = "UNCONDITIONAL"
    RETURN_TO_EXIT = "RETURN_TO_EXIT"
    BREAK_TO_EXIT = "BREAK_TO_EXIT"
    CONTINUE_LOOP = "CONTINUE_LOOP"
    GOTO_TARGET = "GOTO_TARGET"


class CFGEdge:
    """Directed edge connecting source basic block to target basic block."""

    def __init__(
        self,
        src_id: int,
        dst_id: int,
        kind: EdgeKind = EdgeKind.FALLTHROUGH,
        condition_node: Optional[Node] = None,
        case_value: Optional[Any] = None,
        label: str = ""
    ):
        self.src_id: int = src_id
        self.dst_id: int = dst_id
        self.kind: EdgeKind = kind
        self.condition_node: Optional[Node] = condition_node
        self.case_value: Optional[Any] = case_value
        self.label: str = label or kind.value

    def __repr__(self) -> str:
        return f"CFGEdge(B{self.src_id} -> B{self.dst_id}, {self.kind.value})"


class BasicBlock:
    """
    A sequence of linear statements with a single entry point and single exit point.
    """

    def __init__(self, block_id: int, label: str = ""):
        self.id: int = block_id
        self.label: str = label or f"B{block_id}"
        self.statements: List[Node] = []
        self.terminator: Optional[Node] = None
        self.incoming_edges: List[CFGEdge] = []
        self.outgoing_edges: List[CFGEdge] = []
        self.is_entry: bool = False
        self.is_exit: bool = False

    def add_statement(self, stmt_node: Node):
        self.statements.append(stmt_node)

    def set_terminator(self, term_node: Node):
        self.terminator = term_node

    def __repr__(self) -> str:
        tag = " [ENTRY]" if self.is_entry else (" [EXIT]" if self.is_exit else "")
        return f"BasicBlock({self.label}{tag}, stmts={len(self.statements)}, succs={len(self.outgoing_edges)})"


class ControlFlowGraph:
    """
    Intra-procedural Control-Flow Graph representing a single C/C++ function.
    """

    def __init__(self, function_name: str, func_node: Optional[Node] = None):
        self.function_name: str = function_name
        self.func_node: Optional[Node] = func_node
        self.blocks: Dict[int, BasicBlock] = {}
        self.entry_block: Optional[BasicBlock] = None
        self.exit_block: Optional[BasicBlock] = None
        self._next_id: int = 0

    def new_block(self, label: str = "") -> BasicBlock:
        b = BasicBlock(self._next_id, label=label)
        self.blocks[self._next_id] = b
        self._next_id += 1
        return b

    def add_edge(
        self,
        src: BasicBlock,
        dst: BasicBlock,
        kind: EdgeKind = EdgeKind.FALLTHROUGH,
        condition_node: Optional[Node] = None,
        case_value: Optional[Any] = None,
        label: str = ""
    ) -> CFGEdge:
        edge = CFGEdge(src.id, dst.id, kind=kind, condition_node=condition_node, case_value=case_value, label=label)
        src.outgoing_edges.append(edge)
        dst.incoming_edges.append(edge)
        return edge

    def get_predecessors(self, block: BasicBlock) -> List[BasicBlock]:
        return [self.blocks[e.src_id] for e in block.incoming_edges if e.src_id in self.blocks]

    def get_successors(self, block: BasicBlock) -> List[BasicBlock]:
        return [self.blocks[e.dst_id] for e in block.outgoing_edges if e.dst_id in self.blocks]

    def reverse_post_order(self) -> List[BasicBlock]:
        """Returns basic blocks in reverse post-order for optimal forward dataflow analysis."""
        visited: Set[int] = set()
        post_order: List[BasicBlock] = []

        def _dfs(block: BasicBlock):
            visited.add(block.id)
            for succ in self.get_successors(block):
                if succ.id not in visited:
                    _dfs(succ)
            post_order.append(block)

        if self.entry_block:
            _dfs(self.entry_block)

        post_order.reverse()
        return post_order

    def __repr__(self) -> str:
        return f"ControlFlowGraph(func='{self.function_name}', blocks={len(self.blocks)})"
