"""
Path-Sensitive Abstract Interpreter and Worklist Propagator over Control-Flow Graphs.
Executes abstract transfer functions inside basic blocks and refines path states
along conditional edges.
"""

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from tree_sitter import Node

from app.engine.cfg.graph import ControlFlowGraph, BasicBlock, CFGEdge, EdgeKind
from app.engine.cfg.state import PathState, PointerState, VarState, ResourceState, Nullness, Lifetime, InitStatus, ResourceStatus
from app.engine.parser import get_node_text, get_node_location, find_nodes_by_type


@dataclass
class PathDereferenceEvent:
    ptr_name: str
    line: int
    column: int
    code_snippet: str
    state_at_deref: PathState
    block_id: int


@dataclass
class PathFreeEvent:
    ptr_name: str
    line: int
    column: int
    code_snippet: str
    state_at_free: PathState
    block_id: int


@dataclass
class PathReadEvent:
    var_name: str
    line: int
    column: int
    code_snippet: str
    state_at_read: PathState
    block_id: int


@dataclass
class PathExitResourceEvent:
    resource_name: str
    status: ResourceStatus
    open_line: Optional[int]
    exit_line: int
    state_at_exit: PathState
    block_id: int


@dataclass
class PathUncheckedCallEvent:
    func_name: str
    line: int
    column: int
    code_snippet: str
    state: PathState
    block_id: int


class PathPropagator:
    """
    Executes path-sensitive forward dataflow propagation over a CFG until reaching a fixed point.
    """

    def __init__(self, cfg: ControlFlowGraph, source_code: str):
        self.cfg: ControlFlowGraph = cfg
        self.source_code: str = source_code

        # In and Out states per BasicBlock
        self.in_states: Dict[int, PathState] = {}
        self.out_states: Dict[int, PathState] = {}

        # Collected path events
        self.deref_events: List[PathDereferenceEvent] = []
        self.free_events: List[PathFreeEvent] = []
        self.read_events: List[PathReadEvent] = []
        self.exit_resources: List[PathExitResourceEvent] = []
        self.unchecked_calls: List[PathUncheckedCallEvent] = []

    def propagate(self):
        """Execute worklist algorithm over the CFG."""
        if not self.cfg.entry_block:
            return

        # Initialize entry state
        entry_state = PathState()
        self._init_function_parameters(entry_state)
        self.in_states[self.cfg.entry_block.id] = entry_state

        worklist = deque([self.cfg.entry_block])
        in_worklist = {self.cfg.entry_block.id}
        visit_counts: Dict[int, int] = {}
        MAX_BLOCK_VISITS = 10  # Guaranteed termination for loops

        while worklist:
            block = worklist.popleft()
            in_worklist.discard(block.id)

            visit_counts[block.id] = visit_counts.get(block.id, 0) + 1
            if visit_counts[block.id] > MAX_BLOCK_VISITS:
                continue

            # 1. Compute In(block) = Join across incoming edges
            if not block.is_entry:
                in_state = None
                for edge in block.incoming_edges:
                    src_out = self.out_states.get(edge.src_id)
                    if src_out is not None:
                        # Refine state based on edge kind
                        edge_state = self._refine_edge_state(src_out, edge)
                        if in_state is None:
                            in_state = edge_state.copy()
                        else:
                            in_state = in_state.join(edge_state)

                if in_state is None:
                    continue  # Block not yet reachable
                self.in_states[block.id] = in_state
            else:
                in_state = self.in_states[block.id]

            # 2. Transfer function: Out(block) = Transfer(block, In(block))
            out_state, changed = self._transfer_block(block, in_state)

            prev_out = self.out_states.get(block.id)
            if prev_out is None or changed:
                self.out_states[block.id] = out_state
                # Add successors to worklist
                for succ in self.cfg.get_successors(block):
                    if succ.id not in in_worklist:
                        worklist.append(succ)
                        in_worklist.add(succ.id)

        # 3. Check Exit Block resources
        if self.cfg.exit_block and self.cfg.exit_block.id in self.in_states:
            exit_state = self.in_states[self.cfg.exit_block.id]
            exit_line = self.cfg.exit_block.statements[0].start_point.row + 1 if self.cfg.exit_block.statements else 1
            for res_name, res_info in exit_state.resources.items():
                if res_info.status in (ResourceStatus.OPEN, ResourceStatus.POTENTIALLY_LEAKED):
                    self.exit_resources.append(
                        PathExitResourceEvent(
                            resource_name=res_name,
                            status=res_info.status,
                            open_line=res_info.open_line,
                            exit_line=exit_line,
                            state_at_exit=exit_state,
                            block_id=self.cfg.exit_block.id,
                        )
                    )

    def _init_function_parameters(self, state: PathState):
        if not self.cfg.func_node:
            return
        decl = self.cfg.func_node.child_by_field_name("declarator")
        if not decl:
            return
        params = find_nodes_by_type(decl, ["parameter_declaration"])
        for p in params:
            type_node = p.child_by_field_name("type")
            d_node = p.child_by_field_name("declarator")
            type_text = get_node_text(type_node, self.source_code).strip() if type_node else ""
            var_name = get_node_text(d_node, self.source_code).lstrip("*&").strip() if d_node else ""

            if var_name:
                # Function parameters are initialized by caller
                state.variables[var_name] = VarState(init_status=InitStatus.INITIALIZED)
                if "*" in type_text or (d_node and "*" in get_node_text(d_node, self.source_code)):
                    # Pointer parameter (caller-supplied pointer, unknown nullness initially)
                    state.pointers[var_name] = PointerState(nullness=Nullness.UNKNOWN, lifetime=Lifetime.ALLOCATED)

    def _refine_edge_state(self, src_state: PathState, edge: CFGEdge) -> PathState:
        """Refines pointer nullness and conditions along True/False branch edges."""
        refined = src_state.copy()

        if edge.kind == EdgeKind.TRUE_BRANCH and edge.condition_node:
            self._apply_condition_refinement(refined, edge.condition_node, is_true=True)
            refined.path_trace.append(f"Taken True on {get_node_text(edge.condition_node, self.source_code).strip()}")

        elif edge.kind == EdgeKind.FALSE_BRANCH and edge.condition_node:
            self._apply_condition_refinement(refined, edge.condition_node, is_true=False)
            refined.path_trace.append(f"Taken False on {get_node_text(edge.condition_node, self.source_code).strip()}")

        return refined

    def _apply_condition_refinement(self, state: PathState, cond_node: Node, is_true: bool):
        if cond_node.type == "parenthesized_expression":
            for child in cond_node.named_children:
                self._apply_condition_refinement(state, child, is_true)
            return

        if cond_node.type == "unary_expression":
            op = get_node_text(cond_node.child_by_field_name("operator"), self.source_code).strip()
            if op == "!":
                arg = cond_node.child_by_field_name("argument")
                if arg:
                    self._apply_condition_refinement(state, arg, not is_true)
                return

        # Binary comparisons (p == NULL, p != NULL, !p, p == 0)
        if cond_node.type == "binary_expression":
            left = cond_node.child_by_field_name("left")
            right = cond_node.child_by_field_name("right")
            op_node = cond_node.child_by_field_name("operator")
            op = get_node_text(op_node, self.source_code).strip() if op_node else ""

            left_txt = get_node_text(left, self.source_code).strip() if left else ""
            right_txt = get_node_text(right, self.source_code).strip() if right else ""

            # Check if pointer compared to NULL / 0
            is_null_cmp = right_txt in ("NULL", "0", "nullptr") or left_txt in ("NULL", "0", "nullptr")
            ptr_name = left_txt if right_txt in ("NULL", "0", "nullptr") else (right_txt if is_null_cmp else "")

            if ptr_name and ptr_name in state.pointers:
                if op in ("==", "="):
                    if is_true:
                        state.pointers[ptr_name].nullness = Nullness.NULL
                    else:
                        state.pointers[ptr_name].nullness = Nullness.NON_NULL
                elif op == "!=":
                    if is_true:
                        state.pointers[ptr_name].nullness = Nullness.NON_NULL
                    else:
                        state.pointers[ptr_name].nullness = Nullness.NULL

        # Bare identifier: if (p)
        elif cond_node.type == "identifier":
            ptr_name = get_node_text(cond_node, self.source_code).strip()
            if ptr_name in state.pointers:
                if is_true:
                    state.pointers[ptr_name].nullness = Nullness.NON_NULL
                else:
                    state.pointers[ptr_name].nullness = Nullness.NULL

    def _transfer_block(self, block: BasicBlock, in_state: PathState) -> Tuple[PathState, bool]:
        state = in_state.copy()

        for stmt in block.statements:
            self._transfer_statement(stmt, state, block.id)

        # Check if changed compared to previous out state
        prev_out = self.out_states.get(block.id)
        if prev_out is None:
            changed = True
        else:
            changed = (
                state.pointers != prev_out.pointers or
                state.variables != prev_out.variables or
                state.resources != prev_out.resources
            )

        return state, changed

    def _transfer_statement(self, stmt: Node, state: PathState, block_id: int):
        stype = stmt.type

        # 1. Declarations: int x; int *p = malloc(10); FILE *f = fopen(...);
        if stype == "declaration":
            self._handle_declaration(stmt, state, block_id)

        # 2. Expression statements
        elif stype == "expression_statement":
            for child in stmt.named_children:
                self._handle_expression(child, state, block_id)

        # 3. Return statements: check if dereferencing in return expr
        elif stype == "return_statement":
            for child in stmt.named_children:
                self._handle_expression(child, state, block_id)

    def _handle_declaration(self, decl_node: Node, state: PathState, block_id: int):
        type_node = decl_node.child_by_field_name("type")
        type_text = get_node_text(type_node, self.source_code).strip() if type_node else ""

        declarators = find_nodes_by_type(decl_node, ["init_declarator", "pointer_declarator", "identifier"])
        for d in declarators:
            if d.type == "init_declarator":
                var_decl = d.child_by_field_name("declarator")
                val_node = d.child_by_field_name("value")
                var_name = get_node_text(var_decl, self.source_code).lstrip("*&").strip() if var_decl else ""
                line, col = get_node_location(d)
                snippet = get_node_text(d, self.source_code).strip()

                if var_name:
                    # Mark initialized
                    state.variables[var_name] = VarState(init_status=InitStatus.INITIALIZED)

                    # Dynamic allocation or resource creation
                    if val_node and val_node.type == "call_expression":
                        fn_name = get_node_text(val_node.child_by_field_name("function"), self.source_code).strip()
                        if fn_name in ("malloc", "calloc", "realloc"):
                            state.pointers[var_name] = PointerState(
                                nullness=Nullness.UNCHECKED_ALLOCATION,
                                lifetime=Lifetime.ALLOCATED,
                                alloc_line=line
                            )
                        elif fn_name in ("fopen", "open", "socket"):
                            state.resources[var_name] = ResourceState(
                                status=ResourceStatus.OPEN,
                                open_line=line
                            )

                    # Pointer assignment: char *p = q;
                    elif val_node and val_node.type == "identifier":
                        src_var = get_node_text(val_node, self.source_code).strip()
                        if src_var in state.pointers:
                            state.pointers[var_name] = state.pointers[src_var].copy()
                            state.add_alias(var_name, src_var)

                    self._handle_expression(val_node, state, block_id)

            elif d.type == "identifier" and d.parent and d.parent.type == "declaration":
                # Uninitialized variable declaration: int x;
                var_name = get_node_text(d, self.source_code).strip()
                if var_name:
                    state.variables[var_name] = VarState(init_status=InitStatus.UNINITIALIZED)

    def _handle_expression(self, expr: Optional[Node], state: PathState, block_id: int):
        if not expr:
            return

        ntype = expr.type
        line, col = get_node_location(expr)
        snippet = get_node_text(expr, self.source_code).strip()

        # 1. Pointer Dereference (*p, p->field, p[i])
        if ntype == "pointer_expression":
            arg = expr.child_by_field_name("argument")
            ptr_name = get_node_text(arg, self.source_code).lstrip("*&").strip() if arg else ""
            if ptr_name:
                self.deref_events.append(
                    PathDereferenceEvent(
                        ptr_name=ptr_name,
                        line=line,
                        column=col,
                        code_snippet=snippet,
                        state_at_deref=state.copy(),
                        block_id=block_id,
                    )
                )

        elif ntype == "field_expression":
            # p->field
            op = expr.child_by_field_name("operator")
            if op and get_node_text(op, self.source_code).strip() == "->":
                arg = expr.child_by_field_name("argument")
                ptr_name = get_node_text(arg, self.source_code).strip() if arg else ""
                if ptr_name:
                    self.deref_events.append(
                        PathDereferenceEvent(
                            ptr_name=ptr_name,
                            line=line,
                            column=col,
                            code_snippet=snippet,
                            state_at_deref=state.copy(),
                            block_id=block_id,
                        )
                    )

        # 2. Assignment expression (p = NULL, p = malloc(...), x = 5)
        elif ntype == "assignment_expression":
            left = expr.child_by_field_name("left")
            right = expr.child_by_field_name("right")

            # Check right side reads first
            self._handle_expression(right, state, block_id)

            if left and left.type == "identifier":
                var_name = get_node_text(left, self.source_code).strip()
                state.variables[var_name] = VarState(init_status=InitStatus.INITIALIZED)

                if right and right.type == "call_expression":
                    fn_name = get_node_text(right.child_by_field_name("function"), self.source_code).strip()
                    if fn_name in ("malloc", "calloc", "realloc"):
                        state.pointers[var_name] = PointerState(
                            nullness=Nullness.UNCHECKED_ALLOCATION,
                            lifetime=Lifetime.ALLOCATED,
                            alloc_line=line
                        )
                    elif fn_name in ("fopen", "open", "socket"):
                        state.resources[var_name] = ResourceState(status=ResourceStatus.OPEN, open_line=line)
                elif right and right.type == "identifier":
                    right_name = get_node_text(right, self.source_code).strip()
                    if right_name in ("NULL", "0", "nullptr"):
                        if var_name in state.pointers:
                            state.pointers[var_name].nullness = Nullness.NULL
                    elif right_name in state.pointers:
                        state.pointers[var_name] = state.pointers[right_name].copy()
                        state.add_alias(var_name, right_name)

            elif left and left.type == "pointer_expression":
                # *p = val -> pointer dereference write!
                arg = left.child_by_field_name("argument")
                ptr_name = get_node_text(arg, self.source_code).lstrip("*&").strip() if arg else ""
                if ptr_name:
                    self.deref_events.append(
                        PathDereferenceEvent(
                            ptr_name=ptr_name,
                            line=line,
                            column=col,
                            code_snippet=snippet,
                            state_at_deref=state.copy(),
                            block_id=block_id,
                        )
                    )

            return

        # 3. Call expressions (free(p), fclose(f), etc.)
        elif ntype == "call_expression":
            fn_node = expr.child_by_field_name("function")
            fn_name = get_node_text(fn_node, self.source_code).strip() if fn_node else ""
            args_node = expr.child_by_field_name("arguments")
            args = args_node.named_children if args_node else []

            if fn_name == "free" and args:
                arg_name = get_node_text(args[0], self.source_code).lstrip("*&").strip()
                if arg_name:
                    self.free_events.append(
                        PathFreeEvent(
                            ptr_name=arg_name,
                            line=line,
                            column=col,
                            code_snippet=snippet,
                            state_at_free=state.copy(),
                            block_id=block_id,
                        )
                    )
                    # Update pointer and all aliases to FREED
                    all_aliases = state.get_all_aliases(arg_name)
                    for a in all_aliases:
                        if a in state.pointers:
                            state.pointers[a].lifetime = Lifetime.FREED
                            state.pointers[a].free_line = line

            elif fn_name in ("fclose", "close") and args:
                arg_name = get_node_text(args[0], self.source_code).strip()
                if arg_name in state.resources:
                    state.resources[arg_name].status = ResourceStatus.CLOSED

            # Critical unchecked API calls (setuid, seteuid, etc.)
            elif fn_name in ("setuid", "setgid", "seteuid", "setegid"):
                # If call expression parent is just an expression_statement (return ignored)
                if expr.parent and expr.parent.type == "expression_statement":
                    self.unchecked_calls.append(
                        PathUncheckedCallEvent(
                            func_name=fn_name,
                            line=line,
                            column=col,
                            code_snippet=snippet,
                            state=state.copy(),
                            block_id=block_id,
                        )
                    )

        # 4. Identifier Read (Variable initialization check)
        elif ntype == "identifier":
            var_name = get_node_text(expr, self.source_code).strip()
            # If variable read in an expression
            if var_name in state.variables:
                self.read_events.append(
                    PathReadEvent(
                        var_name=var_name,
                        line=line,
                        column=col,
                        code_snippet=snippet,
                        state_at_read=state.copy(),
                        block_id=block_id,
                    )
                )

        # Traverse sub-nodes
        for child in expr.named_children:
            self._handle_expression(child, state, block_id)
