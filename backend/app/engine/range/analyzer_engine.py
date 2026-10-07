"""
Flow-Sensitive Range Analysis Engine for C/C++ Functions.
Traverses function bodies statement by statement, maintaining and refining
variable intervals across assignments, conditional branches, loops, and calls.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set
from tree_sitter import Node

from app.engine.range.interval import Interval, CTypeRange, INF, INT32_MIN, INT32_MAX, UINT32_MAX
from app.engine.range.evaluator import RangeEnvironment, ExpressionEvaluator, ConditionRefiner
from app.engine.parser import get_node_text, get_node_location, find_nodes_by_type


@dataclass
class ArrayAccessFact:
    array_name: str
    index_expr: str
    index_interval: Interval
    array_size: Optional[int]
    element_size: int
    line: int
    column: int
    code_snippet: str
    is_write: bool = False
    loop_bound_exceeded: bool = False


@dataclass
class PointerArithmeticFact:
    ptr_name: str
    offset_expr: str
    offset_interval: Interval
    buffer_size: Optional[int]
    line: int
    column: int
    code_snippet: str


@dataclass
class MemoryCallFact:
    call_name: str  # malloc, calloc, realloc, memcpy, memmove, memset, read, strncpy, snprintf
    args: List[str]
    arg_intervals: List[Interval]
    dest_size: Optional[int]
    line: int
    column: int
    code_snippet: str


@dataclass
class IntOverflowFact:
    op: str
    expr_text: str
    left_interval: Interval
    right_interval: Interval
    result_interval: Interval
    line: int
    column: int
    code_snippet: str
    context_type: str = "signed_int"  # signed_int, alloc_size, unsigned_int


@dataclass
class ConversionFact:
    from_type: str
    to_type: str
    val_interval: Interval
    expr_text: str
    line: int
    column: int
    code_snippet: str
    is_dangerous_signed_to_unsigned: bool = False


class FunctionRangeAnalyzer:
    """
    Analyzes a single C/C++ function definition to infer value ranges and
    collect all safety facts.
    """

    def __init__(self, func_node: Node, source_code: str, file_path: str):
        self.func_node = func_node
        self.source_code = source_code
        self.file_path = file_path

        # Collected facts
        self.array_accesses: List[ArrayAccessFact] = []
        self.pointer_ops: List[PointerArithmeticFact] = []
        self.memory_calls: List[MemoryCallFact] = []
        self.overflow_facts: List[IntOverflowFact] = []
        self.conversion_facts: List[ConversionFact] = []

    def analyze(self) -> "FunctionRangeAnalyzer":
        initial_env = RangeEnvironment()
        self._init_parameters(initial_env)
        body = self.func_node.child_by_field_name("body")
        if body:
            self._walk_statement(body, initial_env)
        return self

    def _init_parameters(self, env: RangeEnvironment):
        """Extract parameter names and types, assign default conservative ranges."""
        params_node = self.func_node.child_by_field_name("declarator")
        if not params_node:
            return

        param_nodes = find_nodes_by_type(params_node, ["parameter_declaration"])
        for p in param_nodes:
            type_node = p.child_by_field_name("type")
            decl_node = p.child_by_field_name("declarator")
            type_text = get_node_text(type_node, self.source_code).strip() if type_node else "int"
            var_name = get_node_text(decl_node, self.source_code).strip() if decl_node else ""
            # Clean pointer stars from var_name
            var_name = var_name.lstrip("*&").strip()

            if var_name:
                env.types[var_name] = type_text
                # If unsigned or size_t, parameter range is [0, MAX]
                if CTypeRange.is_unsigned_type(type_text):
                    env.set_var_interval(var_name, Interval(0, UINT32_MAX))
                else:
                    env.set_var_interval(var_name, Interval(INT32_MIN, INT32_MAX))

    def _walk_statement(self, node: Node, env: RangeEnvironment) -> Tuple[RangeEnvironment, bool]:
        """
        Walks a statement AST node.
        Returns (resulting_env, has_early_exit).
        """
        if not node:
            return env, False

        ntype = node.type

        # 1. Compound statement { s1; s2; ... }
        if ntype == "compound_statement":
            curr_env = env
            for child in node.named_children:
                curr_env, early_exit = self._walk_statement(child, curr_env)
                if early_exit:
                    return curr_env, True
            return curr_env, False

        # 2. Declaration (int arr[10]; int x = 5; char *p = malloc(100);)
        elif ntype == "declaration":
            self._handle_declaration(node, env)
            return env, False

        # 3. Expression Statement (x = 5; arr[i] = 1; memcpy(...);)
        elif ntype == "expression_statement":
            for child in node.named_children:
                self._handle_expression(child, env)
            return env, False

        # 4. If Statement (if (cond) { ... } else { ... })
        elif ntype == "if_statement":
            return self._handle_if_statement(node, env)

        # 5. For Loop (for (int i = 0; i < N; i++) { ... })
        elif ntype == "for_statement":
            return self._handle_for_statement(node, env)

        # 6. While Loop (while (cond) { ... })
        elif ntype == "while_statement":
            return self._handle_while_statement(node, env)

        # 7. Return Statement
        elif ntype == "return_statement":
            for child in node.named_children:
                self._handle_expression(child, env)
            return env, True  # Early exit

        # Default: walk children
        for child in node.named_children:
            env, early_exit = self._walk_statement(child, env)
            if early_exit:
                return env, True

        return env, False

    def _handle_declaration(self, node: Node, env: RangeEnvironment):
        type_node = node.child_by_field_name("type")
        type_text = get_node_text(type_node, self.source_code).strip() if type_node else "int"

        # Walk declarators
        declarators = find_nodes_by_type(node, ["init_declarator", "array_declarator", "pointer_declarator", "identifier"])
        for d in declarators:
            # Array declaration: char buf[10];
            if d.type == "array_declarator":
                arr_ident = d.child_by_field_name("declarator")
                size_node = d.child_by_field_name("size")
                arr_name = get_node_text(arr_ident, self.source_code).strip()
                size_iv = ExpressionEvaluator.evaluate(size_node, env, self.source_code) if size_node else Interval.top()
                if size_iv.is_constant and size_iv.constant_value is not None:
                    count = size_iv.constant_value
                    elem_sz = CTypeRange.get_sizeof(type_text)
                    env.arrays[arr_name] = {
                        "element_count": count,
                        "element_size": elem_sz,
                        "total_bytes": count * elem_sz
                    }
                    env.buffers[arr_name] = Interval.exact(count * elem_sz)
            
            # Initialized declarator: int x = 5; or char *p = malloc(64);
            elif d.type == "init_declarator":
                var_decl = d.child_by_field_name("declarator")
                val_node = d.child_by_field_name("value")
                var_name = get_node_text(var_decl, self.source_code).lstrip("*&").strip()

                if var_name:
                    env.types[var_name] = type_text
                    val_iv = ExpressionEvaluator.evaluate(val_node, env, self.source_code)
                    env.set_var_interval(var_name, val_iv)

                    # Check if dynamic allocation: char *p = malloc(size);
                    if val_node and val_node.type == "call_expression":
                        fn_name = get_node_text(val_node.child_by_field_name("function"), self.source_code).strip()
                        args = val_node.child_by_field_name("arguments")
                        arg_children = args.named_children if args else []
                        if fn_name in ("malloc", "realloc") and arg_children:
                            sz_iv = ExpressionEvaluator.evaluate(arg_children[-1], env, self.source_code)
                            env.buffers[var_name] = sz_iv
                        elif fn_name == "calloc" and len(arg_children) >= 2:
                            n_iv = ExpressionEvaluator.evaluate(arg_children[0], env, self.source_code)
                            s_iv = ExpressionEvaluator.evaluate(arg_children[1], env, self.source_code)
                            env.buffers[var_name] = n_iv.mul(s_iv)

                    # Evaluate any sub-expressions in the initializer
                    self._handle_expression(val_node, env)

    def _handle_expression(self, node: Optional[Node], env: RangeEnvironment):
        if not node:
            return

        ntype = node.type

        # 1. Assignment expression (x = expr; x += expr; arr[i] = val;)
        if ntype == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            op_node = node.child_by_field_name("operator")
            op = get_node_text(op_node, self.source_code).strip() if op_node else "="

            self._handle_expression(right, env)

            if left and left.type == "identifier":
                var_name = get_node_text(left, self.source_code).strip()
                right_iv = ExpressionEvaluator.evaluate(right, env, self.source_code)
                curr_iv = env.get_var_interval(var_name)

                if op == "=":
                    env.set_var_interval(var_name, right_iv)
                elif op == "+=":
                    env.set_var_interval(var_name, curr_iv.add(right_iv))
                elif op == "-=":
                    env.set_var_interval(var_name, curr_iv.sub(right_iv))
                elif op == "*=":
                    env.set_var_interval(var_name, curr_iv.mul(right_iv))

            elif left and left.type == "subscript_expression":
                # Array assignment: arr[i] = val
                self._check_subscript(left, env, is_write=True)

            return

        # 2. Subscript expression (arr[i])
        elif ntype == "subscript_expression":
            self._check_subscript(node, env, is_write=False)

        # 3. Call expression (memcpy, malloc, etc.)
        elif ntype == "call_expression":
            self._check_call(node, env)

        # 4. Binary expression (check for arithmetic overflows)
        elif ntype == "binary_expression":
            self._check_binary_overflow(node, env)

        # 5. Cast expression (check for signed/unsigned mismatch)
        elif ntype == "cast_expression":
            self._check_cast(node, env)

        # 6. Unary expression (x++, ++x, x--, --x)
        elif ntype == "update_expression":
            arg = node.child_by_field_name("argument")
            op = get_node_text(node.child_by_field_name("operator"), self.source_code).strip()
            if arg and arg.type == "identifier":
                var_name = get_node_text(arg, self.source_code).strip()
                curr = env.get_var_interval(var_name)
                if "++" in op:
                    env.set_var_interval(var_name, curr.add(Interval.exact(1)))
                elif "--" in op:
                    env.set_var_interval(var_name, curr.sub(Interval.exact(1)))

        # Traverse children
        for child in node.named_children:
            self._handle_expression(child, env)

    def _check_subscript(self, node: Node, env: RangeEnvironment, is_write: bool):
        """Checks array bounds on `arr[index]`."""
        arg_node = node.child_by_field_name("argument")
        idx_node = node.child_by_field_name("index")
        if not arg_node or not idx_node:
            return

        arr_name = get_node_text(arg_node, self.source_code).strip()
        idx_text = get_node_text(idx_node, self.source_code).strip()
        idx_iv = ExpressionEvaluator.evaluate(idx_node, env, self.source_code)

        line, col = get_node_location(node)
        snippet = get_node_text(node, self.source_code).strip()

        arr_info = env.arrays.get(arr_name)
        arr_size = arr_info["element_count"] if arr_info else None
        elem_size = arr_info["element_size"] if arr_info else 1

        self.array_accesses.append(
            ArrayAccessFact(
                array_name=arr_name,
                index_expr=idx_text,
                index_interval=idx_iv,
                array_size=arr_size,
                element_size=elem_size,
                line=line,
                column=col,
                code_snippet=snippet,
                is_write=is_write,
            )
        )

    def _check_call(self, node: Node, env: RangeEnvironment):
        fn_node = node.child_by_field_name("function")
        fn_name = get_node_text(fn_node, self.source_code).strip() if fn_node else ""
        args_node = node.child_by_field_name("arguments")
        args = args_node.named_children if args_node else []

        arg_texts = [get_node_text(a, self.source_code).strip() for a in args]
        arg_intervals = [ExpressionEvaluator.evaluate(a, env, self.source_code) for a in args]

        line, col = get_node_location(node)
        snippet = get_node_text(node, self.source_code).strip()

        # Extract destination size if known
        dest_size = None
        if fn_name in ("memcpy", "memmove", "memset", "strncpy", "snprintf") and arg_texts:
            dest_var = arg_texts[0].lstrip("&*")
            if dest_var in env.arrays:
                dest_size = env.arrays[dest_var]["total_bytes"]
            elif dest_var in env.buffers and env.buffers[dest_var].is_constant:
                dest_size = env.buffers[dest_var].constant_value

        self.memory_calls.append(
            MemoryCallFact(
                call_name=fn_name,
                args=arg_texts,
                arg_intervals=arg_intervals,
                dest_size=dest_size,
                line=line,
                column=col,
                code_snippet=snippet,
            )
        )

    def _check_binary_overflow(self, node: Node, env: RangeEnvironment):
        op_node = node.child_by_field_name("operator")
        op = get_node_text(op_node, self.source_code).strip() if op_node else ""
        if op not in ("+", "-", "*", "<<"):
            return

        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        left_iv = ExpressionEvaluator.evaluate(left, env, self.source_code)
        right_iv = ExpressionEvaluator.evaluate(right, env, self.source_code)

        result_iv = ExpressionEvaluator.evaluate(node, env, self.source_code)
        line, col = get_node_location(node)
        snippet = get_node_text(node, self.source_code).strip()

        self.overflow_facts.append(
            IntOverflowFact(
                op=op,
                expr_text=snippet,
                left_interval=left_iv,
                right_interval=right_iv,
                result_interval=result_iv,
                line=line,
                column=col,
                code_snippet=snippet,
            )
        )

    def _check_cast(self, node: Node, env: RangeEnvironment):
        type_node = node.child_by_field_name("type")
        val_node = node.child_by_field_name("value")
        type_text = get_node_text(type_node, self.source_code).strip() if type_node else ""
        val_iv = ExpressionEvaluator.evaluate(val_node, env, self.source_code)

        line, col = get_node_location(node)
        snippet = get_node_text(node, self.source_code).strip()

        is_dang = CTypeRange.is_unsigned_type(type_text) and val_iv.could_be_negative()

        self.conversion_facts.append(
            ConversionFact(
                from_type="signed",
                to_type=type_text,
                val_interval=val_iv,
                expr_text=snippet,
                line=line,
                column=col,
                code_snippet=snippet,
                is_dangerous_signed_to_unsigned=is_dang,
            )
        )

    def _handle_if_statement(self, node: Node, env: RangeEnvironment) -> Tuple[RangeEnvironment, bool]:
        cond_node = node.child_by_field_name("condition")
        then_node = node.child_by_field_name("consequence")
        else_node = node.child_by_field_name("alternative")

        # Refine true branch
        then_env = ConditionRefiner.refine(env, cond_node, True, self.source_code)
        then_res_env, then_exit = self._walk_statement(then_node, then_env)

        # Refine false branch
        else_env = ConditionRefiner.refine(env, cond_node, False, self.source_code)
        else_res_env, else_exit = (env, False)
        if else_node:
            else_res_env, else_exit = self._walk_statement(else_node, else_env)

        if then_exit and else_exit:
            return env, True
        elif then_exit:
            # Early return pattern: `if (i < 0 || i >= 10) return;`
            # Remaining code executes under false branch environment!
            return else_env, False
        elif else_exit:
            return then_res_env, False

        # Merge environments
        return then_res_env.join(else_res_env), False

    def _handle_for_statement(self, node: Node, env: RangeEnvironment) -> Tuple[RangeEnvironment, bool]:
        init_node = node.child_by_field_name("initializer")
        cond_node = node.child_by_field_name("condition")
        update_node = node.child_by_field_name("update")
        body_node = node.child_by_field_name("body")

        loop_env = env.copy()
        loop_var = None
        init_val = 0

        if init_node:
            self._walk_statement(init_node, loop_env)
            # Try to identify loop variable name and initial value
            decl_idents = find_nodes_by_type(init_node, ["identifier"])
            if decl_idents:
                loop_var = get_node_text(decl_idents[0], self.source_code).strip()
                init_iv = loop_env.get_var_interval(loop_var)
                if init_iv.min != -INF:
                    init_val = int(init_iv.min)

        loop_body_env = loop_env.copy()

        # Inspect loop condition to determine loop interval (e.g. i < 10 or i <= 10)
        if cond_node and loop_var:
            cond_text = get_node_text(cond_node, self.source_code).strip()
            if cond_node.type == "binary_expression":
                left = cond_node.child_by_field_name("left")
                right = cond_node.child_by_field_name("right")
                op_node = cond_node.child_by_field_name("operator")
                op = get_node_text(op_node, self.source_code).strip() if op_node else ""

                left_text = get_node_text(left, self.source_code).strip() if left else ""
                right_iv = ExpressionEvaluator.evaluate(right, loop_env, self.source_code) if right else Interval.top()

                if left_text == loop_var and right_iv.is_constant and right_iv.constant_value is not None:
                    bound_c = right_iv.constant_value
                    if op == "<":
                        loop_body_env.set_var_interval(loop_var, Interval(init_val, bound_c - 1))
                    elif op == "<=":
                        loop_body_env.set_var_interval(loop_var, Interval(init_val, bound_c))
                    elif op == ">":
                        loop_body_env.set_var_interval(loop_var, Interval(bound_c + 1, init_val))
                    elif op == ">=":
                        loop_body_env.set_var_interval(loop_var, Interval(bound_c, init_val))
                else:
                    loop_body_env = ConditionRefiner.refine(loop_env, cond_node, True, self.source_code)
            else:
                loop_body_env = ConditionRefiner.refine(loop_env, cond_node, True, self.source_code)
        elif cond_node:
            loop_body_env = ConditionRefiner.refine(loop_env, cond_node, True, self.source_code)

        self._walk_statement(body_node, loop_body_env)

        # After loop: refine with false condition
        after_env = ConditionRefiner.refine(loop_env, cond_node, False, self.source_code) if cond_node else loop_env
        return after_env, False

    def _handle_while_statement(self, node: Node, env: RangeEnvironment) -> Tuple[RangeEnvironment, bool]:
        cond_node = node.child_by_field_name("condition")
        body_node = node.child_by_field_name("body")

        loop_env = ConditionRefiner.refine(env, cond_node, True, self.source_code)
        self._walk_statement(body_node, loop_env)

        after_env = ConditionRefiner.refine(env, cond_node, False, self.source_code)
        return after_env, False
