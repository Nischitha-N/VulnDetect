"""
Range Environment, Expression Evaluator, and Condition Refiner.
Evaluates Tree-sitter AST nodes to abstract intervals and refines variables
based on path conditions (comparisons, logical operators, pointer nullness).
"""

import re
from typing import Dict, Any, Optional, Tuple, List, Union
from tree_sitter import Node

from app.engine.range.interval import (
    Interval, CTypeRange, INF,
    INT32_MIN, INT32_MAX, UINT32_MAX, INT64_MIN, INT64_MAX, UINT64_MAX
)
from app.engine.parser import get_node_text, find_nodes_by_type


class RangeEnvironment:
    """
    Tracks state of variables, arrays, dynamically allocated buffers,
    and type declarations in an execution scope.
    """

    def __init__(self):
        # var_name -> Interval
        self.variables: Dict[str, Interval] = {}
        # var_name -> type_string (e.g. "int", "unsigned int", "size_t")
        self.types: Dict[str, str] = {}
        # array_name -> {"element_count": int, "element_size": int, "total_bytes": int}
        self.arrays: Dict[str, Dict[str, Any]] = {}
        # ptr_name -> Interval (allocated buffer size in bytes)
        self.buffers: Dict[str, Interval] = {}
        # const_name -> int (e.g., #define MAX_LEN 1024)
        self.constants: Dict[str, int] = {}
        # Pointers with known offset: ptr_name -> Interval
        self.pointer_offsets: Dict[str, Interval] = {}

    def copy(self) -> "RangeEnvironment":
        clone = RangeEnvironment()
        clone.variables = {k: Interval(v.min, v.max) for k, v in self.variables.items()}
        clone.types = dict(self.types)
        clone.arrays = {k: dict(v) for k, v in self.arrays.items()}
        clone.buffers = {k: Interval(v.min, v.max) for k, v in self.buffers.items()}
        clone.constants = dict(self.constants)
        clone.pointer_offsets = {k: Interval(v.min, v.max) for k, v in self.pointer_offsets.items()}
        return clone

    def join(self, other: "RangeEnvironment") -> "RangeEnvironment":
        """
        Merge two environments at a control-flow join point (union intervals).
        """
        joined = RangeEnvironment()
        joined.types = {**self.types, **other.types}
        joined.arrays = {**self.arrays, **other.arrays}
        joined.constants = {**self.constants, **other.constants}

        all_vars = set(self.variables.keys()) | set(other.variables.keys())
        for var in all_vars:
            iv1 = self.variables.get(var)
            iv2 = other.variables.get(var)
            if iv1 is not None and iv2 is not None:
                joined.variables[var] = iv1.union(iv2)
            elif iv1 is not None:
                # Variable was only in branch 1 (or unassigned in branch 2)
                type_str = self.types.get(var, "int")
                default_iv = CTypeRange.get_type_interval(type_str)
                joined.variables[var] = iv1.union(default_iv)
            elif iv2 is not None:
                type_str = other.types.get(var, "int")
                default_iv = CTypeRange.get_type_interval(type_str)
                joined.variables[var] = iv2.union(default_iv)

        all_bufs = set(self.buffers.keys()) | set(other.buffers.keys())
        for buf in all_bufs:
            b1 = self.buffers.get(buf)
            b2 = other.buffers.get(buf)
            if b1 and b2:
                joined.buffers[buf] = b1.union(b2)
            elif b1:
                joined.buffers[buf] = b1
            elif b2:
                joined.buffers[buf] = b2

        return joined

    def get_var_interval(self, var_name: str) -> Interval:
        if var_name in self.variables:
            return self.variables[var_name]
        if var_name in self.constants:
            return Interval.exact(self.constants[var_name])
        if var_name in self.types:
            return CTypeRange.get_type_interval(self.types[var_name])
        return Interval.top()

    def set_var_interval(self, var_name: str, interval: Interval):
        self.variables[var_name] = interval

    def refine_var_interval(self, var_name: str, interval: Interval):
        current = self.get_var_interval(var_name)
        self.variables[var_name] = current.intersect(interval)


class ExpressionEvaluator:
    """
    Evaluates Tree-sitter AST expression nodes into abstract Intervals.
    """

    @staticmethod
    def parse_int_literal(text: str) -> Optional[int]:
        """Parse C integer literals like 42, 0x2A, 0b1010, 1000UL, etc."""
        cleaned = re.sub(r'[uUlLzZ]+$', '', text.strip())
        try:
            if cleaned.startswith(('0x', '0X')):
                return int(cleaned, 16)
            elif cleaned.startswith(('0b', '0B')):
                return int(cleaned, 2)
            elif cleaned.startswith('0') and len(cleaned) > 1 and cleaned.isdigit():
                return int(cleaned, 8)
            else:
                return int(cleaned)
        except ValueError:
            return None

    @staticmethod
    def evaluate(node: Optional[Node], env: RangeEnvironment, source_code: str) -> Interval:
        """
        Evaluate any expression AST node to an Interval under the given environment.
        """
        if node is None:
            return Interval.top()

        ntype = node.type

        # 1. Numeric Literals
        if ntype == "number_literal":
            txt = get_node_text(node, source_code)
            val = ExpressionEvaluator.parse_int_literal(txt)
            if val is not None:
                return Interval.exact(val)
            return Interval.top()

        # 2. Character Literals ('\0', 'A', etc.)
        elif ntype == "char_literal":
            txt = get_node_text(node, source_code).strip("'")
            if txt == "\\0":
                return Interval.exact(0)
            elif txt == "\\n":
                return Interval.exact(10)
            elif txt == "\\t":
                return Interval.exact(9)
            elif len(txt) == 1:
                return Interval.exact(ord(txt))
            return Interval(0, 255)

        # 3. String Literal -> returns its length
        elif ntype == "string_literal":
            txt = get_node_text(node, source_code)
            if txt.startswith('"') and txt.endswith('"'):
                # subtract 2 for quotes
                return Interval.exact(max(0, len(txt) - 2))
            return Interval(0, INF)

        # 4. Identifier (variable or macro/constant)
        elif ntype == "identifier":
            var_name = get_node_text(node, source_code).strip()
            if var_name == "NULL":
                return Interval.exact(0)
            if var_name in ("true", "TRUE"):
                return Interval.exact(1)
            if var_name in ("false", "FALSE"):
                return Interval.exact(0)
            return env.get_var_interval(var_name)

        # 5. Parenthesized Expressions ( (x + 1) )
        elif ntype == "parenthesized_expression":
            for child in node.named_children:
                return ExpressionEvaluator.evaluate(child, env, source_code)
            return Interval.top()

        # 6. Unary Expressions (-x, +x, !x, ~x, sizeof(x))
        elif ntype == "unary_expression":
            op_node = node.child_by_field_name("operator")
            arg_node = node.child_by_field_name("argument")
            op_txt = get_node_text(op_node, source_code).strip() if op_node else ""
            if not op_txt:
                # Sometimes operator is first child
                for c in node.children:
                    if c.type in ("-", "+", "!", "~", "sizeof"):
                        op_txt = c.type
                        break

            arg_iv = ExpressionEvaluator.evaluate(arg_node, env, source_code) if arg_node else Interval.top()

            if op_txt == "-":
                return arg_iv.neg()
            elif op_txt == "+":
                return arg_iv
            elif op_txt == "!":
                if arg_iv.is_constant and arg_iv.constant_value == 0:
                    return Interval.exact(1)
                elif arg_iv.is_definitely_positive() or arg_iv.is_definitely_negative():
                    return Interval.exact(0)
                return Interval(0, 1)
            elif op_txt == "~":
                if arg_iv.is_constant:
                    return Interval.exact(~arg_iv.constant_value)
                return Interval.top()
            elif op_txt == "sizeof":
                arg_text = get_node_text(arg_node, source_code).strip() if arg_node else ""
                # Check if array
                if arg_text in env.arrays:
                    return Interval.exact(env.arrays[arg_text]["total_bytes"])
                return Interval.exact(CTypeRange.get_sizeof(arg_text))

        # 7. Sizeof Expression
        elif ntype == "sizeof_expression":
            type_node = node.child_by_field_name("type")
            value_node = node.child_by_field_name("value")
            target_node = type_node or value_node or (node.named_children[0] if node.named_children else None)
            if target_node:
                target_text = get_node_text(target_node, source_code).strip("()")
                if target_text in env.arrays:
                    return Interval.exact(env.arrays[target_text]["total_bytes"])
                return Interval.exact(CTypeRange.get_sizeof(target_text))
            return Interval.exact(4)

        # 8. Binary Expressions (a + b, a * b, a << b, etc.)
        elif ntype == "binary_expression":
            left_node = node.child_by_field_name("left")
            right_node = node.child_by_field_name("right")
            op_node = node.child_by_field_name("operator")

            if not op_node:
                for c in node.children:
                    if not c.is_named:
                        op_node = c
                        break

            op_txt = get_node_text(op_node, source_code).strip() if op_node else ""
            left_iv = ExpressionEvaluator.evaluate(left_node, env, source_code)
            right_iv = ExpressionEvaluator.evaluate(right_node, env, source_code)

            if op_txt == "+":
                return left_iv.add(right_iv)
            elif op_txt == "-":
                return left_iv.sub(right_iv)
            elif op_txt == "*":
                return left_iv.mul(right_iv)
            elif op_txt == "/":
                return left_iv.div(right_iv)
            elif op_txt == "%":
                return left_iv.mod(right_iv)
            elif op_txt == "<<":
                if right_iv.is_constant and 0 <= right_iv.constant_value <= 62:
                    multiplier = 1 << right_iv.constant_value
                    return left_iv.mul(Interval.exact(multiplier))
                return Interval.top()
            elif op_txt == ">>":
                if right_iv.is_constant and 0 <= right_iv.constant_value <= 62:
                    divisor = 1 << right_iv.constant_value
                    return left_iv.div(Interval.exact(divisor))
                return Interval.top()
            elif op_txt in ("<", "<=", ">", ">=", "==", "!="):
                # Relational comparison evaluates to boolean [0, 1]
                return Interval(0, 1)

        # 9. Type Cast Expressions ( (int)x, (size_t)len )
        elif ntype == "cast_expression":
            type_node = node.child_by_field_name("type")
            val_node = node.child_by_field_name("value")
            type_text = get_node_text(type_node, source_code).strip() if type_node else "int"
            val_iv = ExpressionEvaluator.evaluate(val_node, env, source_code)
            type_iv = CTypeRange.get_type_interval(type_text)
            # Clip or wrap value to type limits
            if CTypeRange.is_unsigned_type(type_text) and val_iv.could_be_negative():
                # Signed to unsigned conversion of negative number!
                if val_iv.is_constant and val_iv.constant_value < 0:
                    converted = UINT32_MAX + val_iv.constant_value + 1
                    return Interval.exact(converted)
                return Interval(0, UINT64_MAX)
            return val_iv.intersect(type_iv)

        # 10. Call Expressions (strlen(s), sizeof, etc.)
        elif ntype == "call_expression":
            fn_node = node.child_by_field_name("function")
            fn_name = get_node_text(fn_node, source_code).strip() if fn_node else ""
            args_node = node.child_by_field_name("arguments")
            args = args_node.named_children if args_node else []

            if fn_name == "strlen" and args:
                arg_text = get_node_text(args[0], source_code).strip()
                if arg_text.startswith('"') and arg_text.endswith('"'):
                    return Interval.exact(max(0, len(arg_text) - 2))
                return Interval(0, INT32_MAX)
            elif fn_name == "sizeof" and args:
                arg_text = get_node_text(args[0], source_code).strip()
                if arg_text in env.arrays:
                    return Interval.exact(env.arrays[arg_text]["total_bytes"])
                return Interval.exact(CTypeRange.get_sizeof(arg_text))
            elif fn_name in ("abs", "labs") and args:
                arg_iv = ExpressionEvaluator.evaluate(args[0], env, source_code)
                if arg_iv.is_bottom:
                    return Interval.bottom()
                return Interval(0, max(abs(arg_iv.min) if arg_iv.min != -INF else INF, abs(arg_iv.max) if arg_iv.max != INF else INF))

        # Default fallback
        return Interval.top()


class ConditionRefiner:
    """
    Refines variable intervals in a RangeEnvironment based on branch condition nodes.
    e.g. `if (i >= 0 && i < 10)` -> refines `i` to [0, 9] in the True branch.
    """

    @staticmethod
    def refine(env: RangeEnvironment, condition_node: Optional[Node], is_true_branch: bool, source_code: str) -> RangeEnvironment:
        if condition_node is None:
            return env.copy()

        new_env = env.copy()
        ntype = condition_node.type

        # 1. Logical AND (a && b)
        if ntype == "binary_expression":
            op_node = condition_node.child_by_field_name("operator")
            op_txt = get_node_text(op_node, source_code).strip() if op_node else ""
            if not op_txt:
                for c in condition_node.children:
                    if c.type in ("&&", "||", "<", "<=", ">", ">=", "==", "!="):
                        op_txt = c.type
                        break

            if op_txt == "&&":
                left = condition_node.child_by_field_name("left")
                right = condition_node.child_by_field_name("right")
                if is_true_branch:
                    # Both must be true
                    env_left = ConditionRefiner.refine(new_env, left, True, source_code)
                    return ConditionRefiner.refine(env_left, right, True, source_code)
                else:
                    # !(A && B) => !A || !B
                    env_not_a = ConditionRefiner.refine(new_env, left, False, source_code)
                    env_not_b = ConditionRefiner.refine(new_env, right, False, source_code)
                    return env_not_a.join(env_not_b)

            elif op_txt == "||":
                left = condition_node.child_by_field_name("left")
                right = condition_node.child_by_field_name("right")
                if is_true_branch:
                    # A || B is true
                    env_a = ConditionRefiner.refine(new_env, left, True, source_code)
                    env_b = ConditionRefiner.refine(new_env, right, True, source_code)
                    return env_a.join(env_b)
                else:
                    # !(A || B) => !A && !B
                    env_not_a = ConditionRefiner.refine(new_env, left, False, source_code)
                    return ConditionRefiner.refine(env_not_a, right, False, source_code)

            elif op_txt in ("<", "<=", ">", ">=", "==", "!="):
                return ConditionRefiner._refine_comparison(new_env, condition_node, op_txt, is_true_branch, source_code)

        # 2. Parenthesized Expression ( (cond) )
        elif ntype == "parenthesized_expression":
            for child in condition_node.named_children:
                return ConditionRefiner.refine(new_env, child, is_true_branch, source_code)

        # 3. Negation ( !cond )
        elif ntype == "unary_expression":
            op_txt = get_node_text(condition_node.child_by_field_name("operator"), source_code).strip()
            if op_txt == "!":
                arg = condition_node.child_by_field_name("argument")
                return ConditionRefiner.refine(new_env, arg, not is_true_branch, source_code)

        # 4. Bare variable check: if (x)
        elif ntype == "identifier":
            var_name = get_node_text(condition_node, source_code).strip()
            if is_true_branch:
                # x != 0
                curr = new_env.get_var_interval(var_name)
                if curr.is_definitely_non_negative():
                    new_env.refine_var_interval(var_name, Interval(1, INF))
            else:
                # x == 0
                new_env.set_var_interval(var_name, Interval.exact(0))

        return new_env

    @staticmethod
    def _refine_comparison(env: RangeEnvironment, node: Node, op: str, is_true_branch: bool, source_code: str) -> RangeEnvironment:
        left_node = node.child_by_field_name("left")
        right_node = node.child_by_field_name("right")
        if not left_node or not right_node:
            return env

        # Effective operator if inverted
        effective_op = op
        if not is_true_branch:
            inversion_map = {
                "<": ">=",
                "<=": ">",
                ">": "<=",
                ">=": "<",
                "==": "!=",
                "!=": "==",
            }
            effective_op = inversion_map.get(op, op)

        left_text = get_node_text(left_node, source_code).strip()
        right_text = get_node_text(right_node, source_code).strip()

        left_is_ident = (left_node.type == "identifier")
        right_is_ident = (right_node.type == "identifier")

        left_iv = ExpressionEvaluator.evaluate(left_node, env, source_code)
        right_iv = ExpressionEvaluator.evaluate(right_node, env, source_code)

        # Case 1: left is variable, right is expression (e.g. i < 10, i >= 0)
        if left_is_ident and left_text:
            var = left_text
            if effective_op == "<":
                if right_iv.max != INF:
                    env.refine_var_interval(var, Interval(-INF, right_iv.max - 1))
            elif effective_op == "<=":
                if right_iv.max != INF:
                    env.refine_var_interval(var, Interval(-INF, right_iv.max))
            elif effective_op == ">":
                if right_iv.min != -INF:
                    env.refine_var_interval(var, Interval(right_iv.min + 1, INF))
            elif effective_op == ">=":
                if right_iv.min != -INF:
                    env.refine_var_interval(var, Interval(right_iv.min, INF))
            elif effective_op == "==":
                env.refine_var_interval(var, right_iv)

        # Case 2: right is variable, left is expression (e.g. 10 > i, 0 <= i)
        if right_is_ident and right_text:
            var = right_text
            if effective_op == "<": # left < right => right > left
                if left_iv.min != -INF:
                    env.refine_var_interval(var, Interval(left_iv.min + 1, INF))
            elif effective_op == "<=": # left <= right => right >= left
                if left_iv.min != -INF:
                    env.refine_var_interval(var, Interval(left_iv.min, INF))
            elif effective_op == ">": # left > right => right < left
                if left_iv.max != INF:
                    env.refine_var_interval(var, Interval(-INF, left_iv.max - 1))
            elif effective_op == ">=": # left >= right => right <= left
                if left_iv.max != INF:
                    env.refine_var_interval(var, Interval(-INF, left_iv.max))
            elif effective_op == "==":
                env.refine_var_interval(var, left_iv)

        return env
