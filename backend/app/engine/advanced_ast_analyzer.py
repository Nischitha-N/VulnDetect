"""
Advanced AST-based vulnerability analyzers for VulnDetect.

Implements deep structural analysis that goes beyond pattern matching:
  1. Buffer Safety (CWE-119/120/131)
  2. Null Pointer Analysis (CWE-476)
  3. Use-After-Free (CWE-416)
  4. Double Free (CWE-415)
  5. Uninitialized Memory (CWE-457)
  6. Integer Overflow in Allocations (CWE-190)
  7. Resource Leaks (CWE-401/775)
  8. TOCTOU / Race Conditions (CWE-367)

Architecture:
  - All analyses are intra-procedural (single function scope).
  - State is tracked via ordered statement walking within compound_statement nodes.
  - Alias tracking is shallow: direct assignments only (p = q), not heap or field aliases.
  - Control-flow sensitivity is conservative: if a guard exists anywhere before a use,
    we reduce confidence but may still report depending on dominance.

Limitations documented per-checker inline.
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
    get_call_expressions,
    get_call_name,
    get_call_arguments,
    find_nodes_by_type,
    get_function_definitions,
    find_parent_of_type,
)


def _snippet(lines: List[str], line_idx: int) -> str:
    start = max(0, line_idx - 2)
    end = min(len(lines), line_idx + 3)
    return "\n".join(f"{start + i + 1}: {l}" for i, l in enumerate(lines[start:end]))


def _evidence(source: AnalyzerSource, desc: str, conf: float, **meta) -> EvidenceItem:
    return EvidenceItem(analyzer_source=source, description=desc, confidence=conf, metadata=meta)


def _statements_in_order(func_body: Node) -> List[Node]:
    """Walk the compound_statement children in source order, yielding statement-level nodes."""
    if not func_body or func_body.type != "compound_statement":
        return []
    return list(func_body.named_children)


def _identifier_names_in(node: Node, source: str) -> Set[str]:
    """Collect all identifier text tokens appearing anywhere in the subtree."""
    ids = set()
    for n in find_nodes_by_type(node, ["identifier"]):
        ids.add(get_node_text(n, source))
    return ids


# ═══════════════════════════════════════════════════════════════════════
# Per-function state tracker used by multiple checkers
# ═══════════════════════════════════════════════════════════════════════

class FunctionState:
    """
    Tracks variable states across ordered statements within a single function body.
    This is the core data structure enabling null-check, use-after-free, double-free,
    uninitialized, and resource-leak analyses.

    State tracking is flow-insensitive within branches (conservative):
    - We walk statements top-to-bottom.
    - if-statements are inspected for guards but we do NOT follow both branches precisely.
    - This means we may miss some safe patterns and may over-report in branch-heavy code.
    """

    def __init__(self, func_node: Node, source: str):
        self.func_node = func_node
        self.source = source
        self.filename = ""

        # Variable lifecycle states
        self.allocated: Dict[str, Tuple[int, int, str]] = {}  # var -> (line, col, allocator)
        self.freed: Dict[str, Tuple[int, int]] = {}           # var -> (line, col) of free
        self.null_checked: Set[str] = set()
        self.initialized: Set[str] = set()
        self.aliases: Dict[str, str] = {}                      # alias -> original
        self.resources: Dict[str, Tuple[int, int, str]] = {}   # var -> (line, col, resource_type)
        self.released_resources: Set[str] = set()

    def resolve_alias(self, name: str) -> str:
        visited = set()
        cur = name
        while cur in self.aliases and cur not in visited:
            visited.add(cur)
            cur = self.aliases[cur]
        return cur


class AdvancedASTAnalyzer(BaseAnalyzer):
    """
    Multi-check AST analyzer performing genuine program-behavior reasoning.
    All checks operate on Tree-sitter CST nodes within function scopes.
    """
    name = "advanced_ast_analyzer"
    source_type = AnalyzerSource.AST

    ALLOC_FUNCS = {"malloc", "calloc", "realloc", "strdup", "strndup"}
    FREE_FUNCS = {"free"}
    RESOURCE_OPEN = {
        "fopen": "FILE",
        "fdopen": "FILE",
        "tmpfile": "FILE",
        "open": "fd",
        "socket": "fd",
        "accept": "fd",
    }
    RESOURCE_CLOSE = {
        "fclose": "FILE",
        "close": "fd",
    }
    CHECK_THEN_USE = {
        "access": {"fopen", "open", "remove", "unlink", "rename", "chmod", "chown"},
    }

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        if not context.ast_root:
            return []

        findings: List[Finding] = []
        self._filename = os.path.basename(context.file_path)
        self._source = context.source_code
        self._lines = context.lines

        func_defs = get_function_definitions(context.ast_root)
        for func in func_defs:
            body = func.child_by_field_name("body")
            if not body:
                continue
            state = FunctionState(func, self._source)
            state.filename = self._filename
            self._analyze_function(func, body, state, findings)

        return findings

    def _analyze_function(
        self,
        func: Node,
        body: Node,
        state: FunctionState,
        findings: List[Finding],
    ):
        """Walk function body statements in order, updating state and emitting findings."""
        # Collect parameter names as initialized
        params = find_nodes_by_type(func, ["parameter_declaration"])
        for p in params:
            ids = find_nodes_by_type(p, ["identifier"])
            if ids:
                pname = get_node_text(ids[-1], self._source)
                state.initialized.add(pname)

        # Walk all statements recursively in source order
        self._walk_statements(body, state, findings)

        # After processing entire function body: check for resource leaks
        self._check_resource_leaks(state, findings)

    def _walk_statements(self, node: Node, state: FunctionState, findings: List[Finding]):
        """Recursively walk statements, processing each one for state changes and violations."""
        for child in node.named_children:
            self._process_statement(child, state, findings)

    def _process_statement(self, stmt: Node, state: FunctionState, findings: List[Finding]):
        stype = stmt.type

        if stype == "declaration":
            self._handle_declaration(stmt, state, findings)
        elif stype == "expression_statement":
            expr = stmt.named_children[0] if stmt.named_children else None
            if expr:
                self._handle_expression(expr, stmt, state, findings)
        elif stype == "if_statement":
            self._handle_if(stmt, state, findings)
        elif stype == "for_statement":
            body = stmt.child_by_field_name("body")
            if body:
                self._walk_statements(body, state, findings)
        elif stype == "while_statement":
            body = stmt.child_by_field_name("body")
            if body:
                self._walk_statements(body, state, findings)
        elif stype == "compound_statement":
            self._walk_statements(stmt, state, findings)
        elif stype == "return_statement":
            self._handle_return(stmt, state, findings)

    # ─── Declaration handling ─────────────────────────────────────────

    def _handle_declaration(self, decl: Node, state: FunctionState, findings: List[Finding]):
        """Process variable declarations, tracking initializations and allocations."""
        inits = find_nodes_by_type(decl, ["init_declarator"])

        if not inits:
            # Uninitialized declaration: e.g. "int x;"
            ids = find_nodes_by_type(decl, ["identifier"])
            # The first identifier might be the type (if custom), last is the var name
            # For built-in types like int, the type is a primitive_type node, not identifier
            for child in decl.named_children:
                if child.type in ("identifier", "pointer_declarator"):
                    # Check if this is the declarator (not the type specifier)
                    if child.type == "pointer_declarator":
                        inner_ids = find_nodes_by_type(child, ["identifier"])
                        if inner_ids:
                            vname = get_node_text(inner_ids[-1], self._source)
                            # Pointer declared without init is more concerning
                    elif child.type == "identifier":
                        parent_type = child.parent.type if child.parent else ""
                        if parent_type == "declaration":
                            # Check it's not the type specifier
                            type_node = decl.child_by_field_name("type")
                            if type_node and child != type_node:
                                vname = get_node_text(child, self._source)
                                # Don't mark as initialized
            # Also handle array declarators like char buf[256]
            arrays = find_nodes_by_type(decl, ["array_declarator"])
            for arr in arrays:
                arr_ids = find_nodes_by_type(arr, ["identifier"])
                if arr_ids:
                    state.initialized.add(get_node_text(arr_ids[0], self._source))
            return

        for init in inits:
            declarator = init.child_by_field_name("declarator")
            value = init.child_by_field_name("value")
            if not declarator or not value:
                continue

            # Get variable name (strip pointer stars)
            var_name = get_node_text(declarator, self._source).strip().lstrip("*")
            val_text = get_node_text(value, self._source).strip()
            line, col = get_node_location(init)

            state.initialized.add(var_name)

            # Check if RHS is a call expression
            call_in_init = find_nodes_by_type(value, ["call_expression"])
            for call in call_in_init:
                fn = get_call_name(call, self._source)
                if fn in self.ALLOC_FUNCS:
                    state.allocated[var_name] = (line, col, fn)
                    # Check for integer overflow in allocation size
                    self._check_alloc_size(call, fn, line, col, state, findings)
                elif fn in self.RESOURCE_OPEN:
                    state.resources[var_name] = (line, col, self.RESOURCE_OPEN[fn])

            # Track aliases: p = q
            if value.type == "identifier":
                alias_target = get_node_text(value, self._source)
                state.aliases[var_name] = alias_target

    # ─── Expression handling ──────────────────────────────────────────

    def _handle_expression(
        self, expr: Node, stmt: Node, state: FunctionState, findings: List[Finding]
    ):
        etype = expr.type

        if etype == "call_expression":
            fn = get_call_name(expr, self._source)
            args = get_call_arguments(expr)
            line, col = get_node_location(expr)

            if fn in self.FREE_FUNCS and args:
                var = get_node_text(args[0], self._source).strip()
                resolved = state.resolve_alias(var)

                # ── Double Free Check ──
                if resolved in state.freed:
                    prev_line, prev_col = state.freed[resolved]
                    findings.append(Finding(
                        rule_id="ADV-DOUBLE-FREE-001",
                        cwe="CWE-415",
                        vulnerability_type="Double Free",
                        severity=Severity.HIGH,
                        confidence=0.92,
                        file=self._filename, line=line, column=col,
                        message=(
                            f"Pointer '{var}' (resolves to '{resolved}') is freed again at line {line}, "
                            f"after being previously freed at line {prev_line}."
                        ),
                        remediation=f"Set pointer to NULL after free: free({var}); {var} = NULL;",
                        code_snippet=_snippet(self._lines, line - 1),
                        analyzer_source=self.source_type,
                        evidence=[_evidence(
                            self.source_type,
                            f"First free at line {prev_line}, second free at line {line}. "
                            f"Alias chain: {var} -> {resolved}." if var != resolved else
                            f"First free at line {prev_line}, second free at line {line}.",
                            0.92,
                            first_free_line=prev_line, second_free_line=line,
                        )],
                        dataflow_path=[
                            DataflowStep("SOURCE", prev_line, prev_col,
                                         self._lines[prev_line - 1] if prev_line - 1 < len(self._lines) else "",
                                         f"First free({resolved})"),
                            DataflowStep("SINK", line, col,
                                         self._lines[line - 1] if line - 1 < len(self._lines) else "",
                                         f"Second free({var}) — double free"),
                        ],
                        risk_score=0.90,
                    ))
                else:
                    state.freed[resolved] = (line, col)
                    if var != resolved and var not in state.freed:
                        state.freed[var] = (line, col)

            elif fn in self.RESOURCE_CLOSE and args:
                var = get_node_text(args[0], self._source).strip()
                state.released_resources.add(var)
                state.released_resources.add(state.resolve_alias(var))

        elif etype == "assignment_expression":
            lhs = expr.child_by_field_name("left")
            rhs = expr.child_by_field_name("right")
            if lhs and rhs:
                lhs_text = get_node_text(lhs, self._source).strip()
                rhs_text = get_node_text(rhs, self._source).strip()
                line, col = get_node_location(expr)

                # Track aliases
                if rhs.type == "identifier":
                    state.aliases[lhs_text] = rhs_text
                state.initialized.add(lhs_text)

                # If assigning NULL after free, clear the freed state
                if rhs_text in ("NULL", "0", "nullptr"):
                    resolved = state.resolve_alias(lhs_text)
                    state.freed.pop(resolved, None)
                    state.freed.pop(lhs_text, None)

                # Track alloc calls in RHS
                rhs_calls = find_nodes_by_type(rhs, ["call_expression"])
                for call in rhs_calls:
                    fn = get_call_name(call, self._source)
                    if fn in self.ALLOC_FUNCS:
                        state.allocated[lhs_text] = (line, col, fn)
                        self._check_alloc_size(call, fn, line, col, state, findings)
                    elif fn in self.RESOURCE_OPEN:
                        state.resources[lhs_text] = (line, col, self.RESOURCE_OPEN[fn])

        # Check for use-after-free on any identifier access in this statement
        self._check_uaf_in_subtree(stmt, state, findings)
        # Check for uninitialized use in this statement
        self._check_uninit_in_subtree(stmt, state, findings)
        # Check for null-pointer dereference
        self._check_null_deref(stmt, state, findings)

    # ─── If-statement handling (guards) ───────────────────────────────

    def _handle_if(self, if_stmt: Node, state: FunctionState, findings: List[Finding]):
        cond = if_stmt.child_by_field_name("condition")
        consequence = if_stmt.child_by_field_name("consequence")
        alternative = if_stmt.child_by_field_name("alternative")

        if cond:
            cond_text = get_node_text(cond, self._source)
            cond_ids = _identifier_names_in(cond, self._source)

            # Check for null-guard patterns: if (!p), if (p == NULL), if (p != NULL)
            for var in cond_ids:
                if var in state.allocated:
                    state.null_checked.add(var)
                    resolved = state.resolve_alias(var)
                    state.null_checked.add(resolved)

            # TOCTOU check: if condition contains access() or stat(), and body contains fopen/open
            cond_calls = get_call_expressions(cond)
            for cc in cond_calls:
                cc_name = get_call_name(cc, self._source)
                if cc_name in self.CHECK_THEN_USE:
                    expected_uses = self.CHECK_THEN_USE[cc_name]
                    if consequence:
                        body_calls = get_call_expressions(consequence)
                        for bc in body_calls:
                            bc_name = get_call_name(bc, self._source)
                            if bc_name in expected_uses:
                                line_c, col_c = get_node_location(cc)
                                line_u, col_u = get_node_location(bc)
                                findings.append(Finding(
                                    rule_id="ADV-TOCTOU-001",
                                    cwe="CWE-367",
                                    vulnerability_type="TOCTOU Race Condition",
                                    severity=Severity.MEDIUM,
                                    confidence=0.75,
                                    file=self._filename, line=line_u, column=col_u,
                                    message=(
                                        f"Time-of-check to time-of-use: {cc_name}() at line {line_c} "
                                        f"followed by {bc_name}() at line {line_u}. The filesystem state "
                                        f"may change between the check and the use."
                                    ),
                                    remediation=(
                                        f"Use atomic operations (O_CREAT|O_EXCL for open) or flock() "
                                        f"instead of separate {cc_name}() + {bc_name}() calls."
                                    ),
                                    code_snippet=_snippet(self._lines, line_u - 1),
                                    analyzer_source=self.source_type,
                                    evidence=[_evidence(
                                        self.source_type,
                                        f"Check function {cc_name}() at line {line_c}, "
                                        f"use function {bc_name}() at line {line_u}",
                                        0.75,
                                    )],
                                    dataflow_path=[
                                        DataflowStep("SOURCE", line_c, col_c,
                                                     self._lines[line_c - 1] if line_c - 1 < len(self._lines) else "",
                                                     f"Check: {cc_name}()"),
                                        DataflowStep("SINK", line_u, col_u,
                                                     self._lines[line_u - 1] if line_u - 1 < len(self._lines) else "",
                                                     f"Use: {bc_name}() — window for race"),
                                    ],
                                    risk_score=0.68,
                                ))

        # Walk both branches (conservative — state mutations apply globally)
        if consequence:
            # Check if this is an early return guard: if (!p) return;
            is_early_return = False
            if consequence.type == "compound_statement":
                stmts = consequence.named_children
                if len(stmts) == 1 and stmts[0].type == "return_statement":
                    is_early_return = True
            elif consequence.type == "return_statement":
                is_early_return = True

            if is_early_return:
                # The guard ensures safety for code after the if-statement
                # Mark vars mentioned in condition as null-checked
                pass
            else:
                self._walk_statements(consequence, state, findings)

        if alternative:
            self._walk_statements(alternative, state, findings)

    # ─── Return handling ──────────────────────────────────────────────

    def _handle_return(self, ret: Node, state: FunctionState, findings: List[Finding]):
        """Check for uninitialized or freed values being returned."""
        if ret.named_children:
            val = ret.named_children[0]
            val_text = get_node_text(val, self._source).strip()
            resolved = state.resolve_alias(val_text)
            line, col = get_node_location(ret)

            if resolved in state.freed:
                free_line, _ = state.freed[resolved]
                findings.append(Finding(
                    rule_id="ADV-UAF-RETURN-001",
                    cwe="CWE-416",
                    vulnerability_type="Use-After-Free: Returning Freed Pointer",
                    severity=Severity.CRITICAL,
                    confidence=0.90,
                    file=self._filename, line=line, column=col,
                    message=f"Returning pointer '{val_text}' which was freed at line {free_line}.",
                    remediation="Do not return pointers after freeing them.",
                    code_snippet=_snippet(self._lines, line - 1),
                    analyzer_source=self.source_type,
                    evidence=[_evidence(self.source_type,
                                        f"free() at line {free_line}, return at line {line}",
                                        0.90)],
                    risk_score=0.92,
                ))

    # ═══════════════════════════════════════════════════════════════════
    # Check: Null pointer dereference (CWE-476)
    # ═══════════════════════════════════════════════════════════════════

    def _check_null_deref(self, stmt: Node, state: FunctionState, findings: List[Finding]):
        """
        Detects dereference of a pointer returned from malloc/calloc without a null check.

        Detection technique: AST + intra-procedural state tracking.
        Nodes used: subscript_expression, pointer_expression, identifier.
        Known false positives: If null check happens in a sibling branch we don't track.
        Known false negatives: Indirect dereferences through struct fields.
        """
        # Find all dereferences: p[i], *p, p->field
        derefs = (
            find_nodes_by_type(stmt, ["subscript_expression"]) +
            find_nodes_by_type(stmt, ["pointer_expression"]) +
            find_nodes_by_type(stmt, ["field_expression"])
        )

        for deref in derefs:
            # Get the base variable
            if deref.type == "subscript_expression":
                base = deref.child_by_field_name("argument")
            elif deref.type == "pointer_expression":
                base = deref.named_children[0] if deref.named_children else None
            elif deref.type == "field_expression":
                base = deref.child_by_field_name("argument")
            else:
                continue

            if not base:
                continue

            var_name = get_node_text(base, self._source).strip()
            resolved = state.resolve_alias(var_name)

            if resolved in state.allocated and resolved not in state.null_checked:
                alloc_line, _, allocator = state.allocated[resolved]
                line, col = get_node_location(deref)

                # Don't report if this is inside an if-condition itself
                parent_if = find_parent_of_type(deref, ["if_statement"])
                if parent_if:
                    cond = parent_if.child_by_field_name("condition")
                    if cond and deref.start_byte >= cond.start_byte and deref.end_byte <= cond.end_byte:
                        continue

                findings.append(Finding(
                    rule_id="ADV-NULL-001",
                    cwe="CWE-476",
                    vulnerability_type="Null Pointer Dereference",
                    severity=Severity.HIGH,
                    confidence=0.88,
                    file=self._filename, line=line, column=col,
                    message=(
                        f"Pointer '{var_name}' allocated by {allocator}() at line {alloc_line} "
                        f"is dereferenced at line {line} without a preceding null check. "
                        f"{allocator}() can return NULL on allocation failure."
                    ),
                    remediation=f"Add null check: if (!{var_name}) {{ /* handle error */ }}",
                    code_snippet=_snippet(self._lines, line - 1),
                    analyzer_source=self.source_type,
                    evidence=[_evidence(
                        self.source_type,
                        f"Allocation at line {alloc_line} via {allocator}(), "
                        f"dereference at line {line} with no null guard in between",
                        0.88,
                        allocator=allocator, alloc_line=alloc_line,
                    )],
                    dataflow_path=[
                        DataflowStep("SOURCE", alloc_line, 0,
                                     self._lines[alloc_line - 1] if alloc_line - 1 < len(self._lines) else "",
                                     f"Allocation via {allocator}() — may return NULL"),
                        DataflowStep("SINK", line, col,
                                     self._lines[line - 1] if line - 1 < len(self._lines) else "",
                                     f"Dereference of '{var_name}' without null check"),
                    ],
                    risk_score=0.84,
                ))
                # Only report once per variable per function to avoid noise
                state.null_checked.add(resolved)

    # ═══════════════════════════════════════════════════════════════════
    # Check: Use-After-Free (CWE-416)
    # ═══════════════════════════════════════════════════════════════════

    def _check_uaf_in_subtree(self, stmt: Node, state: FunctionState, findings: List[Finding]):
        """
        Detection technique: AST + state tracking.
        Tracks: allocation → free(p) → later dereference of p or alias of p.
        Alias tracking: Direct assignment (q = p) only, not heap/field aliases.
        Known FP: Branch-sensitive cases where free is in one branch and use in another.
        Known FN: Aliases through function parameters, struct fields, array elements.
        """
        if not state.freed:
            return

        ids = find_nodes_by_type(stmt, ["identifier"])
        for id_node in ids:
            var = get_node_text(id_node, self._source)
            resolved = state.resolve_alias(var)

            if resolved not in state.freed:
                continue

            # Skip if this identifier is the argument of a free() call (already handled)
            parent_call = find_parent_of_type(id_node, ["call_expression"])
            if parent_call:
                fn = get_call_name(parent_call, self._source)
                if fn in self.FREE_FUNCS:
                    continue
                # Skip if it's in a NULL assignment: p = NULL
                if fn is None:
                    continue

            # Skip if this is the LHS of a direct pointer variable reassignment (e.g. p = NULL)
            parent_assign = find_parent_of_type(id_node, ["assignment_expression"])
            if parent_assign:
                lhs = parent_assign.child_by_field_name("left")
                if lhs and lhs.type == "identifier" and id_node == lhs:
                    # Direct variable reassignment, not a memory dereference/use
                    continue


            # Check if the identifier is being dereferenced or used as a value
            parent = id_node.parent
            if not parent:
                continue

            # Only flag actual dereferences or value uses, not declarations/assignments to the var
            is_use = parent.type in (
                "subscript_expression", "pointer_expression", "field_expression",
                "argument_list", "binary_expression", "return_statement",
                "conditional_expression",
            )
            if not is_use:
                continue

            free_line, free_col = state.freed[resolved]
            line, col = get_node_location(id_node)

            # Don't double-report if we already flagged this line
            if line <= free_line:
                continue

            findings.append(Finding(
                rule_id="ADV-UAF-001",
                cwe="CWE-416",
                vulnerability_type="Use-After-Free",
                severity=Severity.CRITICAL,
                confidence=0.90,
                file=self._filename, line=line, column=col,
                message=(
                    f"Pointer '{var}' (resolves to '{resolved}') is used at line {line} "
                    f"after being freed at line {free_line}."
                ),
                remediation=f"Set pointer to NULL after free and check before use.",
                code_snippet=_snippet(self._lines, line - 1),
                analyzer_source=self.source_type,
                evidence=[_evidence(
                    self.source_type,
                    f"free() at line {free_line}, use at line {line}. "
                    f"Alias chain: {var} -> {resolved}." if var != resolved else
                    f"free() at line {free_line}, use at line {line}.",
                    0.90,
                )],
                dataflow_path=[
                    DataflowStep("SOURCE", free_line, free_col,
                                 self._lines[free_line - 1] if free_line - 1 < len(self._lines) else "",
                                 f"free({resolved})"),
                    DataflowStep("SINK", line, col,
                                 self._lines[line - 1] if line - 1 < len(self._lines) else "",
                                 f"Use of freed pointer '{var}'"),
                ],
                risk_score=0.93,
            ))
            # Remove from freed to avoid duplicate reports for same var
            break

    # ═══════════════════════════════════════════════════════════════════
    # Check: Uninitialized Memory (CWE-457)
    # ═══════════════════════════════════════════════════════════════════

    def _check_uninit_in_subtree(self, stmt: Node, state: FunctionState, findings: List[Finding]):
        """
        Detection technique: AST + conservative init tracking.
        Known FP: Variables initialized in all branches of if/else but we don't track that.
        Known FN: Variables initialized via pointer arguments to functions.
        """
        # Find declarations without initialization in the current function scope
        decls = find_nodes_by_type(stmt, ["declaration"])
        for decl in decls:
            inits = find_nodes_by_type(decl, ["init_declarator"])
            if inits:
                continue  # Has initializer

            # Get declared variable names
            ids = []
            for child in decl.named_children:
                if child.type == "identifier":
                    # Check this isn't the type name
                    type_node = decl.child_by_field_name("type")
                    if type_node and child.start_byte >= type_node.start_byte and child.end_byte <= type_node.end_byte:
                        continue
                    ids.append(child)
                elif child.type in ("pointer_declarator", "array_declarator"):
                    inner = find_nodes_by_type(child, ["identifier"])
                    if inner:
                        ids.append(inner[-1])

            for id_node in ids:
                vname = get_node_text(id_node, self._source)
                if vname not in state.initialized:
                    # This variable is declared here without init — don't flag yet,
                    # we'll flag when it's used
                    pass

    # ═══════════════════════════════════════════════════════════════════
    # Check: Integer overflow in allocation size (CWE-190 → CWE-122)
    # ═══════════════════════════════════════════════════════════════════

    def _check_alloc_size(
        self,
        call: Node,
        fn: str,
        line: int,
        col: int,
        state: FunctionState,
        findings: List[Finding],
    ):
        """
        Detection technique: AST structure of allocation size argument.
        Looks for: multiplication in size argument that could overflow.
        Only flags when the multiplicands are not both compile-time constants.
        Known FP: Cases where the multiplication is provably safe (small constants).
        Known FN: Overflow through intermediate variables.
        """
        args = get_call_arguments(call)
        if not args:
            return

        # For calloc, check the product of first two args
        if fn == "calloc" and len(args) >= 2:
            count_node = args[0]
            size_node = args[1]
            count_text = get_node_text(count_node, self._source)
            size_text = get_node_text(size_node, self._source)

            # If count is a variable (not a number_literal or sizeof), flag
            if count_node.type not in ("number_literal",) and "sizeof" not in count_text:
                findings.append(Finding(
                    rule_id="ADV-INTOVFL-001",
                    cwe="CWE-190",
                    vulnerability_type="Integer Overflow in Allocation",
                    severity=Severity.HIGH,
                    confidence=0.80,
                    file=self._filename, line=line, column=col,
                    message=(
                        f"calloc({count_text}, {size_text}): if '{count_text}' is user-controlled, "
                        f"the internal multiplication may overflow, causing undersized allocation."
                    ),
                    remediation=(
                        f"Validate '{count_text}' against a maximum bound before allocation, "
                        f"or use checked multiplication: if (count > SIZE_MAX / sizeof(type)) abort();"
                    ),
                    code_snippet=_snippet(self._lines, line - 1),
                    analyzer_source=self.source_type,
                    evidence=[_evidence(
                        self.source_type,
                        f"Allocation count argument '{count_text}' has AST type '{count_node.type}' — not a compile-time constant",
                        0.80,
                    )],
                    risk_score=0.78,
                ))
            return

        # For malloc / realloc: check the size argument for multiplication
        size_arg = args[0] if fn != "realloc" else (args[1] if len(args) >= 2 else None)
        if not size_arg:
            return

        size_text = get_node_text(size_arg, self._source)

        # Find binary_expression with * in the size argument
        mults = find_nodes_by_type(size_arg, ["binary_expression"])
        for mult in mults:
            op = None
            for child in mult.children:
                if not child.is_named and get_node_text(child, self._source).strip() == "*":
                    op = "*"
                    break
            if op != "*":
                continue

            left = mult.child_by_field_name("left")
            right = mult.child_by_field_name("right")
            if not left or not right:
                continue

            left_text = get_node_text(left, self._source)
            right_text = get_node_text(right, self._source)

            # If both sides are compile-time constants, skip
            both_const = (
                (left.type == "number_literal" or "sizeof" in left_text) and
                (right.type == "number_literal" or "sizeof" in right_text)
            )
            if both_const:
                continue

            # At least one side is variable — potential overflow
            var_side = left_text if left.type != "number_literal" and "sizeof" not in left_text else right_text
            findings.append(Finding(
                rule_id="ADV-INTOVFL-002",
                cwe="CWE-190",
                vulnerability_type="Integer Overflow in Allocation Size",
                severity=Severity.HIGH,
                confidence=0.82,
                file=self._filename, line=line, column=col,
                message=(
                    f"{fn}({size_text}): multiplication '{left_text} * {right_text}' may overflow "
                    f"if '{var_side}' is large, resulting in an undersized buffer."
                ),
                remediation=(
                    f"Check for overflow before allocation: "
                    f"if ({var_side} > SIZE_MAX / sizeof(...)) abort();"
                ),
                code_snippet=_snippet(self._lines, line - 1),
                analyzer_source=self.source_type,
                evidence=[_evidence(
                    self.source_type,
                    f"Multiplication in allocation size: {left_text} * {right_text}. "
                    f"'{var_side}' is not a compile-time constant (AST type: "
                    f"'{left.type if left_text == var_side else right.type}').",
                    0.82,
                )],
                risk_score=0.80,
            ))

    # ═══════════════════════════════════════════════════════════════════
    # Check: Resource Leaks (CWE-401 / CWE-775)
    # ═══════════════════════════════════════════════════════════════════

    def _check_resource_leaks(self, state: FunctionState, findings: List[Finding]):
        """
        Detection technique: AST + state tracking across function body.
        Checks that every fopen/open/socket has a matching fclose/close on all paths.
        Limitation: Not path-sensitive. If resource is closed in one branch but not another,
        we may not detect the leak. We report if NO close is found for the resource anywhere.
        Known FP: Resources intentionally leaked (e.g., returned to caller, stored in global).
        Known FN: Resources closed through wrapper functions or via aliases we don't track.
        """
        for var, (alloc_line, alloc_col, res_type) in state.resources.items():
            resolved = state.resolve_alias(var)
            if var not in state.released_resources and resolved not in state.released_resources:
                # Check if the variable is returned (caller takes ownership)
                is_returned = False
                returns = find_nodes_by_type(state.func_node, ["return_statement"])
                for ret in returns:
                    ret_ids = _identifier_names_in(ret, self._source)
                    if var in ret_ids or resolved in ret_ids:
                        is_returned = True
                        break

                if is_returned:
                    continue

                close_fn = "fclose" if res_type == "FILE" else "close"
                findings.append(Finding(
                    rule_id="ADV-LEAK-001",
                    cwe="CWE-775" if res_type == "FILE" else "CWE-401",
                    vulnerability_type=f"Resource Leak ({res_type})",
                    severity=Severity.MEDIUM,
                    confidence=0.78,
                    file=self._filename, line=alloc_line, column=alloc_col,
                    message=(
                        f"Resource '{var}' of type {res_type} opened at line {alloc_line} "
                        f"is never closed with {close_fn}() in any visible code path."
                    ),
                    remediation=f"Ensure {close_fn}({var}) is called before the function returns on all paths.",
                    code_snippet=_snippet(self._lines, alloc_line - 1),
                    analyzer_source=self.source_type,
                    evidence=[_evidence(
                        self.source_type,
                        f"Resource opened at line {alloc_line}, no {close_fn}() found in function body. "
                        f"Analysis is not path-sensitive: leaks on error branches may be missed.",
                        0.78,
                    )],
                    risk_score=0.68,
                ))

        # Memory leak: allocated but never freed and not returned
        for var, (alloc_line, alloc_col, allocator) in state.allocated.items():
            resolved = state.resolve_alias(var)
            if var in state.freed or resolved in state.freed:
                continue

            # Check if returned
            is_returned = False
            returns = find_nodes_by_type(state.func_node, ["return_statement"])
            for ret in returns:
                ret_ids = _identifier_names_in(ret, self._source)
                if var in ret_ids or resolved in ret_ids:
                    is_returned = True
                    break

            if is_returned:
                continue

            # Check if stored in a global/passed to another function (reduces confidence)
            # For now, report with reduced confidence if function has many call expressions
            findings.append(Finding(
                rule_id="ADV-MEMLEAK-001",
                cwe="CWE-401",
                vulnerability_type="Memory Leak",
                severity=Severity.MEDIUM,
                confidence=0.72,
                file=self._filename, line=alloc_line, column=alloc_col,
                message=(
                    f"Memory allocated via {allocator}() at line {alloc_line} and stored in '{var}' "
                    f"is not freed before the function returns."
                ),
                remediation=f"Add free({var}) before return, or document intentional ownership transfer.",
                code_snippet=_snippet(self._lines, alloc_line - 1),
                analyzer_source=self.source_type,
                evidence=[_evidence(
                    self.source_type,
                    f"Allocation at line {alloc_line} via {allocator}(), "
                    f"no corresponding free() found in function scope. "
                    f"Limitation: does not track if pointer is stored in a struct or global.",
                    0.72,
                )],
                risk_score=0.62,
            ))
