"""
C++ Semantic Security Engine.
Analyzes C++ RAII, move semantics, smart pointers, container/iterator invalidations,
new/delete mismatches, dangling references, polymorphic destruction, and unsafe casts.
"""

from typing import Dict, List, Set, Optional, Tuple, Any
from tree_sitter import Node

from app.engine.base import (
    Finding,
    AnalyzerSource,
    Severity,
    AnalysisStatus,
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
from app.engine.cpp.model import (
    CppTypeKind,
    AllocKind,
    CppObjectLifecycle,
    ClassHierarchy,
    CppVariableState,
)


class CppSemanticEngine:
    """
    Analyzes C++ semantics across AST nodes.
    """

    def __init__(self):
        self.classes: Dict[str, ClassHierarchy] = {}

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        if not context.ast_root:
            return []

        findings: List[Finding] = []
        source_code = context.source_code

        # 1. Pre-scan class declarations & inheritance hierarchies
        self._scan_classes(context.ast_root, source_code)

        # 2. Analyze functions for C++ semantics
        funcs = get_function_definitions(context.ast_root)
        for fn in funcs:
            self._analyze_function(fn, context, findings)

        return findings

    def _scan_classes(self, root: Node, source_code: str):
        """Extracts class definitions, virtual methods, and virtual destructors."""
        self.classes = {}
        class_nodes = find_nodes_by_type(root, ["class_specifier", "struct_specifier"])

        for cls in class_nodes:
            name_node = cls.child_by_field_name("name")
            cls_name = get_node_text(name_node, source_code).strip() if name_node else ""
            if not cls_name:
                continue

            hierarchy = ClassHierarchy(class_name=cls_name)

            # Check base classes
            bases_node = cls.child_by_field_name("bases") or cls.child_by_field_name("base_class_clause")
            if bases_node:
                for base in find_nodes_by_type(bases_node, ["type_identifier", "identifier"]):
                    hierarchy.base_classes.append(get_node_text(base, source_code).strip())

            # Check members inside class body
            body_node = cls.child_by_field_name("body")
            if body_node:
                for decl in find_nodes_by_type(body_node, ["field_declaration", "declaration", "function_definition"]):
                    decl_text = get_node_text(decl, source_code)
                    if "virtual" in decl_text:
                        hierarchy.virtual_methods.append(decl_text.split("(")[0].strip())
                        if f"~{cls_name}" in decl_text:
                            hierarchy.has_virtual_destructor = True
                    elif f"~{cls_name}" in decl_text:
                        hierarchy.has_custom_destructor = True

            self.classes[cls_name] = hierarchy

    def _analyze_function(self, func_node: Node, context: AnalysisContext, findings: List[Finding]):
        source_code = context.source_code
        vars_map: Dict[str, CppVariableState] = {}
        func_text = get_node_text(func_node, source_code)
        header_text = func_text.split("{")[0] if "{" in func_text else func_text
        is_ref_return = "&" in header_text or "string_view" in header_text

        body = func_node.child_by_field_name("body")
        if not body:
            return

        stmts = find_nodes_by_type(body, ["declaration", "expression_statement", "return_statement"])

        for stmt in stmts:
            line, col = get_node_location(stmt)
            code_text = get_node_text(stmt, source_code).strip()
            stype = stmt.type

            # ─── 1. Declarations & Allocations ────────────────────────────────
            if stype == "declaration":
                self._handle_declaration(stmt, vars_map, source_code, line, col, code_text, context, findings)

            # ─── 2. Expression Statements (Moves, Deletions, Mutations) ───────
            elif stype == "expression_statement":
                self._handle_expression_statement(stmt, vars_map, source_code, line, col, code_text, context, findings)

            # ─── 3. Return Statements (Dangling Reference to Local) ───────────
            elif stype == "return_statement":
                self._handle_return_statement(stmt, vars_map, is_ref_return, header_text.strip(), source_code, line, col, code_text, context, findings)

    def _handle_declaration(
        self,
        stmt: Node,
        vars_map: Dict[str, CppVariableState],
        source_code: str,
        line: int,
        col: int,
        code_text: str,
        context: AnalysisContext,
        findings: List[Finding]
    ):
        type_node = stmt.child_by_field_name("type")
        type_text = get_node_text(type_node, source_code).strip() if type_node else ""

        init_decls = find_nodes_by_type(stmt, ["init_declarator"])
        for d in init_decls:
            decl_child = d.child_by_field_name("declarator")
            val_node = d.child_by_field_name("value")
            var_name = get_node_text(decl_child, source_code).lstrip("*&").strip() if decl_child else ""

            if not var_name:
                continue

            # Record variable state
            vars_map[var_name] = CppVariableState(
                var_name=var_name,
                type_name=type_text,
                declared_line=line
            )

            if not val_node:
                continue

            val_text = get_node_text(val_node, source_code).strip()

            # A. Allocation: new T vs new T[] vs make_unique
            if "new " in val_text:
                is_array = "[" in val_text
                vars_map[var_name].type_kind = CppTypeKind.RAW_POINTER
                vars_map[var_name].alloc_kind = AllocKind.ARRAY_NEW if is_array else AllocKind.SCALAR_NEW
                vars_map[var_name].type_name = type_text.rstrip("* ")

            elif "make_unique" in val_text or "unique_ptr" in type_text:
                vars_map[var_name].type_kind = CppTypeKind.UNIQUE_PTR
                vars_map[var_name].alloc_kind = AllocKind.MAKE_UNIQUE
                vars_map[var_name].type_name = type_text

            # B. Move construction: auto v2 = std::move(v1);
            elif "std::move" in val_text or "move(" in val_text:
                moved_vars = find_nodes_by_type(val_node, ["identifier"])
                for mv in moved_vars:
                    mv_name = get_node_text(mv, source_code).strip()
                    if mv_name in vars_map and mv_name != "move" and mv_name != "std":
                        vars_map[mv_name].lifecycle = CppObjectLifecycle.MOVED_FROM
                        vars_map[mv_name].move_line = line

            # C. Dangling Temporary: const char* p = std::string("...").c_str();
            elif ".c_str()" in val_text or "data()" in val_text:
                if "std::string(" in val_text or "string(" in val_text or "\"" in val_text:
                    f = Finding(
                        rule_id="CPP-DANGLING-TEMPORARY-002",
                        cwe="CWE-672",
                        vulnerability_type="Dangling Pointer to Temporary Object",
                        severity=Severity.HIGH,
                        risk_score=0.88,
                        confidence=0.95,
                        file=context.file_path,
                        line=line,
                        column=col,
                        message=f"Dangling pointer '{var_name}': points to internal buffer of temporary std::string destroyed at end of statement.",
                        remediation="Bind the std::string to a named local variable with adequate lifetime before calling .c_str().",
                        code_snippet=code_text,
                        analyzer_source=AnalyzerSource.CPP,
                        analysis_status=AnalysisStatus.CONFIRMED,
                        evidence=[
                            EvidenceItem(
                                analyzer_source=AnalyzerSource.CPP,
                                description="Temporary std::string object lifetime ends at full expression boundary",
                                confidence=0.95
                            )
                        ]
                    )
                    findings.append(f)

            # D. Iterator or Element pointer: auto it = v.begin(); or int *p = &v[0];
            if ".begin()" in val_text or ".end()" in val_text:
                cont = val_text.split(".")[0].strip()
                vars_map[var_name].type_kind = CppTypeKind.ITERATOR
                vars_map[var_name].container_target = cont
            elif "[0]" in val_text or "&" in val_text:
                for v in list(vars_map.keys()):
                    if f"&{v}[" in val_text or f"&{v}." in val_text:
                        vars_map[var_name].type_kind = CppTypeKind.RAW_POINTER
                        vars_map[var_name].container_target = v
                        break

    def _handle_expression_statement(
        self,
        stmt: Node,
        vars_map: Dict[str, CppVariableState],
        source_code: str,
        line: int,
        col: int,
        code_text: str,
        context: AnalysisContext,
        findings: List[Finding]
    ):
        # ─── A. Delete Expressions (Mismatches & Non-Virtual Destructors) ─────
        delete_nodes = find_nodes_by_type(stmt, ["delete_expression"])
        for del_node in delete_nodes:
            is_array_delete = "[" in get_node_text(del_node, source_code)
            del_args = find_nodes_by_type(del_node, ["identifier"])
            for arg in del_args:
                var_name = get_node_text(arg, source_code).strip()
                if var_name in vars_map:
                    state = vars_map[var_name]

                    # 1. new[] / delete mismatch
                    if state.alloc_kind == AllocKind.ARRAY_NEW and not is_array_delete:
                        f = Finding(
                            rule_id="CPP-ARRAY-DELETE-MISMATCH-001",
                            cwe="CWE-762",
                            vulnerability_type="Mismatched Deallocation (new[] with delete)",
                            severity=Severity.CRITICAL,
                            risk_score=0.92,
                            confidence=0.98,
                            file=context.file_path,
                            line=line,
                            column=col,
                            message=f"Mismatched deallocation: array allocated with 'new[]' on line {state.declared_line} is deleted with scalar 'delete'.",
                            remediation=f"Use 'delete[] {var_name};' or replace with std::vector / std::unique_ptr<T[]>.",
                            code_snippet=code_text,
                            analyzer_source=AnalyzerSource.CPP,
                            analysis_status=AnalysisStatus.CONFIRMED,
                            evidence=[
                                EvidenceItem(
                                    analyzer_source=AnalyzerSource.CPP,
                                    description=f"Variable '{var_name}' allocated with 'new[]' on L{state.declared_line}, freed with scalar 'delete'",
                                    confidence=0.98
                                )
                            ]
                        )
                        findings.append(f)

                    # 2. new / delete[] mismatch
                    elif state.alloc_kind == AllocKind.SCALAR_NEW and is_array_delete:
                        f = Finding(
                            rule_id="CPP-SCALAR-DELETE-MISMATCH-002",
                            cwe="CWE-762",
                            vulnerability_type="Mismatched Deallocation (new with delete[])",
                            severity=Severity.CRITICAL,
                            risk_score=0.92,
                            confidence=0.98,
                            file=context.file_path,
                            line=line,
                            column=col,
                            message=f"Mismatched deallocation: scalar object allocated with 'new' on line {state.declared_line} is deleted with array 'delete[]'.",
                            remediation=f"Use 'delete {var_name};' or std::make_unique.",
                            code_snippet=code_text,
                            analyzer_source=AnalyzerSource.CPP,
                            analysis_status=AnalysisStatus.CONFIRMED,
                            evidence=[
                                EvidenceItem(
                                    analyzer_source=AnalyzerSource.CPP,
                                    description=f"Variable '{var_name}' allocated with scalar 'new' on L{state.declared_line}, freed with 'delete[]'",
                                    confidence=0.98
                                )
                            ]
                        )
                        findings.append(f)

                    # 3. Polymorphic Destruction without Virtual Destructor
                    if state.type_name in self.classes:
                        cls_info = self.classes[state.type_name]
                        if cls_info.virtual_methods and not cls_info.has_virtual_destructor:
                            f = Finding(
                                rule_id="CPP-NON-VIRTUAL-DTOR-001",
                                cwe="CWE-1079",
                                vulnerability_type="Polymorphic Deletion without Virtual Destructor",
                                severity=Severity.HIGH,
                                risk_score=0.88,
                                confidence=0.95,
                                file=context.file_path,
                                line=line,
                                column=col,
                                message=f"Deleting polymorphic object through base class pointer '{state.type_name}*' without a virtual destructor.",
                                remediation=f"Declare 'virtual ~{state.type_name}() = default;' in class '{state.type_name}'.",
                                code_snippet=code_text,
                                analyzer_source=AnalyzerSource.CPP,
                                analysis_status=AnalysisStatus.CONFIRMED,
                                evidence=[
                                    EvidenceItem(
                                        analyzer_source=AnalyzerSource.CPP,
                                        description=f"Class '{state.type_name}' has virtual methods but non-virtual destructor",
                                        confidence=0.95
                                    )
                                ]
                            )
                            findings.append(f)

                    state.lifecycle = CppObjectLifecycle.DELETED
                    state.delete_line = line

        # ─── B. Check std::move in function calls or assignments ─────────────
        if "std::move" in code_text or "move(" in code_text:
            calls = get_call_expressions(stmt)
            for call in calls:
                cname = get_call_name(call, source_code)
                if cname in ("std::move", "move"):
                    args = get_call_arguments(call)
                    if args:
                        m_var = get_node_text(args[0], source_code).strip()
                        if m_var in vars_map:
                            vars_map[m_var].lifecycle = CppObjectLifecycle.MOVED_FROM
                            vars_map[m_var].move_line = line

        # ─── C. Check Use-After-Move on Accessed Identifiers ─────────────────
        idents = find_nodes_by_type(stmt, ["identifier", "field_expression", "pointer_expression"])
        for id_node in idents:
            name = get_node_text(id_node, source_code).lstrip("*&").strip()
            # Ignore move call itself
            if "move" in code_text and name in ("move", "std"):
                continue

            if name in vars_map:
                st = vars_map[name]
                if st.lifecycle == CppObjectLifecycle.MOVED_FROM and st.move_line and st.move_line < line:
                    f = Finding(
                        rule_id="CPP-USE-AFTER-MOVE-001",
                        cwe="CWE-672",
                        vulnerability_type="Use After Move",
                        severity=Severity.HIGH,
                        risk_score=0.88,
                        confidence=0.95,
                        file=context.file_path,
                        line=line,
                        column=col,
                        message=f"Use-after-move: object '{name}' was moved on line {st.move_line} and subsequently accessed in moved-from state.",
                        remediation=f"Do not access '{name}' after std::move(), or reinitialize it before reuse.",
                        code_snippet=code_text,
                        analyzer_source=AnalyzerSource.CPP,
                        analysis_status=AnalysisStatus.CONFIRMED,
                        evidence=[
                            EvidenceItem(
                                analyzer_source=AnalyzerSource.CPP,
                                description=f"Variable '{name}' moved on L{st.move_line}",
                                confidence=0.95
                            )
                        ],
                        dataflow_path=[
                            DataflowStep("SOURCE", st.move_line, None, f"std::move({name})", "Object moved here"),
                            DataflowStep("SINK", line, col, code_text, "Use in moved-from state")
                        ]
                    )
                    findings.append(f)

        # ─── D. Check Container Mutations & Iterator Invalidation ────────────
        calls = get_call_expressions(stmt)
        for call in calls:
            cname = get_call_name(call, source_code) or ""
            # e.g. v.push_back(x), v.insert(...), v.erase(...), v.resize(...)
            if any(mut in cname for mut in ("push_back", "emplace_back", "insert", "erase", "resize", "clear")):
                container_var = cname.split(".")[0].split("->")[0].strip()
                # Invalidate all iterators / element pointers pointing to this container
                for it_name, it_state in vars_map.items():
                    if it_state.container_target == container_var:
                        it_state.lifecycle = CppObjectLifecycle.INVALIDATED
                        it_state.delete_line = line

        # ─── E. Check Iterator Dereference after Invalidation ─────────────────
        derefs = find_nodes_by_type(stmt, ["pointer_expression", "subscript_expression"])
        for d in derefs:
            arg = d.child_by_field_name("argument")
            ptr_name = get_node_text(arg, source_code).lstrip("*&").strip() if arg else ""
            if ptr_name in vars_map:
                it_state = vars_map[ptr_name]
                if it_state.lifecycle == CppObjectLifecycle.INVALIDATED:
                    f = Finding(
                        rule_id="CPP-ITERATOR-INVALIDATION-001",
                        cwe="CWE-825",
                        vulnerability_type="Iterator or Buffer Invalidation",
                        severity=Severity.HIGH,
                        risk_score=0.88,
                        confidence=0.95,
                        file=context.file_path,
                        line=line,
                        column=col,
                        message=f"Iterator/pointer '{ptr_name}' referencing container '{it_state.container_target}' was invalidated on line {it_state.delete_line} and dereferenced.",
                        remediation=f"Reacquire iterator/pointer after modifying container '{it_state.container_target}'.",
                        code_snippet=code_text,
                        analyzer_source=AnalyzerSource.CPP,
                        analysis_status=AnalysisStatus.CONFIRMED,
                        evidence=[
                            EvidenceItem(
                                analyzer_source=AnalyzerSource.CPP,
                                description=f"Container '{it_state.container_target}' was reallocated/mutated on L{it_state.delete_line}",
                                confidence=0.95
                            )
                        ]
                    )
                    findings.append(f)

        # ─── F. Reinterpret Casts ─────────────────────────────────────────────
        casts = find_nodes_by_type(stmt, ["reinterpret_cast", "cast_expression"])
        for c in casts:
            ctext = get_node_text(c, source_code).strip()
            if "reinterpret_cast" in ctext:
                f = Finding(
                    rule_id="CPP-REINTERPRET-CAST-001",
                    cwe="CWE-704",
                    vulnerability_type="Potentially Unsafe Reinterpret Cast",
                    severity=Severity.MEDIUM,
                    risk_score=0.70,
                    confidence=0.85,
                    file=context.file_path,
                    line=line,
                    column=col,
                    message="Use of 'reinterpret_cast': bypasses C++ type safety and may cause strict aliasing or alignment faults.",
                    remediation="Use static_cast or std::bit_cast where type safety guarantees are required.",
                    code_snippet=code_text,
                    analyzer_source=AnalyzerSource.CPP,
                    analysis_status=AnalysisStatus.LIKELY,
                )
                findings.append(f)

    def _handle_return_statement(
        self,
        stmt: Node,
        vars_map: Dict[str, CppVariableState],
        is_ref_return: bool,
        ret_type_text: str,
        source_code: str,
        line: int,
        col: int,
        code_text: str,
        context: AnalysisContext,
        findings: List[Finding]
    ):
        if not is_ref_return or not stmt.named_children:
            return

        ret_expr = stmt.named_children[0]
        ret_text = get_node_text(ret_expr, source_code).lstrip("&").strip()

        # If returning address of local stack variable or local container
        if ret_text in vars_map:
            f = Finding(
                rule_id="CPP-DANGLING-LOCAL-RETURN-001",
                cwe="CWE-562",
                vulnerability_type="Returning Reference to Local Stack Object",
                severity=Severity.CRITICAL,
                risk_score=0.94,
                confidence=0.98,
                file=context.file_path,
                line=line,
                column=col,
                message=f"Dangling reference return: function returns '{ret_type_text}' bound to local stack variable '{ret_text}'.",
                remediation="Return by value or dynamically allocate with std::unique_ptr.",
                code_snippet=code_text,
                analyzer_source=AnalyzerSource.CPP,
                analysis_status=AnalysisStatus.CONFIRMED,
                evidence=[
                    EvidenceItem(
                        analyzer_source=AnalyzerSource.CPP,
                        description=f"Local stack object '{ret_text}' is destroyed at return point",
                        confidence=0.98
                    )
                ]
            )
            findings.append(f)
