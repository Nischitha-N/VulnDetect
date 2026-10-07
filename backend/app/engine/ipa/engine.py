"""
Inter-Procedural Static Analysis Engine.
Propagates function summaries across CallGraph call sites to identify cross-function
vulnerabilities (UAF, command injection, double free, resource leaks).
"""

from dataclasses import dataclass
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
    find_nodes_by_type,
    get_function_definitions,
    get_call_expressions,
    get_call_name,
    get_call_arguments,
)
from app.engine.ipa.summary import FunctionSummary
from app.engine.ipa.callgraph import CallGraph, CallSite
from app.engine.ipa.summarizer import FunctionSummarizer
from app.engine.ipa.store import ProjectSummaryStore
from app.engine.ipa.alloc import AllocObject, AllocState
from app.engine.taint.spec import TaintConfigManager


class InterProceduralEngine:
    """
    Executes inter-procedural analysis over a CallGraph using bottom-up function summaries.
    Supports both single-file analysis and whole-project cross-file analysis.
    """

    def __init__(self, taint_config: Optional[TaintConfigManager] = None):
        self.taint_config: TaintConfigManager = taint_config or TaintConfigManager()
        self.summarizer: FunctionSummarizer = FunctionSummarizer(self.taint_config)
        self.summaries: Dict[str, FunctionSummary] = {}
        self.call_graph: CallGraph = CallGraph()
        self.project_store: Optional[ProjectSummaryStore] = None

    def build_project_summaries(self, contexts: List[AnalysisContext]):
        """
        Phase 1: Project-wide Function Summary Collection.
        Scans all translation units, maps call dependencies across files,
        computes bottom-up topological ordering, and derives FunctionSummary objects
        persisted in self.project_store.
        """
        self.project_store = ProjectSummaryStore()

        # 1. Collect all function definitions across all compilation units
        # func_records: scoped_id -> (file_path, func_name, func_node, source_code, is_static)
        func_records: Dict[str, Tuple[str, str, Node, str, bool]] = {}
        global_name_to_files: Dict[str, List[str]] = {}

        for ctx in contexts:
            if not ctx.ast_root:
                continue
            source_code = ctx.source_code
            file_path = ctx.file_path
            func_nodes = get_function_definitions(ctx.ast_root)
            for fn_node in func_nodes:
                fn_name = CallGraph._extract_func_name(fn_node, source_code)
                if not fn_name or fn_name == "anonymous":
                    continue
                is_static = any(
                    c.type == "storage_class_specifier" and c.text.decode("utf-8") == "static"
                    for c in fn_node.children
                )
                scoped_id = f"{file_path}::{fn_name}"
                func_records[scoped_id] = (file_path, fn_name, fn_node, source_code, is_static)
                if not is_static:
                    global_name_to_files.setdefault(fn_name, []).append(file_path)

        # 2. Build dependency graph across project functions
        # callees_graph: scoped_id -> set of callee scoped_ids
        callees_graph: Dict[str, Set[str]] = {sid: set() for sid in func_records}

        for scoped_id, (file_path, fn_name, fn_node, source_code, is_static) in func_records.items():
            calls = get_call_expressions(fn_node)
            for c in calls:
                callee_name = get_call_name(c, source_code)
                if not callee_name:
                    continue
                # Local call in same file
                local_callee_id = f"{file_path}::{callee_name}"
                if local_callee_id in func_records:
                    callees_graph[scoped_id].add(local_callee_id)
                # Global call in another file (only if unambiguous)
                elif callee_name in global_name_to_files:
                    def_files = global_name_to_files[callee_name]
                    if len(def_files) == 1:
                        target_id = f"{def_files[0]}::{callee_name}"
                        if target_id in func_records:
                            callees_graph[scoped_id].add(target_id)

        # 3. Bottom-up topological sort across all project functions
        visited: Set[str] = set()
        eval_order: List[str] = []

        def _dfs(sid: str, path: Set[str]):
            if sid in path or sid in visited:
                return
            path.add(sid)
            for callee_id in callees_graph.get(sid, set()):
                if callee_id in func_records:
                    _dfs(callee_id, path)
            path.remove(sid)
            visited.add(sid)
            eval_order.append(sid)

        for sid in func_records:
            if sid not in visited:
                _dfs(sid, set())

        # 4. Derive summaries bottom-up and persist in project_store
        for sid in eval_order:
            file_path, fn_name, fn_node, source_code, is_static = func_records[sid]
            known = self.project_store.get_accessible_summaries(file_path)
            summary = self.summarizer.summarize(
                fn_name,
                fn_node,
                source_code,
                file_path,
                known,
            )
            self.project_store.add_summary(summary, is_static=is_static)

    def clear_project_summaries(self):
        """Reset project-level summary store."""
        if self.project_store:
            self.project_store.clear()
        self.project_store = None

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        if not context.ast_root:
            return []

        findings: List[Finding] = []
        source_code = context.source_code

        # 1. Build CallGraph for current file
        self.call_graph = CallGraph()
        self.call_graph.build_from_ast(context.ast_root, source_code)

        # 2. Populate summaries
        if self.project_store is not None:
            # Multi-file project mode: retrieve summaries for this file's scope
            self.summaries = self.project_store.get_accessible_summaries(context.file_path)
        else:
            # Single-file mode: compute bottom-up within translation unit
            self.summaries = {}
            eval_order = self.call_graph.bottom_up_order()
            for fn_name in eval_order:
                fn_node = self.call_graph.functions[fn_name]
                summary = self.summarizer.summarize(
                    fn_name,
                    fn_node,
                    source_code,
                    context.file_path,
                    self.summaries
                )
                self.summaries[fn_name] = summary

        # 3. Analyze each caller function instantiating callee summaries
        for fn_name, fn_node in self.call_graph.functions.items():
            self._analyze_function_with_summaries(fn_name, fn_node, context, findings)

        return findings

    # --- Allocation helpers for Env/Store memory model ---
    _alloc_counter: int = 0

    @classmethod
    def _next_alloc_id(cls) -> str:
        cls._alloc_counter += 1
        return f"alloc_{cls._alloc_counter}"

    def _create_alloc(
        self,
        file_path: str,
        func_name: str,
        line: int,
        col: int,
        allocator: str,
        env: Dict[str, Set[AllocObject]],
        store: Dict[AllocObject, AllocState],
        var_name: str,
    ) -> AllocObject:
        """Create a new AllocObject, bind it in env, and set it ALLOCATED in store."""
        obj = AllocObject(
            alloc_id=self._next_alloc_id(),
            file_path=file_path,
            function_name=func_name,
            line=line,
            column=col,
            allocator=allocator,
        )
        # Strong update: rebind variable to exactly this new allocation
        env[var_name] = {obj}
        store[obj] = AllocState(status="ALLOCATED", alloc_line=line, alloc_column=col)
        return obj

    def _free_var(
        self,
        var_name: str,
        line: int,
        col: int,
        freed_via: str,
        env: Dict[str, Set[AllocObject]],
        store: Dict[AllocObject, AllocState],
    ) -> Optional[AllocObject]:
        """
        Mark all allocations bound to *var_name* as FREED.
        Returns the first already-FREED AllocObject (for double-free reporting), or None.
        """
        objs = env.get(var_name, set())
        already_freed: Optional[AllocObject] = None
        for obj in objs:
            state = store.get(obj)
            if state and state.status == "FREED" and already_freed is None:
                already_freed = obj
            # Transition to FREED regardless (needed for UAF detection after this point)
            if state:
                state.status = "FREED"
                state.free_line = line
                state.free_column = col
                state.freed_via = freed_via
            else:
                store[obj] = AllocState(status="FREED", free_line=line, free_column=col, freed_via=freed_via)
        return already_freed

    def _check_deref_uaf(
        self,
        var_name: str,
        env: Dict[str, Set[AllocObject]],
        store: Dict[AllocObject, AllocState],
    ) -> Optional[AllocObject]:
        """Return the first FREED AllocObject bound to *var_name*, or None."""
        for obj in env.get(var_name, set()):
            state = store.get(obj)
            if state and state.status == "FREED":
                return obj
        return None

    def _analyze_function_with_summaries(
        self,
        caller_name: str,
        func_node: Node,
        context: AnalysisContext,
        findings: List[Finding]
    ):
        source_code = context.source_code
        body = func_node.child_by_field_name("body")
        if not body:
            return

        # --- Env / Store memory model ---
        # env:   variable_name -> set of abstract AllocObjects it may point to
        # store: AllocObject   -> AllocState (lifecycle: ALLOCATED | FREED)
        env: Dict[str, Set[AllocObject]] = {}
        store: Dict[AllocObject, AllocState] = {}

        # Taint tracking (unchanged)
        # var -> {"taint_source": str, "source_line": int, "source_callee": str}
        tainted_vars: Dict[str, Dict[str, Any]] = {}
        # res -> {"acquired_line": int, "status": "OPEN"|"CLOSED"}
        resource_state: Dict[str, Dict[str, Any]] = {}

        stmts = find_nodes_by_type(body, ["declaration", "expression_statement"])

        for stmt in stmts:
            line, col = get_node_location(stmt)
            code_text = get_node_text(stmt, source_code).strip()

            # A. Process Declarations & Initializations
            init_decls = find_nodes_by_type(stmt, ["init_declarator"])
            for d in init_decls:
                var_decl = d.child_by_field_name("declarator")
                val_node = d.child_by_field_name("value")
                var_name = get_node_text(var_decl, source_code).lstrip("*&").strip() if var_decl else ""

                if var_name and val_node:
                    if val_node.type == "call_expression":
                        callee_name = get_call_name(val_node, source_code) or ""
                        if callee_name in self.summaries:
                            callee_sum = self.summaries[callee_name]
                            if callee_sum.return_is_source:
                                tainted_vars[var_name] = {
                                    "taint_source": callee_sum.return_source_desc,
                                    "source_line": line,
                                    "source_callee": callee_name,
                                    "source_file": callee_sum.file_path,
                                }
                            if callee_sum.return_allocated_memory or callee_sum.return_can_be_null:
                                self._create_alloc(
                                    context.file_path, caller_name, line, col,
                                    callee_name, env, store, var_name,
                                )
                        elif callee_name in ("malloc", "calloc", "realloc"):
                            self._create_alloc(
                                context.file_path, caller_name, line, col,
                                callee_name, env, store, var_name,
                            )
                    elif val_node.type == "identifier":
                        # Pointer alias via declaration: char *q = p;
                        rhs_name = get_node_text(val_node, source_code).lstrip("*&").strip()
                        if rhs_name in env:
                            env[var_name] = set(env[rhs_name])  # share allocation identity
                        if rhs_name in tainted_vars:
                            tainted_vars[var_name] = dict(tainted_vars[rhs_name])

            # B. Process Assignments (p = q, cmd = get_input(), etc.)
            assign_nodes = find_nodes_by_type(stmt, ["assignment_expression"])
            for a in assign_nodes:
                left = a.child_by_field_name("left")
                right = a.child_by_field_name("right")
                left_text = get_node_text(left, source_code).lstrip("*&").strip() if left else ""

                if left_text and right:
                    if right.type == "call_expression":
                        callee_name = get_call_name(right, source_code) or ""
                        if callee_name in self.summaries:
                            callee_sum = self.summaries[callee_name]
                            if callee_sum.return_is_source:
                                tainted_vars[left_text] = {
                                    "taint_source": callee_sum.return_source_desc,
                                    "source_line": line,
                                    "source_callee": callee_name,
                                    "source_file": callee_sum.file_path,
                                }
                            if callee_sum.return_allocated_memory:
                                # Strong update: rebind variable to fresh allocation
                                self._create_alloc(
                                    context.file_path, caller_name, line, col,
                                    callee_name, env, store, left_text,
                                )
                        elif callee_name in ("malloc", "calloc", "realloc"):
                            # Strong update: rebind variable to fresh allocation
                            self._create_alloc(
                                context.file_path, caller_name, line, col,
                                callee_name, env, store, left_text,
                            )
                    elif right.type == "identifier":
                        # Simple pointer copy: q = p  -> q aliases the same objects as p
                        rhs_name = get_node_text(right, source_code).lstrip("*&").strip()
                        if rhs_name in env:
                            env[left_text] = set(env[rhs_name])  # copy binding set

            # C. Check Dereferences (Inter-procedural UAF)
            derefs = find_nodes_by_type(stmt, ["pointer_expression", "subscript_expression"])
            for d in derefs:
                arg = d.child_by_field_name("argument")
                ptr_name = get_node_text(arg, source_code).lstrip("*&").strip() if arg else ""
                freed_obj = self._check_deref_uaf(ptr_name, env, store)
                if freed_obj is not None:
                    freed_state = store[freed_obj]
                    freed_via = freed_state.freed_via or "free"
                    freed_line = freed_state.free_line or 0
                    msg = (
                        f"Inter-procedural Use-After-Free: pointer '{ptr_name}' was freed via helper "
                        f"'{freed_via}()' on line {freed_line} and subsequently dereferenced."
                    )
                    f = Finding(
                        rule_id="IPA-UAF-001",
                        cwe="CWE-416",
                        vulnerability_type="Inter-procedural Use After Free",
                        severity=Severity.CRITICAL,
                        risk_score=0.96,
                        confidence=0.98,
                        file=context.file_path,
                        line=line,
                        column=col,
                        message=msg,
                        remediation=f"Do not access '{ptr_name}' after passing it to freeing helper '{freed_via}()'.",
                        code_snippet=code_text,
                        analyzer_source=AnalyzerSource.IPA,
                        analysis_status=AnalysisStatus.CONFIRMED,
                        evidence=[
                            EvidenceItem(
                                analyzer_source=AnalyzerSource.IPA,
                                description=f"Function summary contract: '{freed_via}()' releases argument 0",
                                confidence=0.98,
                                metadata={"freed_via": freed_via, "free_line": freed_line}
                            )
                        ],
                        dataflow_path=[
                            DataflowStep("SOURCE", freed_line, None, f"{freed_via}({ptr_name})", f"Memory released by helper"),
                            DataflowStep("SINK", line, col, code_text, f"Use-after-free in caller '{caller_name}'")
                        ]
                    )
                    findings.append(f)

            # D. Process Call Expressions & Callee Side-Effects
            calls = get_call_expressions(stmt)
            for c in calls:
                callee_name = get_call_name(c, source_code) or ""
                args = get_call_arguments(c)
                arg_texts = [get_node_text(a, source_code).lstrip("*&").strip() for a in args]

                # 1. Direct free()
                if callee_name == "free" and arg_texts:
                    target = arg_texts[0]
                    already_freed_obj = self._free_var(target, line, col, "free", env, store)
                    if already_freed_obj is not None:
                        self._report_double_free(target, line, col, code_text, already_freed_obj, store, context, findings)

                # 2. Callee with summary
                elif callee_name in self.summaries:
                    callee_sum = self.summaries[callee_name]

                    # Check freed parameters
                    for freed_idx in callee_sum.freed_params:
                        if freed_idx < len(arg_texts):
                            target = arg_texts[freed_idx]
                            already_freed_obj = self._free_var(target, line, col, callee_name, env, store)
                            if already_freed_obj is not None:
                                self._report_double_free(target, line, col, code_text, already_freed_obj, store, context, findings)

                    # Check sink destinations (Inter-procedural Taint / Command Injection)
                    for sink_name, sink_p_idx, cwe in callee_sum.sink_calls:
                        if sink_p_idx < len(arg_texts):
                            target = arg_texts[sink_p_idx]
                            if target in tainted_vars:
                                t_info = tainted_vars[target]
                                msg = (
                                    f"Inter-procedural Command Injection: tainted data originating from "
                                    f"'{t_info['taint_source']}' on line {t_info['source_line']} flows into "
                                    f"helper '{callee_name}()' which executes critical sink '{sink_name}()'."
                                )
                                f = Finding(
                                    rule_id=f"IPA-TAINT-{sink_name.upper()}-001",
                                    cwe=cwe,
                                    vulnerability_type=f"Inter-procedural Taint to {sink_name}()",
                                    severity=Severity.CRITICAL,
                                    risk_score=0.96,
                                    confidence=0.98,
                                    file=context.file_path,
                                    line=line,
                                    column=col,
                                    message=msg,
                                    remediation="Validate or sanitize input before passing to execution helper.",
                                    code_snippet=code_text,
                                    analyzer_source=AnalyzerSource.IPA,
                                    analysis_status=AnalysisStatus.CONFIRMED,
                                    evidence=[
                                        EvidenceItem(
                                            analyzer_source=AnalyzerSource.IPA,
                                            description=f"Inter-procedural dataflow: {t_info.get('source_callee', 'source')}() -> {caller_name}() -> {callee_name}() -> {sink_name}()",
                                            confidence=0.98,
                                            metadata={
                                                "origin_callee": t_info.get("source_callee"),
                                                "origin_file": t_info.get("source_file"),
                                                "sink_callee": callee_name,
                                                "sink_file": callee_sum.file_path,
                                                "sink_func": sink_name,
                                            }
                                        )
                                    ],
                                    dataflow_path=[
                                        DataflowStep("SOURCE", t_info["source_line"], None, "", f"Taint origin: {t_info['taint_source']}"),
                                        DataflowStep("PROPAGATION", line, col, code_text, f"Passed to helper '{callee_name}()'"),
                                        DataflowStep("SINK", line, col, f"{callee_name}({target})", f"Callee invokes sink '{sink_name}()'")
                                    ]
                                )
                                findings.append(f)

    def _report_double_free(
        self,
        target: str,
        line: int,
        col: int,
        code_text: str,
        freed_obj: AllocObject,
        store: Dict[AllocObject, AllocState],
        context: AnalysisContext,
        findings: List[Finding]
    ):
        freed_state = store[freed_obj]
        freed_via = freed_state.freed_via or "free"
        freed_line = freed_state.free_line or 0
        msg = (
            f"Inter-procedural Double Free: pointer '{target}' was previously freed on line {freed_line} "
            f"via '{freed_via}()' and is freed again."
        )
        f = Finding(
            rule_id="IPA-DOUBLE-FREE-001",
            cwe="CWE-415",
            vulnerability_type="Inter-procedural Double Free",
            severity=Severity.CRITICAL,
            risk_score=0.96,
            confidence=0.98,
            file=context.file_path,
            line=line,
            column=col,
            message=msg,
            remediation=f"Avoid duplicate free on '{target}'.",
            code_snippet=code_text,
            analyzer_source=AnalyzerSource.IPA,
            analysis_status=AnalysisStatus.CONFIRMED,
            evidence=[
                EvidenceItem(
                    analyzer_source=AnalyzerSource.IPA,
                    description=f"Inter-procedural double free: already freed via '{freed_via}()'",
                    confidence=0.98
                )
            ],
            dataflow_path=[
                DataflowStep("SOURCE", freed_line, None, "", f"First free via {freed_via}()"),
                DataflowStep("SINK", line, col, code_text, "Second free")
            ]
        )
        findings.append(f)
