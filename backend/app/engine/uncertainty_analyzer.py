"""
Layer 6: Explicit Uncertainty & Unknown Behavior Analyzer for VulnDetect.

Identifies situations where static analysis has insufficient information:
  - External library functions / missing AST definitions
  - Function pointers & indirect dispatch
  - Custom / external sanitization routines
  - Inline assembly
  - Unknown ownership semantics
  - Preprocessor macro indirections

Classifies findings into three explicit states:
  - CONFIRMED: Strong, conclusive evidence exists in the visible AST scope.
  - LIKELY: Multiple indicators suggest a vulnerability, but complete proof is unavailable.
  - NEEDS_REVIEW: Potentially dangerous pattern identified, but safety cannot be determined statically.
"""

import os
import re
from typing import List, Dict, Set, Tuple, Optional, Any
from tree_sitter import Node

from app.engine.base import (
    BaseAnalyzer,
    Finding,
    AnalyzerSource,
    AnalysisStatus,
    Severity,
    EvidenceItem,
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

# Standard C / POSIX functions whose semantics are known
KNOWN_STDLIB_FUNCS = {
    "printf", "fprintf", "sprintf", "snprintf", "dprintf", "vprintf", "vsnprintf", "vsprintf",
    "scanf", "fscanf", "sscanf", "gets", "fgets", "fputs", "puts", "getchar", "putchar",
    "strcpy", "strncpy", "strcat", "strncat", "strlen", "strcmp", "strncmp", "strdup", "strndup",
    "memcpy", "memmove", "memset", "memcmp", "malloc", "calloc", "realloc", "free",
    "system", "popen", "pclose", "execve", "execl", "execlp", "execv", "execvp",
    "fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "rewind", "fdopen", "open", "close",
    "read", "write", "access", "stat", "fstat", "lstat", "chmod", "chown", "unlink", "remove",
    "atoi", "atol", "atoll", "strtol", "strtoll", "strtoul", "strtoull", "exit", "abort",
    "setuid", "seteuid", "setgid", "setegid", "getuid", "geteuid", "getgid", "getegid",
}

# Regex patterns identifying potential custom sanitization / validation functions
SANITIZER_PATTERN = re.compile(
    r"(sanitize|clean|validate|escape|filter|check|verify|strip|normalize|is_safe|is_valid|auth)",
    re.IGNORECASE,
)


# Inline assembly keywords
ASM_KEYWORDS = {"asm", "__asm__", "__asm", "asm_statement", "inline_asm"}


class UncertaintyAnalyzer:
    """
    Evaluates findings in the context of the AST to classify certainty states
    and annotate explicit limitations, unknowns, and verification instructions.
    """

    def __init__(self):
        pass

    def evaluate_findings(self, findings: List[Finding], context: AnalysisContext) -> List[Finding]:
        """Classify each finding and enrich with uncertainty metadata."""
        if not context.ast_root:
            # When AST is unavailable, everything is NEEDS_REVIEW or LIKELY
            for f in findings:
                f.analysis_status = AnalysisStatus.NEEDS_REVIEW
                f.analysis_limitations.append(
                    "AST parser could not generate a syntax tree for this file; analysis relies strictly on lexical heuristics."
                )
                f.assumptions.append("Assumes regex pattern matches active executable code (not commented or inactive preprocessor blocks).")
                f.unknowns.append("Full syntax structure, control flow, and scope visibility are unknown.")
                f.recommended_manual_verification.append("Manually inspect the surrounding function logic and build configurations.")
                f.deterministic_result = {
                    "rule_id": f.rule_id,
                    "cwe": f.cwe,
                    "status": f.analysis_status.value,
                    "confidence": f.confidence,
                }
            return findings

        # Collect defined functions within the current compilation unit
        defined_funcs = self._get_defined_function_names(context.ast_root, context.source_code)

        # Collect function-scoped uncertainty markers (function pointers, inline asm, external calls)
        func_defs = get_function_definitions(context.ast_root)
        func_contexts = {}
        for func in func_defs:
            fname = self._get_function_name(func, context.source_code)
            if fname:
                func_contexts[fname] = self._analyze_function_uncertainty(func, context.source_code, defined_funcs)

        for finding in findings:
            self._evaluate_single_finding(finding, context, defined_funcs, func_contexts)

        return findings

    def _get_defined_function_names(self, root: Node, source: str) -> Set[str]:
        """Extract names of all functions defined in this AST translation unit."""
        defined = set()
        funcs = get_function_definitions(root)
        for f in funcs:
            name = self._get_function_name(f, source)
            if name:
                defined.add(name)
        return defined

    def _get_function_name(self, func_node: Node, source: str) -> Optional[str]:
        decl = func_node.child_by_field_name("declarator")
        if not decl:
            return None
        curr = decl
        while curr and curr.type != "identifier":
            inner = curr.child_by_field_name("declarator")
            if inner:
                curr = inner
            elif curr.named_children:
                curr = curr.named_children[0]
            else:
                break
        if curr and curr.type == "identifier":
            return get_node_text(curr, source).strip()
        ids = find_nodes_by_type(decl, ["identifier"])
        if ids:
            return get_node_text(ids[0], source).strip()
        return None

    def _analyze_function_uncertainty(self, func: Node, source: str, defined_funcs: Set[str]) -> Dict[str, Any]:
        """Identify uncertainty indicators inside a specific function body."""
        body = func.child_by_field_name("body")
        if not body:
            return {}

        body_text = get_node_text(body, source)

        # 1. Inline assembly
        has_inline_asm = bool(re.search(r'\b(__asm__|__asm|asm)\b', body_text))

        # 2. Function pointers & indirect calls
        indirect_calls = []
        calls = get_call_expressions(body)
        for call in calls:
            fn_node = call.child_by_field_name("function")
            if fn_node:
                fn_text = get_node_text(fn_node, source).strip()
                if (
                    fn_node.type in ("parenthesized_expression", "pointer_expression", "field_expression")
                    or "*" in fn_text
                    or "->" in fn_text
                ):
                    indirect_calls.append(fn_text)

        # 3. External function calls (neither in defined_funcs nor in known libc)
        external_calls = set()
        custom_sanitizers = set()
        for call in calls:
            cname = get_call_name(call, source)
            if cname:
                if cname not in defined_funcs and cname not in KNOWN_STDLIB_FUNCS:
                    external_calls.add(cname)
                    if SANITIZER_PATTERN.search(cname):
                        custom_sanitizers.add(cname)

        return {
            "has_inline_asm": has_inline_asm,
            "indirect_calls": indirect_calls,
            "external_calls": list(external_calls),
            "custom_sanitizers": list(custom_sanitizers),
        }


    def _evaluate_single_finding(
        self,
        finding: Finding,
        context: AnalysisContext,
        defined_funcs: Set[str],
        func_contexts: Dict[str, Dict[str, Any]],
    ):
        """Determine certainty status, assumptions, unknowns, and limitations for a finding."""
        source = context.source_code
        lines = context.lines
        line_idx = finding.line - 1
        line_text = lines[line_idx] if 0 <= line_idx < len(lines) else ""

        # Find enclosing function
        enclosing_func = None
        func_info = {}
        if context.ast_root:
            funcs = get_function_definitions(context.ast_root)
            for f in funcs:
                f_line_start, _ = get_node_location(f)
                f_line_end = f.end_point.row + 1
                if f_line_start <= finding.line <= f_line_end:
                    enclosing_func = self._get_function_name(f, source)
                    if enclosing_func and enclosing_func in func_contexts:
                        func_info = func_contexts[enclosing_func]
                    break

        assumptions: List[str] = []
        unknowns: List[str] = []
        limitations: List[str] = []
        manual_steps: List[str] = []

        is_confirmed = False
        is_needs_review = False

        # ─── 1. Check for Unknown Sanitizers ─────────────────────────
        if func_info.get("custom_sanitizers"):
            for san in func_info["custom_sanitizers"]:
                is_needs_review = True
                unknowns.append(f"Implementation and security contract of custom sanitizer '{san}()' is external to this translation unit.")
                assumptions.append(f"Assumes '{san}()' does NOT completely neutralize all malicious inputs or edge-case encodings.")
                limitations.append(f"VulnDetect cannot determine whether '{san}()' fully canonicalizes or sanitizes dangerous payloads because its source code is external.")
                manual_steps.append(f"Inspect the implementation of '{san}()' to verify that all malicious inputs, escapes, and null-byte bypasses are handled.")

        # ─── 2. Check for Inline Assembly ────────────────────────────
        if func_info.get("has_inline_asm"):
            is_needs_review = True
            unknowns.append("Function body contains inline assembly instructions with unknown register, stack, or memory side-effects.")
            limitations.append("VulnDetect does not parse CPU-specific assembly instructions; memory safety guarantees cannot be proven statically.")
            manual_steps.append("Audit the inline assembly block to ensure pointer bounds and register state preservation.")

        # ─── 3. Check for Function Pointers / Indirect Calls ─────────
        if func_info.get("indirect_calls"):
            for ic in func_info["indirect_calls"]:
                is_needs_review = True
                unknowns.append(f"Indirect call via function pointer '{ic}' with runtime-resolved target.")
                limitations.append(f"Target function for indirect call via function pointer '{ic}' is determined at runtime; callee behavior and pointer ownership cannot be traced statically.")
                manual_steps.append(f"Verify all possible runtime targets assigned to function pointer '{ic}'.")

        # ─── 4. Check for External Library Calls modifying state ─────
        if func_info.get("external_calls"):
            ext_list = [
                c for c in func_info["external_calls"]
                if c not in func_info.get("custom_sanitizers", []) and c not in func_info.get("indirect_calls", [])
            ]
            if ext_list:
                unknowns.append(f"Function interacts with external library APIs: {', '.join(ext_list[:3])}.")
                assumptions.append(f"Assumes external functions do not mutate or free internal pointer state unexpectedly.")
                limitations.append("Static analysis has visibility only into the current translation unit; external library contracts are assumed but unverified.")


        # ─── 5. Evaluate Rule-Specific Deterministic Confidence ──────
        rule_id = finding.rule_id

        # Conclusive cases with strong local proof
        if ("CONFIRMED" in rule_id or 
            rule_id in ("ADV-UAF-001", "ADV-UAF-RETURN-001", "ADV-DOUBLE-FREE-001",
                        "RANGE-LOOP-OFFBYONE", "RANGE-MEMCPY-OVERFLOW", "RANGE-ALLOC-NEGATIVE",
                        "CFG-RESOURCE-LEAK-001", "CFG-UAF-CONFIRMED-001", "CFG-NULL-CONFIRMED-001",
                        "CFG-DOUBLE-FREE-CONFIRMED-001", "CFG-UNINIT-CONFIRMED-001",
                        "IPA-UAF-001", "IPA-DOUBLE-FREE-001",
                        "CPP-USE-AFTER-MOVE-001", "CPP-ARRAY-DELETE-MISMATCH-001",
                        "CPP-SCALAR-DELETE-MISMATCH-002", "CPP-DANGLING-LOCAL-RETURN-001",
                        "CPP-DANGLING-TEMPORARY-002", "CPP-ITERATOR-INVALIDATION-001",
                        "CPP-NON-VIRTUAL-DTOR-001") or
            "IPA-TAINT" in rule_id) and not is_needs_review:
            is_confirmed = True
            assumptions.append("Control flow reaches this path deterministically under runtime conditions.")
            manual_steps.append("Verify runtime execution preconditions for this path.")

        elif rule_id == "AST-FORMAT-001" and not is_needs_review:
            # Direct non-literal format string (e.g. printf(user_input))
            is_confirmed = True
            assumptions.append("Format string argument is passed directly without compile-time format string protection (e.g. -Wformat-security).")
            manual_steps.append("Verify whether -Werror=format-security is enabled in the build system.")

        elif rule_id == "AST-ALLOC-003" and not is_needs_review:
            # malloc(strlen(s)) missing + 1
            is_confirmed = True
            assumptions.append("String argument requires standard null-terminator byte.")
            manual_steps.append("Verify if the allocated buffer is treated as a raw byte array or a null-terminated C string.")

        elif rule_id in ("ADV-NULL-001", "ADV-INTOVFL-001", "ADV-INTOVFL-002", "ADV-TOCTOU-001", "ADV-LEAK-001"):
            # Structural patterns that are very likely, but may depend on external inputs or caller context
            if not is_needs_review:
                finding.analysis_status = AnalysisStatus.LIKELY
                if rule_id == "ADV-NULL-001":
                    assumptions.append("Allocation function may return NULL when system memory is exhausted.")
                    unknowns.append("Runtime system memory headroom and caller-level signal handlers (e.g. SIGSEGV recovery) are unknown.")
                    manual_steps.append("Check if global out-of-memory handlers or custom allocators that abort on failure (xmalloc) are used.")
                elif "INTOVFL" in rule_id:
                    assumptions.append("Size/count parameter is supplied by user or external input without prior range clamping.")
                    unknowns.append("Pre-validation bounds applied in caller functions are not visible in this function scope.")
                    manual_steps.append("Inspect caller functions to verify if input is bounded before being passed here.")
                elif rule_id == "ADV-TOCTOU-001":
                    assumptions.append("Filesystem target path resides in a shared or writable directory accessible to untrusted users.")
                    unknowns.append("Filesystem permissions and directory ownership at runtime are unknown.")
                    manual_steps.append("Verify whether the target directory has restricted permissions (e.g., sticky bit / restricted DACL).")
                elif rule_id == "ADV-LEAK-001":
                    assumptions.append("Caller function does not assume ownership of the opened file/resource handle.")
                    unknowns.append("Global cleanup hooks (e.g., atexit) or long-lived process lifecycle semantics are unknown.")
                    manual_steps.append("Verify whether resource ownership is transferred across architectural boundaries.")

        elif finding.analyzer_source == AnalyzerSource.REGEX:
            # Regex rules on their own can never be CONFIRMED (inherently ambiguous)
            if not is_needs_review:
                finding.analysis_status = AnalysisStatus.LIKELY
                limitations.append("Finding was matched via lexical pattern matching without AST semantic verification.")
                assumptions.append("Assumes matched token is active code and not dead code or macro parameter.")
                manual_steps.append("Review AST structure to verify data reaches the dangerous API.")

        # Assign final status
        if is_needs_review:
            finding.analysis_status = AnalysisStatus.NEEDS_REVIEW
            # Slightly calibrate confidence when unknown blockers exist
            finding.confidence = min(finding.confidence, 0.70)
        elif is_confirmed and finding.confidence >= 0.88:
            finding.analysis_status = AnalysisStatus.CONFIRMED
        else:
            finding.analysis_status = AnalysisStatus.LIKELY

        # Attach metadata
        finding.assumptions.extend(assumptions)
        finding.unknowns.extend(unknowns)
        finding.analysis_limitations.extend(limitations)
        finding.recommended_manual_verification.extend(manual_steps)

        # Store pristine deterministic result
        finding.deterministic_result = {
            "rule_id": finding.rule_id,
            "cwe": finding.cwe,
            "status": finding.analysis_status.value,
            "confidence": finding.confidence,
            "analyzer_source": finding.analyzer_source.value,
            "evidence_count": len(finding.evidence),
        }
