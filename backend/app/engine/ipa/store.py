"""
Project-Level Function Summary Store for Inter-Procedural Static Analysis.
Maintains persistent FunctionSummary objects across multiple source files / translation units.
Distinguishes static (file-scoped) and global symbols, preventing unsafe cross-file leakage
and conservatively handling global symbol collisions.
"""

from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Tuple
from app.engine.ipa.summary import FunctionSummary


def _normalize_path(path: str) -> str:
    """Normalize file paths for consistent dictionary lookup across platforms."""
    return path.replace("\\", "/").strip()


@dataclass(frozen=True)
class FunctionId:
    """Stable project-wide identifier for a function definition."""
    file_path: str
    function_name: str

    def __str__(self) -> str:
        return f"{_normalize_path(self.file_path)}::{self.function_name}"


class ProjectSummaryStore:
    """
    Project-level summary store that persists FunctionSummary objects across files.
    
    Symbol scoping rules:
    1. Static functions ('static void f()') are strictly file-scoped:
       registered only under 'file_path::f' and never exposed globally.
    2. Non-static functions ('void f()') are registered globally and locally.
    3. Global symbol collisions: If multiple files define non-static functions
       with identical names, cross-file resolution is marked ambiguous (None)
       to avoid unsafe guesses.
    4. Callers always resolve local functions first (shadowing globals of same name).
    """

    def __init__(self):
        # Scoped key: "file_path::function_name" -> FunctionSummary
        self._scoped: Dict[str, FunctionSummary] = {}
        # Global symbol table: function_name -> list of (file_path, FunctionSummary)
        self._globals: Dict[str, List[Tuple[str, FunctionSummary]]] = {}
        # Static functions per file: file_path -> set of function_name
        self._static_funcs: Dict[str, Set[str]] = {}

    def add_summary(self, summary: FunctionSummary, is_static: bool = False):
        """Register a function summary into the project store."""
        norm_path = _normalize_path(summary.file_path)
        scoped_key = f"{norm_path}::{summary.function_name}"
        self._scoped[scoped_key] = summary

        if is_static:
            self._static_funcs.setdefault(norm_path, set()).add(summary.function_name)
        else:
            self._globals.setdefault(summary.function_name, []).append((norm_path, summary))

    def get_scoped(self, file_path: str, func_name: str) -> Optional[FunctionSummary]:
        """Retrieve a function summary strictly within the specified file scope."""
        norm_path = _normalize_path(file_path)
        return self._scoped.get(f"{norm_path}::{func_name}")

    def resolve_callee(self, caller_file_path: str, callee_name: str) -> Optional[FunctionSummary]:
        """
        Resolves a call to callee_name made from caller_file_path:
        1. Local scope: Check if defined in the caller's translation unit.
        2. Global scope: Check if defined globally and unambiguously in another file.
        3. Returns None if unresolved or ambiguous due to collision.
        """
        norm_path = _normalize_path(caller_file_path)

        # 1. Local scope lookup
        local_sum = self.get_scoped(norm_path, callee_name)
        if local_sum is not None:
            return local_sum

        # 2. Global scope lookup
        if callee_name in self._globals:
            entries = self._globals[callee_name]
            if len(entries) == 1:
                return entries[0][1]
            # Multiple global definitions: collision, conservatively unresolved
            return None

        return None

    def get_accessible_summaries(self, caller_file_path: str) -> Dict[str, FunctionSummary]:
        """
        Returns a dictionary of {func_name: FunctionSummary} accessible from caller_file_path.
        Includes all unambiguous global functions plus all functions defined locally in caller_file_path.
        Local definitions shadow global definitions of the same name.
        """
        norm_path = _normalize_path(caller_file_path)
        accessible: Dict[str, FunctionSummary] = {}

        # 1. Add all unambiguous global summaries
        for name, entries in self._globals.items():
            if len(entries) == 1:
                accessible[name] = entries[0][1]

        # 2. Add local summaries (shadowing globals of the same name)
        prefix = f"{norm_path}::"
        for key, summary in self._scoped.items():
            if key.startswith(prefix):
                accessible[summary.function_name] = summary

        return accessible

    def clear(self):
        """Reset the store completely."""
        self._scoped.clear()
        self._globals.clear()
        self._static_funcs.clear()
