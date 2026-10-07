"""
Function Summary Data Models for Inter-Procedural Static Analysis.
Captures callee side-effects, taint origins, memory/resource lifecycles, and sink destinations.
"""

from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Tuple, Any


@dataclass
class ParameterEffect:
    param_idx: int
    param_name: str
    is_freed: bool = False
    is_closed: bool = False
    is_modified: bool = False
    is_passed_to_sink: bool = False
    sink_name: Optional[str] = None
    sink_cwe: Optional[str] = None
    is_sanitized: bool = False
    sanitizer_type: Optional[str] = None


@dataclass
class FunctionSummary:
    """
    Compact semantic summary of a function's observable side-effects and return contracts.
    """
    function_name: str
    file_path: str = ""
    param_names: List[str] = field(default_factory=list)

    # Taint contracts
    return_is_source: bool = False
    return_source_desc: str = ""
    return_tainted_from_params: Set[int] = field(default_factory=set)  # Indices of params that taint return
    sink_calls: List[Tuple[str, int, str]] = field(default_factory=list)  # (sink_name, param_idx, cwe)
    sanitized_params: Dict[int, str] = field(default_factory=dict)  # param_idx -> sanitizer_type
    is_sanitizer: bool = False

    # Memory & Pointer Lifecycle
    freed_params: Set[int] = field(default_factory=set)  # Indices of params freed by this function
    return_allocated_memory: bool = False
    return_can_be_null: bool = False

    # Resource Lifecycle
    closed_resource_params: Set[int] = field(default_factory=set)
    return_resource_acquired: Optional[str] = None  # e.g. "FILE*", "socket"

    # Out-parameters & Effects
    modified_params: Set[int] = field(default_factory=set)
    may_throw_cpp: bool = False
    is_external: bool = False  # True for library functions without visible source

    def __repr__(self) -> str:
        tags = []
        if self.return_is_source:
            tags.append(f"Source({self.return_source_desc})")
        if self.freed_params:
            tags.append(f"FreesParams({list(self.freed_params)})")
        if self.sink_calls:
            tags.append(f"SinkCalls({self.sink_calls})")
        if self.return_can_be_null:
            tags.append("NullableReturn")
        if self.is_external:
            tags.append("External")
        tag_str = f" [{', '.join(tags)}]" if tags else ""
        return f"FunctionSummary({self.function_name}({len(self.param_names)} params){tag_str})"
