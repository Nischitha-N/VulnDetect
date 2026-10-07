"""
Abstract Allocation Identity and Heap Lifecycle State for Inter-Procedural Analysis.
Provides stable object identities across pointer assignments and function call boundaries.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class AllocObject:
    """
    Stable abstract identity for a memory allocation site.
    Distinguishes independent allocations regardless of variable naming.
    """
    alloc_id: str
    file_path: str
    function_name: str
    line: int
    column: int
    allocator: str


@dataclass
class AllocState:
    """
    Tracks the lifecycle state of an individual abstract allocation object.
    """
    status: str = "ALLOCATED"  # "ALLOCATED" | "FREED"
    alloc_line: int = 0
    alloc_column: int = 0
    free_line: Optional[int] = None
    free_column: Optional[int] = None
    freed_via: Optional[str] = None
