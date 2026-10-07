"""
PathState and Lattice Domains for Path-Sensitive Analysis.
Tracks pointer nullness, allocation lifecycle, variable initialization,
resource ownership, taint status, and numeric intervals along individual CFG paths.
"""

from enum import Enum
from typing import Dict, Set, Optional, Any, List
from app.engine.range.interval import Interval


class Nullness(str, Enum):
    NON_NULL = "NON_NULL"
    NULL = "NULL"
    UNCHECKED_ALLOCATION = "UNCHECKED_ALLOCATION"
    POTENTIALLY_NULL = "POTENTIALLY_NULL"
    UNKNOWN = "UNKNOWN"


class Lifetime(str, Enum):
    UNALLOCATED = "UNALLOCATED"
    ALLOCATED = "ALLOCATED"
    FREED = "FREED"
    POTENTIALLY_FREED = "POTENTIALLY_FREED"


class InitStatus(str, Enum):
    UNINITIALIZED = "UNINITIALIZED"
    INITIALIZED = "INITIALIZED"
    POTENTIALLY_UNINITIALIZED = "POTENTIALLY_UNINITIALIZED"


class ResourceStatus(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    POTENTIALLY_LEAKED = "POTENTIALLY_LEAKED"


class TaintStatus(str, Enum):
    CLEAN = "CLEAN"
    TAINTED = "TAINTED"
    UNKNOWN = "UNKNOWN"


class PointerState:
    """Tracks nullness and allocation lifecycle for a pointer variable."""
    def __init__(
        self,
        nullness: Nullness = Nullness.UNKNOWN,
        lifetime: Lifetime = Lifetime.UNALLOCATED,
        alloc_line: Optional[int] = None,
        free_line: Optional[int] = None,
    ):
        self.nullness: Nullness = nullness
        self.lifetime: Lifetime = lifetime
        self.alloc_line: Optional[int] = alloc_line
        self.free_line: Optional[int] = free_line

    def copy(self) -> "PointerState":
        return PointerState(
            nullness=self.nullness,
            lifetime=self.lifetime,
            alloc_line=self.alloc_line,
            free_line=self.free_line
        )

    def join(self, other: "PointerState") -> "PointerState":
        # Nullness join
        if self.nullness == other.nullness:
            joined_null = self.nullness
        elif {self.nullness, other.nullness} == {Nullness.NULL, Nullness.NON_NULL}:
            joined_null = Nullness.POTENTIALLY_NULL
        elif Nullness.UNCHECKED_ALLOCATION in (self.nullness, other.nullness):
            joined_null = Nullness.UNCHECKED_ALLOCATION
        else:
            joined_null = Nullness.POTENTIALLY_NULL

        # Lifetime join
        if self.lifetime == other.lifetime:
            joined_life = self.lifetime
        elif {self.lifetime, other.lifetime} == {Lifetime.ALLOCATED, Lifetime.FREED}:
            joined_life = Lifetime.POTENTIALLY_FREED
        elif Lifetime.POTENTIALLY_FREED in (self.lifetime, other.lifetime):
            joined_life = Lifetime.POTENTIALLY_FREED
        else:
            joined_life = Lifetime.ALLOCATED if (self.lifetime == Lifetime.ALLOCATED or other.lifetime == Lifetime.ALLOCATED) else Lifetime.UNALLOCATED

        return PointerState(
            nullness=joined_null,
            lifetime=joined_life,
            alloc_line=self.alloc_line or other.alloc_line,
            free_line=self.free_line or other.free_line
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PointerState):
            return False
        return (
            self.nullness == other.nullness and
            self.lifetime == other.lifetime and
            self.alloc_line == other.alloc_line and
            self.free_line == other.free_line
        )

    def __repr__(self) -> str:
        return f"Ptr({self.nullness.value}, {self.lifetime.value})"


class VarState:
    """Tracks initialization, range interval, and taint for scalar variables."""
    def __init__(
        self,
        init_status: InitStatus = InitStatus.UNINITIALIZED,
        interval: Optional[Interval] = None,
        taint: TaintStatus = TaintStatus.CLEAN,
    ):
        self.init_status: InitStatus = init_status
        self.interval: Interval = interval if interval is not None else Interval.top()
        self.taint: TaintStatus = taint

    def copy(self) -> "VarState":
        return VarState(
            init_status=self.init_status,
            interval=Interval(self.interval.min, self.interval.max),
            taint=self.taint
        )

    def join(self, other: "VarState") -> "VarState":
        # Init status join
        if self.init_status == other.init_status:
            joined_init = self.init_status
        else:
            joined_init = InitStatus.POTENTIALLY_UNINITIALIZED

        # Range interval join (union)
        joined_interval = self.interval.union(other.interval)

        # Taint join
        if self.taint == TaintStatus.TAINTED or other.taint == TaintStatus.TAINTED:
            joined_taint = TaintStatus.TAINTED
        elif self.taint == TaintStatus.UNKNOWN or other.taint == TaintStatus.UNKNOWN:
            joined_taint = TaintStatus.UNKNOWN
        else:
            joined_taint = TaintStatus.CLEAN

        return VarState(init_status=joined_init, interval=joined_interval, taint=joined_taint)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VarState):
            return False
        return (
            self.init_status == other.init_status and
            self.interval == other.interval and
            self.taint == other.taint
        )

    def __repr__(self) -> str:
        return f"Var({self.init_status.value}, {self.interval}, {self.taint.value})"


class ResourceState:
    """Tracks resource handles (FILE*, sockets, file descriptors)."""
    def __init__(self, status: ResourceStatus = ResourceStatus.CLOSED, open_line: Optional[int] = None):
        self.status: ResourceStatus = status
        self.open_line: Optional[int] = open_line

    def copy(self) -> "ResourceState":
        return ResourceState(status=self.status, open_line=self.open_line)

    def join(self, other: "ResourceState") -> "ResourceState":
        if self.status == other.status:
            joined_status = self.status
        else:
            joined_status = ResourceStatus.POTENTIALLY_LEAKED
        return ResourceState(status=joined_status, open_line=self.open_line or other.open_line)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ResourceState):
            return False
        return self.status == other.status and self.open_line == other.open_line


class PathState:
    """
    Complete state of the program along a specific execution path.
    """

    def __init__(self):
        self.pointers: Dict[str, PointerState] = {}
        self.variables: Dict[str, VarState] = {}
        self.resources: Dict[str, ResourceState] = {}
        self.aliases: Dict[str, Set[str]] = {}
        self.path_trace: List[str] = []

    def copy(self) -> "PathState":
        clone = PathState()
        clone.pointers = {k: v.copy() for k, v in self.pointers.items()}
        clone.variables = {k: v.copy() for k, v in self.variables.items()}
        clone.resources = {k: v.copy() for k, v in self.resources.items()}
        clone.aliases = {k: set(v) for k, v in self.aliases.items()}
        clone.path_trace = list(self.path_trace)
        return clone

    def join(self, other: "PathState") -> "PathState":
        joined = PathState()

        # Join pointers
        all_ptrs = set(self.pointers.keys()) | set(other.pointers.keys())
        for p in all_ptrs:
            p1 = self.pointers.get(p)
            p2 = other.pointers.get(p)
            if p1 and p2:
                joined.pointers[p] = p1.join(p2)
            elif p1:
                joined.pointers[p] = p1.copy()
            elif p2:
                joined.pointers[p] = p2.copy()

        # Join variables
        all_vars = set(self.variables.keys()) | set(other.variables.keys())
        for v in all_vars:
            v1 = self.variables.get(v)
            v2 = other.variables.get(v)
            if v1 and v2:
                joined.variables[v] = v1.join(v2)
            elif v1:
                joined.variables[v] = v1.copy()
            elif v2:
                joined.variables[v] = v2.copy()

        # Join resources
        all_res = set(self.resources.keys()) | set(other.resources.keys())
        for r in all_res:
            r1 = self.resources.get(r)
            r2 = other.resources.get(r)
            if r1 and r2:
                joined.resources[r] = r1.join(r2)
            elif r1:
                joined.resources[r] = r1.copy()
            elif r2:
                joined.resources[r] = r2.copy()

        # Join aliases
        all_aliases = set(self.aliases.keys()) | set(other.aliases.keys())
        for a in all_aliases:
            joined.aliases[a] = self.aliases.get(a, set()) | other.aliases.get(a, set())

        joined.path_trace = list(self.path_trace)
        return joined

    def add_alias(self, var1: str, var2: str):
        if var1 not in self.aliases:
            self.aliases[var1] = set()
        if var2 not in self.aliases:
            self.aliases[var2] = set()
        self.aliases[var1].add(var2)
        self.aliases[var2].add(var1)

    def get_all_aliases(self, var: str) -> Set[str]:
        return self.aliases.get(var, set()) | {var}
