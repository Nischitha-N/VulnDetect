"""
C++ Semantic Data Models and Lifecycle Lattices.
Models types, ownership categories, allocation kinds, move lifecycles, and class inheritance.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Set, List, Optional, Any


class CppTypeKind(str, Enum):
    RAW_POINTER = "RAW_POINTER"
    UNIQUE_PTR = "UNIQUE_PTR"
    SHARED_PTR = "SHARED_PTR"
    WEAK_PTR = "WEAK_PTR"
    REFERENCE = "REFERENCE"
    CONTAINER = "CONTAINER"  # vector, string, map, set, list, deque
    ITERATOR = "ITERATOR"
    CLASS_OBJECT = "CLASS_OBJECT"
    PRIMITIVE = "PRIMITIVE"


class AllocKind(str, Enum):
    SCALAR_NEW = "SCALAR_NEW"      # new T
    ARRAY_NEW = "ARRAY_NEW"        # new T[N]
    MALLOC = "MALLOC"              # malloc(N)
    MAKE_UNIQUE = "MAKE_UNIQUE"    # std::make_unique<T>()
    MAKE_SHARED = "MAKE_SHARED"    # std::make_shared<T>()
    STACK = "STACK"                # local stack variable


class CppObjectLifecycle(str, Enum):
    VALID = "VALID"
    MOVED_FROM = "MOVED_FROM"
    DELETED = "DELETED"
    INVALIDATED = "INVALIDATED"
    DANGLING = "DANGLING"


@dataclass
class ClassHierarchy:
    """Represents a C++ class or struct declaration and its polymorphic properties."""
    class_name: str
    base_classes: List[str] = field(default_factory=list)
    virtual_methods: List[str] = field(default_factory=list)
    has_virtual_destructor: bool = False
    has_custom_destructor: bool = False


@dataclass
class CppVariableState:
    """Tracks C++ semantics, allocation style, and lifecycle state for a variable."""
    var_name: str
    type_kind: CppTypeKind = CppTypeKind.PRIMITIVE
    alloc_kind: AllocKind = AllocKind.STACK
    lifecycle: CppObjectLifecycle = CppObjectLifecycle.VALID
    type_name: str = ""
    declared_line: int = 1
    move_line: Optional[int] = None
    delete_line: Optional[int] = None
    container_target: Optional[str] = None  # If iterator or element pointer, references container name
