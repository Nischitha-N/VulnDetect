"""
Abstract Interval Domain for Static Range Analysis.
Handles integer intervals [min, max] with +/- infinity, arithmetic operations,
set operations, and C standard type limits.
"""

import math
from typing import Optional, Union, Tuple

INF = math.inf

# Standard 32-bit / 64-bit integer limits
INT8_MIN = -128
INT8_MAX = 127
UINT8_MAX = 255

INT16_MIN = -32768
INT16_MAX = 32767
UINT16_MAX = 65535

INT32_MIN = -2147483648
INT32_MAX = 2147483647
UINT32_MAX = 4294967295

INT64_MIN = -9223372036854775808
INT64_MAX = 9223372036854775807
UINT64_MAX = 18446744073709551615

SIZE_T_MAX = UINT64_MAX


class Interval:
    """
    Represents an integer interval [min_val, max_val].
    min_val can be -inf or an integer.
    max_val can be +inf or an integer.
    """

    def __init__(self, min_val: Union[int, float], max_val: Union[int, float]):
        # Normalize -inf, +inf
        if min_val is None or min_val == -INF:
            self.min: Union[int, float] = -INF
        elif min_val == INF:
            self.min: Union[int, float] = INF
        else:
            self.min: Union[int, float] = int(min_val)

        if max_val is None or max_val == INF:
            self.max: Union[int, float] = INF
        elif max_val == -INF:
            self.max: Union[int, float] = -INF
        else:
            self.max: Union[int, float] = int(max_val)

        # Check for empty / inverted intervals
        if self.min > self.max:
            # Degenerate to empty / bottom representation
            self.min = INF
            self.max = -INF

    @classmethod
    def exact(cls, val: int) -> "Interval":
        """Create exact point interval [val, val]."""
        return cls(val, val)

    @classmethod
    def top(cls) -> "Interval":
        """Unconstrained range [-inf, +inf]."""
        return cls(-INF, INF)

    @classmethod
    def bottom(cls) -> "Interval":
        """Empty / unreachable range."""
        return cls(INF, -INF)

    @classmethod
    def non_negative(cls) -> "Interval":
        """Range [0, +inf]."""
        return cls(0, INF)

    @classmethod
    def positive(cls) -> "Interval":
        """Range [1, +inf]."""
        return cls(1, INF)

    @property
    def is_bottom(self) -> bool:
        """True if the interval is empty (unreachable)."""
        return self.min > self.max

    @property
    def is_top(self) -> bool:
        """True if unconstrained [-inf, +inf]."""
        return self.min == -INF and self.max == INF

    @property
    def is_constant(self) -> bool:
        """True if interval represents a single known constant [c, c]."""
        return not self.is_bottom and self.min == self.max and self.min != -INF and self.min != INF

    @property
    def constant_value(self) -> Optional[int]:
        """Returns the constant value if is_constant is True, else None."""
        if self.is_constant:
            return int(self.min)
        return None

    def __repr__(self) -> str:
        if self.is_bottom:
            return "⊥ (empty)"
        min_str = "-∞" if self.min == -INF else str(self.min)
        max_str = "+∞" if self.max == INF else str(self.max)
        return f"[{min_str}, {max_str}]"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Interval):
            return False
        if self.is_bottom and other.is_bottom:
            return True
        return self.min == other.min and self.max == other.max

    # ─── Arithmetic Operations ───────────────────────────────────────────────

    def add(self, other: "Interval") -> "Interval":
        if self.is_bottom or other.is_bottom:
            return Interval.bottom()
        new_min = -INF if self.min == -INF or other.min == -INF else self.min + other.min
        new_max = INF if self.max == INF or other.max == INF else self.max + other.max
        return Interval(new_min, new_max)

    def sub(self, other: "Interval") -> "Interval":
        if self.is_bottom or other.is_bottom:
            return Interval.bottom()
        new_min = -INF if self.min == -INF or other.max == INF else self.min - other.max
        new_max = INF if self.max == INF or other.min == -INF else self.max - other.min
        return Interval(new_min, new_max)

    def mul(self, other: "Interval") -> "Interval":
        if self.is_bottom or other.is_bottom:
            return Interval.bottom()
        
        # Handle zeros specifically
        if self.is_constant and self.constant_value == 0:
            return Interval.exact(0)
        if other.is_constant and other.constant_value == 0:
            return Interval.exact(0)

        corners = []
        for a in (self.min, self.max):
            for b in (other.min, other.max):
                if a == 0 or b == 0:
                    corners.append(0)
                elif a == -INF or a == INF or b == -INF or b == INF:
                    sign = (1 if a > 0 else -1) * (1 if b > 0 else -1)
                    corners.append(INF if sign > 0 else -INF)
                else:
                    corners.append(a * b)

        return Interval(min(corners), max(corners))

    def div(self, other: "Interval") -> "Interval":
        if self.is_bottom or other.is_bottom:
            return Interval.bottom()
        
        # Avoid division by zero
        if other.is_constant and other.constant_value == 0:
            return Interval.bottom()

        # If denominator can be zero, remove 0 or return unconstrained
        denom_min = other.min
        denom_max = other.max

        if denom_min <= 0 <= denom_max:
            # Denominator contains 0
            if denom_min == 0 and denom_max == 0:
                return Interval.bottom()
            # General safe bound
            return Interval.top()

        corners = []
        for a in (self.min, self.max):
            for b in (denom_min, denom_max):
                if b == 0:
                    continue
                if a == -INF or a == INF:
                    sign = (1 if a > 0 else -1) * (1 if b > 0 else -1)
                    corners.append(INF if sign > 0 else -INF)
                else:
                    corners.append(int(a / b))

        if not corners:
            return Interval.top()
        return Interval(min(corners), max(corners))

    def mod(self, other: "Interval") -> "Interval":
        if self.is_bottom or other.is_bottom:
            return Interval.bottom()
        if other.is_constant and other.constant_value is not None:
            c = abs(other.constant_value)
            if c == 0:
                return Interval.bottom()
            if self.min >= 0:
                return Interval(0, min(self.max, c - 1))
            return Interval(-(c - 1), c - 1)
        return Interval.top()

    def neg(self) -> "Interval":
        if self.is_bottom:
            return Interval.bottom()
        new_min = -INF if self.max == INF else -self.max
        new_max = INF if self.min == -INF else -self.min
        return Interval(new_min, new_max)

    # ─── Set / Domain Operations ─────────────────────────────────────────────

    def union(self, other: "Interval") -> "Interval":
        """Combine ranges across multiple branches (join operator)."""
        if self.is_bottom:
            return other
        if other.is_bottom:
            return self
        new_min = min(self.min, other.min)
        new_max = max(self.max, other.max)
        return Interval(new_min, new_max)

    def intersect(self, other: "Interval") -> "Interval":
        """Refine range based on condition (meet operator)."""
        if self.is_bottom or other.is_bottom:
            return Interval.bottom()
        new_min = max(self.min, other.min)
        new_max = min(self.max, other.max)
        if new_min > new_max:
            return Interval.bottom()
        return Interval(new_min, new_max)

    def widen(self, other: "Interval") -> "Interval":
        """Widening operator to ensure loop termination in static analysis."""
        if self.is_bottom:
            return other
        if other.is_bottom:
            return self
        new_min = -INF if other.min < self.min else self.min
        new_max = INF if other.max > self.max else self.max
        return Interval(new_min, new_max)

    # ─── Safety & Bounds Predicates ──────────────────────────────────────────

    def is_definitely_positive(self) -> bool:
        """min > 0"""
        return not self.is_bottom and self.min > 0

    def is_definitely_non_negative(self) -> bool:
        """min >= 0"""
        return not self.is_bottom and self.min >= 0

    def could_be_negative(self) -> bool:
        """min < 0"""
        return not self.is_bottom and self.min < 0

    def is_definitely_negative(self) -> bool:
        """max < 0"""
        return not self.is_bottom and self.max < 0

    def is_definitely_in_bounds(self, low: int, high: int) -> bool:
        """min >= low and max <= high"""
        return not self.is_bottom and self.min >= low and self.max <= high

    def is_definitely_out_of_bounds(self, low: int, high: int) -> bool:
        """max < low or min > high"""
        return not self.is_bottom and (self.max < low or self.min > high)

    def could_exceed(self, limit: int) -> bool:
        """max > limit"""
        return not self.is_bottom and self.max > limit

    def is_definitely_exceeding(self, limit: int) -> bool:
        """min > limit"""
        return not self.is_bottom and self.min > limit

    def could_overflow_signed_32(self) -> bool:
        return not self.is_bottom and (self.max > INT32_MAX or self.min < INT32_MIN)

    def could_overflow_unsigned_32(self) -> bool:
        return not self.is_bottom and (self.max > UINT32_MAX or self.min < 0)


class CTypeRange:
    """Helper for C/C++ type boundaries and standard sizes."""

    TYPE_RANGES = {
        "char": Interval(INT8_MIN, INT8_MAX),
        "signed char": Interval(INT8_MIN, INT8_MAX),
        "unsigned char": Interval(0, UINT8_MAX),
        "uint8_t": Interval(0, UINT8_MAX),
        "int8_t": Interval(INT8_MIN, INT8_MAX),
        
        "short": Interval(INT16_MIN, INT16_MAX),
        "short int": Interval(INT16_MIN, INT16_MAX),
        "signed short": Interval(INT16_MIN, INT16_MAX),
        "unsigned short": Interval(0, UINT16_MAX),
        "uint16_t": Interval(0, UINT16_MAX),
        "int16_t": Interval(INT16_MIN, INT16_MAX),
        
        "int": Interval(INT32_MIN, INT32_MAX),
        "signed int": Interval(INT32_MIN, INT32_MAX),
        "signed": Interval(INT32_MIN, INT32_MAX),
        "unsigned": Interval(0, UINT32_MAX),
        "unsigned int": Interval(0, UINT32_MAX),
        "uint32_t": Interval(0, UINT32_MAX),
        "int32_t": Interval(INT32_MIN, INT32_MAX),
        
        "long": Interval(INT64_MIN, INT64_MAX),
        "signed long": Interval(INT64_MIN, INT64_MAX),
        "unsigned long": Interval(0, UINT64_MAX),
        "long long": Interval(INT64_MIN, INT64_MAX),
        "unsigned long long": Interval(0, UINT64_MAX),
        "size_t": Interval(0, SIZE_T_MAX),
        "ssize_t": Interval(INT64_MIN, INT64_MAX),
        "uint64_t": Interval(0, UINT64_MAX),
        "int64_t": Interval(INT64_MIN, INT64_MAX),
    }

    SIZEOF_MAP = {
        "char": 1,
        "unsigned char": 1,
        "int8_t": 1,
        "uint8_t": 1,
        "bool": 1,
        "short": 2,
        "unsigned short": 2,
        "int16_t": 2,
        "uint16_t": 2,
        "int": 4,
        "unsigned int": 4,
        "unsigned": 4,
        "int32_t": 4,
        "uint32_t": 4,
        "float": 4,
        "long": 8,
        "unsigned long": 8,
        "long long": 8,
        "unsigned long long": 8,
        "int64_t": 8,
        "uint64_t": 8,
        "double": 8,
        "size_t": 8,
        "ssize_t": 8,
        "uintptr_t": 8,
        "intptr_t": 8,
        "void*": 8,
        "char*": 8,
        "int*": 8,
    }

    @staticmethod
    def get_type_interval(type_str: str) -> Interval:
        cleaned = " ".join(type_str.replace("const", "").replace("volatile", "").split()).strip()
        if cleaned in CTypeRange.TYPE_RANGES:
            return CTypeRange.TYPE_RANGES[cleaned]
        if "unsigned" in cleaned or cleaned.startswith("uint") or "size_t" in cleaned:
            return Interval(0, UINT32_MAX)
        if "*" in cleaned:
            return Interval(0, UINT64_MAX)  # pointer addresses
        return Interval(INT32_MIN, INT32_MAX)

    @staticmethod
    def is_unsigned_type(type_str: str) -> bool:
        cleaned = type_str.lower()
        return "unsigned" in cleaned or cleaned.startswith("uint") or "size_t" in cleaned

    @staticmethod
    def get_sizeof(type_str: str) -> int:
        cleaned = " ".join(type_str.replace("const", "").replace("volatile", "").split()).strip()
        if cleaned in CTypeRange.SIZEOF_MAP:
            return CTypeRange.SIZEOF_MAP[cleaned]
        if "*" in cleaned:
            return 8
        return 4
