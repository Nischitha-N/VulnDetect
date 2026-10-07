"""
Configurable Specifications and Data Models for Semantic Taint Analysis.
Defines Taint Sources, Sinks, Sanitizers, and the TaintState domain.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any
from app.engine.base import Severity


class TaintState(str, Enum):
    DEFINITELY_TAINTED = "DEFINITELY_TAINTED"
    POSSIBLY_TAINTED = "POSSIBLY_TAINTED"
    DEFINITELY_SANITIZED = "DEFINITELY_SANITIZED"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"


@dataclass
class TaintSourceSpec:
    name: str
    tainted_args: List[int] = field(default_factory=list)
    returns_tainted: bool = False
    is_variable: bool = False
    cwe: str = "CWE-20"
    description: str = "Untrusted input source"


@dataclass
class TaintSinkSpec:
    name: str
    sink_args: List[int] = field(default_factory=lambda: [0])
    cwe: str = "CWE-78"
    vuln_type: str = "Command Injection"
    severity: Severity = Severity.HIGH
    risk_score: float = 0.85
    message: str = "Untrusted input flows into critical sink."
    remediation: str = "Sanitize and validate input before use in this API."


@dataclass
class TaintSanitizerSpec:
    name: str
    sanitized_args: List[int] = field(default_factory=lambda: [0])
    returns_sanitized: bool = False
    sanitizer_type: str = "general"  # path, command, sql, format, integer, general
    is_trusted: bool = True  # True if known trusted library/kernel sanitizer, False if custom/unverified


class TaintConfigManager:
    """Manages configurable Sources, Sinks, and Sanitizers."""

    DEFAULT_SOURCES: Dict[str, TaintSourceSpec] = {
        # Environment & CLI
        "getenv": TaintSourceSpec("getenv", returns_tainted=True, cwe="CWE-20", description="Environment variable from getenv()"),
        "argv": TaintSourceSpec("argv", is_variable=True, cwe="CWE-20", description="Command line argument array 'argv'"),
        "argc": TaintSourceSpec("argc", is_variable=True, cwe="CWE-20", description="Command line argument count"),
        
        # Standard input & Streams
        "gets": TaintSourceSpec("gets", tainted_args=[0], cwe="CWE-242", description="Unbounded user input from gets()"),
        "fgets": TaintSourceSpec("fgets", tainted_args=[0], cwe="CWE-20", description="Stream input from fgets()"),
        "getchar": TaintSourceSpec("getchar", returns_tainted=True, cwe="CWE-20", description="Character input from getchar()"),
        "fgetc": TaintSourceSpec("fgetc", returns_tainted=True, cwe="CWE-20", description="Character input from fgetc()"),
        "readline": TaintSourceSpec("readline", returns_tainted=True, cwe="CWE-20", description="Line input from readline()"),
        
        # Formatted input
        "scanf": TaintSourceSpec("scanf", tainted_args=[1, 2, 3, 4], cwe="CWE-20", description="Formatted input from scanf()"),
        "sscanf": TaintSourceSpec("sscanf", tainted_args=[2, 3, 4], cwe="CWE-20", description="Parsed string from sscanf()"),
        "fscanf": TaintSourceSpec("fscanf", tainted_args=[2, 3, 4], cwe="CWE-20", description="File formatted input from fscanf()"),
        
        # File & Network descriptors
        "read": TaintSourceSpec("read", tainted_args=[1], cwe="CWE-20", description="File descriptor read buffer"),
        "fread": TaintSourceSpec("fread", tainted_args=[0], cwe="CWE-20", description="Stream fread buffer"),
        "recv": TaintSourceSpec("recv", tainted_args=[1], cwe="CWE-20", description="Network socket input from recv()"),
        "recvfrom": TaintSourceSpec("recvfrom", tainted_args=[1], cwe="CWE-20", description="Network packet input from recvfrom()"),
        "recvmsg": TaintSourceSpec("recvmsg", tainted_args=[1], cwe="CWE-20", description="Socket message input from recvmsg()"),
        
        # Database fetch APIs
        "mysql_fetch_row": TaintSourceSpec("mysql_fetch_row", returns_tainted=True, cwe="CWE-20", description="Database record from mysql_fetch_row()"),
        "sqlite3_column_text": TaintSourceSpec("sqlite3_column_text", returns_tainted=True, cwe="CWE-20", description="Database text from sqlite3_column_text()"),
        "PQgetvalue": TaintSourceSpec("PQgetvalue", returns_tainted=True, cwe="CWE-20", description="PostgreSQL result from PQgetvalue()"),
    }

    DEFAULT_SINKS: Dict[str, TaintSinkSpec] = {
        # Command execution sinks
        "system": TaintSinkSpec("system", sink_args=[0], cwe="CWE-78", vuln_type="Command Injection via system()", severity=Severity.CRITICAL, risk_score=0.95, message="Untrusted input reaches shell command execution sink system().", remediation="Use execve() with structured arguments instead of system()."),
        "popen": TaintSinkSpec("popen", sink_args=[0], cwe="CWE-78", vuln_type="Command Injection via popen()", severity=Severity.CRITICAL, risk_score=0.93, message="Untrusted input reaches pipe command execution sink popen().", remediation="Do not pass unvalidated user input to popen()."),
        "wsystem": TaintSinkSpec("wsystem", sink_args=[0], cwe="CWE-78", vuln_type="Command Injection via wsystem()", severity=Severity.CRITICAL, risk_score=0.95, message="Untrusted wide string reaches wsystem().", remediation="Use CreateProcess with explicit arguments."),
        "execve": TaintSinkSpec("execve", sink_args=[0, 1], cwe="CWE-78", vuln_type="Command Injection via execve()", severity=Severity.HIGH, risk_score=0.88, message="Untrusted binary path or arguments in execve().", remediation="Ensure executable path is fixed and arguments are whitelisted."),
        "execl": TaintSinkSpec("execl", sink_args=[0, 1], cwe="CWE-78", vuln_type="Command Injection via execl()", severity=Severity.HIGH, risk_score=0.88, message="Untrusted command in execl().", remediation="Verify executable path."),
        "execlp": TaintSinkSpec("execlp", sink_args=[0, 1], cwe="CWE-78", vuln_type="Command Injection via execlp()", severity=Severity.HIGH, risk_score=0.88, message="Untrusted command in execlp().", remediation="Verify executable path."),
        "execvp": TaintSinkSpec("execvp", sink_args=[0, 1], cwe="CWE-78", vuln_type="Command Injection via execvp()", severity=Severity.HIGH, risk_score=0.88, message="Untrusted command in execvp().", remediation="Verify executable path."),
        "ShellExecuteA": TaintSinkSpec("ShellExecuteA", sink_args=[1, 2], cwe="CWE-78", vuln_type="Command Injection via ShellExecute", severity=Severity.CRITICAL, risk_score=0.92, message="Untrusted command string passed to ShellExecute.", remediation="Use CreateProcess with strict parameters."),
        "ShellExecuteW": TaintSinkSpec("ShellExecuteW", sink_args=[1, 2], cwe="CWE-78", vuln_type="Command Injection via ShellExecute", severity=Severity.CRITICAL, risk_score=0.92, message="Untrusted command string passed to ShellExecute.", remediation="Use CreateProcess with strict parameters."),

        # Path Traversal & Filesystem sinks
        "fopen": TaintSinkSpec("fopen", sink_args=[0], cwe="CWE-22", vuln_type="Path Traversal via fopen()", severity=Severity.HIGH, risk_score=0.84, message="Untrusted filename passed directly to fopen().", remediation="Canonicalize paths and verify they resolve within an authorized directory sandbox."),
        "open": TaintSinkSpec("open", sink_args=[0], cwe="CWE-22", vuln_type="Path Traversal via open()", severity=Severity.HIGH, risk_score=0.84, message="Untrusted file path passed directly to open().", remediation="Validate path against whitelist before open()."),
        "unlink": TaintSinkSpec("unlink", sink_args=[0], cwe="CWE-22", vuln_type="Arbitrary File Deletion via unlink()", severity=Severity.HIGH, risk_score=0.88, message="Untrusted path passed to file deletion API unlink().", remediation="Verify file path is restricted to a temporary workspace."),
        "remove": TaintSinkSpec("remove", sink_args=[0], cwe="CWE-22", vuln_type="Arbitrary File Deletion via remove()", severity=Severity.HIGH, risk_score=0.88, message="Untrusted path passed to remove().", remediation="Verify file path is restricted to authorized folder."),
        "rename": TaintSinkSpec("rename", sink_args=[0, 1], cwe="CWE-22", vuln_type="Path Traversal via rename()", severity=Severity.HIGH, risk_score=0.82, message="Untrusted path in rename().", remediation="Canonicalize source and target filenames."),
        "chmod": TaintSinkSpec("chmod", sink_args=[0], cwe="CWE-22", vuln_type="Path Traversal via chmod()", severity=Severity.MEDIUM, risk_score=0.75, message="Untrusted path in chmod().", remediation="Verify target file ownership."),

        # Format String sinks
        "printf": TaintSinkSpec("printf", sink_args=[0], cwe="CWE-134", vuln_type="Format String Vulnerability via printf()", severity=Severity.CRITICAL, risk_score=0.94, message="Untrusted user input used as format specifier in printf().", remediation="Always specify a literal format string: printf(\"%s\", input)."),
        "fprintf": TaintSinkSpec("fprintf", sink_args=[1], cwe="CWE-134", vuln_type="Format String Vulnerability via fprintf()", severity=Severity.CRITICAL, risk_score=0.94, message="Untrusted user input used as format specifier in fprintf().", remediation="Always use fprintf(stream, \"%s\", input)."),
        "sprintf": TaintSinkSpec("sprintf", sink_args=[1], cwe="CWE-134", vuln_type="Format String Vulnerability via sprintf()", severity=Severity.CRITICAL, risk_score=0.92, message="Untrusted format string in sprintf().", remediation="Use snprintf(buf, sizeof(buf), \"%s\", input)."),
        "snprintf": TaintSinkSpec("snprintf", sink_args=[2], cwe="CWE-134", vuln_type="Format String Vulnerability via snprintf()", severity=Severity.HIGH, risk_score=0.88, message="Untrusted format string in snprintf().", remediation="Use snprintf(buf, sizeof(buf), \"%s\", input)."),
        "syslog": TaintSinkSpec("syslog", sink_args=[1], cwe="CWE-134", vuln_type="Format String Vulnerability via syslog()", severity=Severity.HIGH, risk_score=0.90, message="Untrusted format string in syslog().", remediation="Use syslog(priority, \"%s\", msg)."),

        # SQL Injection sinks
        "sqlite3_exec": TaintSinkSpec("sqlite3_exec", sink_args=[1], cwe="CWE-89", vuln_type="SQL Injection via sqlite3_exec()", severity=Severity.CRITICAL, risk_score=0.95, message="Untrusted input passed to raw SQL execution sqlite3_exec().", remediation="Use parameterized queries with sqlite3_prepare_v2() and sqlite3_bind_*()."),
        "mysql_query": TaintSinkSpec("mysql_query", sink_args=[1], cwe="CWE-89", vuln_type="SQL Injection via mysql_query()", severity=Severity.CRITICAL, risk_score=0.95, message="Untrusted input concatenated into mysql_query().", remediation="Use prepared statements with mysql_stmt_prepare()."),
        "mysql_real_query": TaintSinkSpec("mysql_real_query", sink_args=[1], cwe="CWE-89", vuln_type="SQL Injection via mysql_real_query()", severity=Severity.CRITICAL, risk_score=0.95, message="Untrusted input concatenated into mysql_real_query().", remediation="Use prepared statements."),
        "PQexec": TaintSinkSpec("PQexec", sink_args=[1], cwe="CWE-89", vuln_type="SQL Injection via PQexec()", severity=Severity.CRITICAL, risk_score=0.95, message="Untrusted query string in PQexec().", remediation="Use PQexecParams() with query parameters."),

        # Unbounded String copy sinks
        "strcpy": TaintSinkSpec("strcpy", sink_args=[1], cwe="CWE-120", vuln_type="Buffer Overflow via strcpy()", severity=Severity.HIGH, risk_score=0.88, message="Untrusted source string flows into unbounded strcpy().", remediation="Use strncpy(dest, src, sizeof(dest)-1) or snprintf()."),
        "strcat": TaintSinkSpec("strcat", sink_args=[1], cwe="CWE-120", vuln_type="Buffer Overflow via strcat()", severity=Severity.HIGH, risk_score=0.85, message="Untrusted source string appended via unbounded strcat().", remediation="Use strncat() with explicit remaining space."),
    }

    DEFAULT_SANITIZERS: Dict[str, TaintSanitizerSpec] = {
        # Path sanitizers
        "canonicalize_file_name": TaintSanitizerSpec("canonicalize_file_name", returns_sanitized=True, sanitizer_type="path", is_trusted=True),
        "realpath": TaintSanitizerSpec("realpath", sanitized_args=[1], returns_sanitized=True, sanitizer_type="path", is_trusted=True),
        "basename": TaintSanitizerSpec("basename", returns_sanitized=True, sanitizer_type="path", is_trusted=True),
        "sanitize_path": TaintSanitizerSpec("sanitize_path", sanitized_args=[0], returns_sanitized=True, sanitizer_type="path", is_trusted=True),
        "validate_filename": TaintSanitizerSpec("validate_filename", sanitized_args=[0], returns_sanitized=True, sanitizer_type="path", is_trusted=True),
        
        # Shell command sanitizers / escapers
        "escape_shell_cmd": TaintSanitizerSpec("escape_shell_cmd", returns_sanitized=True, sanitizer_type="command", is_trusted=True),
        "escape_shell_arg": TaintSanitizerSpec("escape_shell_arg", returns_sanitized=True, sanitizer_type="command", is_trusted=True),
        "sh_quote": TaintSanitizerSpec("sh_quote", returns_sanitized=True, sanitizer_type="command", is_trusted=True),
        "sanitize_cmd": TaintSanitizerSpec("sanitize_cmd", sanitized_args=[0], returns_sanitized=True, sanitizer_type="command", is_trusted=True),
        "escape_shell_metachars": TaintSanitizerSpec("escape_shell_metachars", sanitized_args=[0], returns_sanitized=True, sanitizer_type="command", is_trusted=True),

        # SQL Escapers
        "mysql_real_escape_string": TaintSanitizerSpec("mysql_real_escape_string", sanitized_args=[1], returns_sanitized=True, sanitizer_type="sql", is_trusted=True),
        "sqlite3_mprintf": TaintSanitizerSpec("sqlite3_mprintf", returns_sanitized=True, sanitizer_type="sql", is_trusted=True),
        "PQescapeStringConn": TaintSanitizerSpec("PQescapeStringConn", sanitized_args=[1], returns_sanitized=True, sanitizer_type="sql", is_trusted=True),

        # Type conversion sanitizers (string to integer)
        "atoi": TaintSanitizerSpec("atoi", returns_sanitized=True, sanitizer_type="integer", is_trusted=True),
        "atol": TaintSanitizerSpec("atol", returns_sanitized=True, sanitizer_type="integer", is_trusted=True),
        "strtol": TaintSanitizerSpec("strtol", returns_sanitized=True, sanitizer_type="integer", is_trusted=True),
        "strtoul": TaintSanitizerSpec("strtoul", returns_sanitized=True, sanitizer_type="integer", is_trusted=True),
        "sscanf_d": TaintSanitizerSpec("sscanf_d", sanitized_args=[2], sanitizer_type="integer", is_trusted=True),

        # Generic validation
        "validate_input": TaintSanitizerSpec("validate_input", sanitized_args=[0], returns_sanitized=True, sanitizer_type="general", is_trusted=True),
        "is_valid_input": TaintSanitizerSpec("is_valid_input", sanitized_args=[0], returns_sanitized=True, sanitizer_type="general", is_trusted=True),
    }

    def __init__(
        self,
        custom_sources: Optional[List[str]] = None,
        custom_sinks: Optional[List[str]] = None,
        custom_sanitizers: Optional[List[str]] = None,
    ):
        self.sources: Dict[str, TaintSourceSpec] = dict(self.DEFAULT_SOURCES)
        self.sinks: Dict[str, TaintSinkSpec] = dict(self.DEFAULT_SINKS)
        self.sanitizers: Dict[str, TaintSanitizerSpec] = dict(self.DEFAULT_SANITIZERS)

        if custom_sources:
            for s in custom_sources:
                self.sources[s] = TaintSourceSpec(name=s, returns_tainted=True, tainted_args=[0], description=f"Custom configured source '{s}'")

        if custom_sinks:
            for s in custom_sinks:
                self.sinks[s] = TaintSinkSpec(name=s, sink_args=[0], vuln_type=f"Custom Sink: {s}", message=f"Untrusted input reaches custom configured sink '{s}'.")

        if custom_sanitizers:
            for s in custom_sanitizers:
                # Custom sanitizers default to is_trusted=False unless verified, triggering NEEDS_REVIEW
                self.sanitizers[s] = TaintSanitizerSpec(name=s, sanitized_args=[0], returns_sanitized=True, is_trusted=False)
