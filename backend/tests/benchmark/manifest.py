"""
VulnDetect Benchmark Manifest.
Defines annotated C/C++ benchmark fixtures across 11 categories (A to K).
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class BenchmarkFixture:
    name: str
    category: str
    code: str
    is_vulnerable: bool
    cwe: Optional[str] = None
    vulnerability_class: Optional[str] = None
    expected_status: str = "CONFIRMED"  # CONFIRMED, LIKELY, NEEDS_REVIEW, SAFE
    is_cpp: bool = False
    notes: str = ""


BENCHMARK_FIXTURES: List[BenchmarkFixture] = [
    # ─── Category A: Known Vulnerable Programs ────────────────────────────────
    BenchmarkFixture(
        name="A1_direct_command_injection",
        category="A_Known_Vulnerable",
        code="""
        #include <stdlib.h>
        void run_cmd(char *user_input) {
            system(user_input);
        }
        """,
        is_vulnerable=True,
        cwe="CWE-78",
        vulnerability_class="Command Injection",
        expected_status="CONFIRMED",
    ),
    BenchmarkFixture(
        name="A2_unbounded_gets",
        category="A_Known_Vulnerable",
        code="""
        #include <stdio.h>
        void read_data() {
            char buf[64];
            gets(buf);
        }
        """,
        is_vulnerable=True,
        cwe="CWE-242",
        vulnerability_class="Dangerous gets() API",
        expected_status="CONFIRMED",
    ),
    BenchmarkFixture(
        name="A3_use_after_free",
        category="A_Known_Vulnerable",
        code="""
        #include <stdlib.h>
        void process() {
            char *p = malloc(32);
            free(p);
            *p = 'X';
        }
        """,
        is_vulnerable=True,
        cwe="CWE-416",
        vulnerability_class="Use After Free",
        expected_status="CONFIRMED",
    ),
    BenchmarkFixture(
        name="A4_double_free",
        category="A_Known_Vulnerable",
        code="""
        #include <stdlib.h>
        void cleanup() {
            char *p = malloc(16);
            free(p);
            free(p);
        }
        """,
        is_vulnerable=True,
        cwe="CWE-415",
        vulnerability_class="Double Free",
        expected_status="CONFIRMED",
    ),
    BenchmarkFixture(
        name="A5_format_string_attack",
        category="A_Known_Vulnerable",
        code="""
        #include <stdio.h>
        void log_user_msg(char *user_msg) {
            printf(user_msg);
        }
        """,
        is_vulnerable=True,
        cwe="CWE-134",
        vulnerability_class="Format String",
        expected_status="CONFIRMED",
    ),

    # ─── Category B: Equivalent Safe Programs ─────────────────────────────────
    BenchmarkFixture(
        name="B1_safe_snprintf_bounded",
        category="B_Equivalent_Safe",
        code="""
        #include <stdio.h>
        void safe_copy(const char *src) {
            char dest[32];
            snprintf(dest, sizeof(dest), "%s", src);
        }
        """,
        is_vulnerable=False,
        expected_status="SAFE",
    ),
    BenchmarkFixture(
        name="B2_safe_literal_printf",
        category="B_Equivalent_Safe",
        code="""
        #include <stdio.h>
        void print_status(int count) {
            printf("Processing count: %d\\n", count);
        }
        """,
        is_vulnerable=False,
        expected_status="SAFE",
    ),
    BenchmarkFixture(
        name="B3_safe_checked_null_guard",
        category="B_Equivalent_Safe",
        code="""
        #include <stdlib.h>
        void safe_deref(char *p) {
            if (p == NULL)
                return;
            *p = 'A';
        }
        """,
        is_vulnerable=False,
        expected_status="SAFE",
    ),
    BenchmarkFixture(
        name="B4_safe_free_null_pointer_cleanup",
        category="B_Equivalent_Safe",
        code="""
        #include <stdlib.h>
        void safe_pointer_cleanup(char *p) {
            if (p == NULL)
                return;
            free(p);
            p = NULL;
        }
        """,
        is_vulnerable=False,
        expected_status="SAFE",
    ),
    BenchmarkFixture(
        name="B5_safe_independent_pointer_lifecycle",
        category="B_Equivalent_Safe",
        code="""
        #include <stdlib.h>
        void safe_two_pointers(void) {
            char *p;
            char *q;
            p = (char *)malloc(16);
            q = (char *)malloc(16);
            if (p != NULL && q != NULL) {
                free(q);
                p[0] = 'Z';
                free(p);
            }
        }
        """,
        is_vulnerable=False,
        expected_status="SAFE",
    ),

    # ─── Category C: Near-Miss Programs ───────────────────────────────────────
    BenchmarkFixture(
        name="C1_near_miss_exact_bound_check",
        category="C_Near_Miss",
        code="""
        void safe_index(int i) {
            int arr[10];
            if (i >= 0 && i < 10) {
                arr[i] = 42;
            }
        }
        """,
        is_vulnerable=False,
        expected_status="SAFE",
    ),
    BenchmarkFixture(
        name="C2_near_miss_off_by_one_vulnerable",
        category="C_Near_Miss",
        code="""
        void off_by_one_index(int i) {
            int arr[10];
            if (i >= 0 && i <= 10) {
                arr[i] = 42;
            }
        }
        """,
        is_vulnerable=True,
        cwe="CWE-125",
        vulnerability_class="Out of Bounds Index",
        expected_status="LIKELY",
    ),

    # ─── Category D: False-Positive Traps ─────────────────────────────────────
    BenchmarkFixture(
        name="D1_constant_command_trap",
        category="D_False_Positive_Trap",
        code="""
        #include <stdlib.h>
        void run_fixed_system_utility() {
            system("ls -la /tmp");
        }
        """,
        is_vulnerable=False,
        expected_status="SAFE",
    ),
    BenchmarkFixture(
        name="D2_password_identifier_trap",
        category="D_False_Positive_Trap",
        code="""
        #include <string.h>
        void handle_password_field(const char *pwd) {
            char password_label[] = "Enter Password:";
        }
        """,
        is_vulnerable=False,
        expected_status="SAFE",
    ),
    BenchmarkFixture(
        name="D3_fopen_constant_path_trap",
        category="D_False_Positive_Trap",
        code="""
        #include <stdio.h>
        void open_config() {
            FILE *f = fopen("app_config.json", "r");
            fclose(f);
        }
        """,
        is_vulnerable=False,
        expected_status="SAFE",
    ),

    # ─── Category E: Multi-Line Variants ──────────────────────────────────────
    BenchmarkFixture(
        name="E1_multiline_split_taint",
        category="E_Multi_Line",
        code="""
        #include <stdlib.h>
        void test_multiline() {
            char *cmd = 
                getenv(
                    "REMOTE_EXEC"
                );
            system(
                cmd
            );
        }
        """,
        is_vulnerable=True,
        cwe="CWE-78",
        vulnerability_class="Command Injection",
        expected_status="CONFIRMED",
    ),

    # ─── Category F: Macro Variants ───────────────────────────────────────────
    BenchmarkFixture(
        name="F1_macro_execution",
        category="F_Macro_Variants",
        code="""
        #include <stdlib.h>
        #define EXEC_CMD(x) system(x)
        void test_macro(char *input) {
            EXEC_CMD(input);
        }
        """,
        is_vulnerable=True,
        cwe="CWE-78",
        vulnerability_class="Command Injection via Macro",
        expected_status="CONFIRMED",
    ),

    # ─── Category G: Alias Variants ───────────────────────────────────────────
    BenchmarkFixture(
        name="G1_pointer_alias_uaf",
        category="G_Alias_Variants",
        code="""
        #include <stdlib.h>
        void test_alias() {
            char *p = malloc(32);
            char *alias1 = p;
            char *alias2 = alias1;
            free(alias2);
            *p = 'Z';
        }
        """,
        is_vulnerable=True,
        cwe="CWE-416",
        vulnerability_class="Use After Free via Alias",
        expected_status="CONFIRMED",
    ),

    # ─── Category H: Function-Wrapper Variants ────────────────────────────────
    BenchmarkFixture(
        name="H1_helper_wrapper_command_injection",
        category="H_Function_Wrapper",
        code="""
        #include <stdlib.h>
        char *get_env_input() {
            return getenv("USER_DATA");
        }
        void execute_helper(char *cmd) {
            system(cmd);
        }
        void main_driver() {
            char *raw = get_env_input();
            execute_helper(raw);
        }
        """,
        is_vulnerable=True,
        cwe="CWE-78",
        vulnerability_class="Inter-procedural Command Injection",
        expected_status="CONFIRMED",
    ),

    # ─── Category I: Branch Variants ──────────────────────────────────────────
    BenchmarkFixture(
        name="I1_branch_unguarded_log_fallthrough",
        category="I_Branch_Variants",
        code="""
        #include <stdio.h>
        void test_unguarded(char *p) {
            if (p == NULL)
                printf("Warning: pointer is null\\n");
            *p = 'W';
        }
        """,
        is_vulnerable=True,
        cwe="CWE-476",
        vulnerability_class="Null Pointer Dereference",
        expected_status="LIKELY",
    ),

    # ─── Category J: Loop Variants ────────────────────────────────────────────
    BenchmarkFixture(
        name="J1_loop_off_by_one_overflow",
        category="J_Loop_Variants",
        code="""
        void fill_buffer() {
            int arr[10];
            for (int i = 0; i <= 10; i++) {
                arr[i] = 0;
            }
        }
        """,
        is_vulnerable=True,
        cwe="CWE-787",
        vulnerability_class="Out of Bounds Write via Loop",
        expected_status="CONFIRMED",
    ),

    # ─── Category K: C++ Semantic Variants ────────────────────────────────────
    BenchmarkFixture(
        name="K1_cpp_use_after_move",
        category="K_Cpp_Variants",
        code="""
        #include <string>
        #include <iostream>
        void test_move() {
            std::string s = "secure_token";
            std::string s2 = std::move(s);
            std::cout << s;
        }
        """,
        is_vulnerable=True,
        cwe="CWE-672",
        vulnerability_class="Use After Move",
        expected_status="CONFIRMED",
        is_cpp=True,
    ),
    BenchmarkFixture(
        name="K2_cpp_array_delete_mismatch",
        category="K_Cpp_Variants",
        code="""
        void test_mismatch() {
            int *arr = new int[50];
            delete arr;
        }
        """,
        is_vulnerable=True,
        cwe="CWE-762",
        vulnerability_class="Mismatched Deallocation",
        expected_status="CONFIRMED",
        is_cpp=True,
    ),
    BenchmarkFixture(
        name="K3_cpp_safe_unique_ptr",
        category="K_Cpp_Variants",
        code="""
        #include <memory>
        void test_safe_raii() {
            auto ptr = std::make_unique<int>(42);
        }
        """,
        is_vulnerable=False,
        expected_status="SAFE",
        is_cpp=True,
    ),
]
