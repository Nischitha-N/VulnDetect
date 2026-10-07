# VulnDetect ML Finding Triage Dataset

## 1. Overview & Research Goal
In VulnDetect, Machine Learning is **auxiliary to static analysis**:
- **Layer 1–6 Static Analyzers** identify suspicious code patterns and emit `Finding` objects.
- **The ML Classifier** evaluates each `Finding` and predicts whether it represents a **genuine vulnerability** ($y=1$) or a **benign / false-positive finding** ($y=0$).

```
C/C++ Source Code
       │
       ▼
Deterministic Static Analysis (Rule, AST, Taint, Range, CFG, IPA)
       │
       ▼
   Finding Objects
       │
       ├─────────────────────────────────┐
       ▼                                 ▼
Finding Metadata & Snippet         Feature Extractor (12 Features)
       │                                 │
       ▼                                 ▼
Auxiliary ML Risk Triage ◄──────── Numerical Vector X
       │
       ▼
Calibrated Finding Confidence & Risk Score
```

## 2. Negative-Class Ground-Truth Design
Because the classifier operates on an existing `Finding`, a safe source file that produces zero findings **cannot** serve as a negative training sample.

Instead:
- **Positive Sample ($y=1$):** Static analyzer produces a finding, and ground truth confirms it is a genuine, exploitable vulnerability.
- **Negative Sample ($y=0$):** Static analyzer produces a finding, but human/curated ground truth confirms the code pattern is semantically safe or benign (e.g. constant argument, guard condition preventing out-of-bounds, mutually exclusive execution paths, or non-specifier string).

A `NEEDS_REVIEW` status is treated as an indicator of ambiguity, **not** as proof of benign safety. Ground-truth labels are assigned based on strict semantic analysis.

## 3. Dataset Composition
The dataset strictly covers **4 showcase CWEs**:
- `CWE-78`: OS Command Injection
- `CWE-416`: Use-After-Free
- `CWE-193`: Loop Off-by-One / Buffer Bounds
- `CWE-134`: Non-Literal Format String

### Summary Statistics
| Metric | Value |
|---|---|
| **Total Samples** | 56 |
| **Total Groups** | 28 (2 samples per group: 1 vuln, 1 benign) |
| **Positive Labels ($y=1$)** | 28 (50.0%) |
| **Negative Labels ($y=0$)** | 28 (50.0%) |
| **CWE-78 Samples** | 14 (7 vuln, 7 benign) |
| **CWE-416 Samples** | 14 (7 vuln, 7 benign) |
| **CWE-193 Samples** | 14 (7 vuln, 7 benign) |
| **CWE-134 Samples** | 14 (7 vuln, 7 benign) |
| **Benchmark Fixtures Used** | **0** (strictly quarantined) |

## 4. Deterministic Grouping & Zero Leakage
To prevent data leakage, samples are organized into `group_id` clusters (e.g. `GRP-CWE78-DIRECT-TAINT`).
- Related vulnerable and benign variants belong to the **same group**.
- Splitting is performed at the **group level** (`split.py`).
- No group ever appears in multiple partitions.
- Random seed is fixed to `42`.

### Partition Breakdown
| Partition | Groups | Samples | Percentage | Pos ($y=1$) | Neg ($y=0$) |
|---|---|---|---|---|---|
| **Train** | 16 | 32 | 57.1% | 16 | 16 |
| **Validation** | 6 | 12 | 21.4% | 6 | 6 |
| **Held-out Test** | 6 | 12 | 21.4% | 6 | 6 |
| **Total** | 28 | 56 | 100.0% | 28 | 28 |

## 5. Audited 12-Feature Pipeline
The feature extractor (`backend/app/ml/feature_extractor.py`) computes a 12-dimensional vector directly from `Finding` dataclass instances:

| # | Feature Name | Source | Description / Safe Default |
|---|---|---|---|
| 1 | `analyzer_confidence` | `f.confidence` | Calibrated detector confidence [0.0, 1.0]; default 0.5. |
| 2 | `is_multi_layer` | `f.analyzer_source`, `f.evidence` | 1.0 if `MULTI_ANALYZER` or evidence count > 1; else 0.0. |
| 3 | `has_dataflow_path` | `f.dataflow_path` | 1.0 if dataflow path exists; else 0.0. |
| 4 | `dataflow_step_count` | `len(f.dataflow_path)` | Number of dataflow steps (0.0 if empty). |
| 5 | `has_sanitizer_in_path` | `f.dataflow_path`, `f.evidence` | 1.0 if any step is SANITIZER or metadata contains sanitizer; else 0.0. |
| 6 | `is_interprocedural` | `f.analyzer_source`, `f.rule_id` | 1.0 if IPA analyzer or IPA rule prefix; else 0.0. |
| 7 | `analysis_status_code` | `f.analysis_status` | CONFIRMED: 1.0, LIKELY: 0.5, NEEDS_REVIEW: 0.0; default 0.5. |
| 8 | `cwe_family_id` | `f.cwe` | CWE-78: 1.0, CWE-416: 2.0, CWE-193: 3.0, CWE-134: 4.0; other: 0.0. |
| 9 | `has_guard_in_snippet` | `f.code_snippet` | 1.0 if snippet contains `if`, `break`, `continue`, `return`, `assert`, `sizeof`; else 0.0. |
| 10 | `is_constant_literal_sink`| `f.code_snippet` | 1.0 if snippet contains string literal quotes (`"..."`) or `const `; else 0.0. |
| 11 | `line_length_norm` | `f.code_snippet` | Snippet length normalized by 120 chars: `min(1.0, len/120.0)`. |
| 12 | `pointer_deref_present` | `f.code_snippet` | 1.0 if snippet contains pointer operators `*p`, `p->`, `p[...]`; else 0.0. |
