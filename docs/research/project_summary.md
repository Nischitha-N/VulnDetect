# VulnDetect: Project Summary & IEEE Paper Abstract Guide

**Title:** Multi-Layer Static Analysis with Auxiliary Machine-Learning Finding Verification for C/C++ Source Code  
**Artifact Classification:** Research Prototype & Experimental Report  
**Target Domain:** Static Application Security Testing (SAST), Software Engineering, Systems Security

---

## 1. Abstract
C and C++ remain foundational to systems programming, yet their lack of inherent memory safety regularly introduces severe vulnerabilities, including buffer overflows, use-after-free, off-by-one boundary errors, and command injections. Existing static analyzers frequently oscillate between shallow lexical pattern matchers that generate excessive false alarms and heavyweight formal methods that face scalability bottlenecks. 

This project presents **VulnDetect**, a hybrid vulnerability detection framework combining an 8-layer static analysis engine with an auxiliary finding-level machine learning verifier. VulnDetect parses C/C++ source code into Concrete Syntax Trees using Tree-sitter, sequentially applying AST structural rules, pointer lifecycle state tracking, forward source-to-sink taint analysis, integer interval range analysis, control-flow graph reachability, interprocedural function summary propagation, and C++ RAII semantics. Candidate findings are consolidated through multi-analyzer deduplication and classified by uncertainty. 

To assist developer triage without risking false negatives, an auxiliary Random Forest classifier evaluates 12 finding-level features to estimate finding validity. Crucially, the static analysis pipeline remains authoritative: the machine learning verifier never deletes or suppresses static alerts. 

Evaluated on a curated 24-case benchmark across 11 vulnerability categories, the full static engine achieved a precision of 100.0%, a recall of 85.7%, and an F1 score of 92.3%, substantially outperforming a lexical baseline (F1: 60.0%). The auxiliary Random Forest model achieved an F1 score of 0.7273 and an ROC-AUC of 0.8750 on a held-out test split of 12 samples with zero group leakage. The complete system produces OASIS SARIF v2.1.0 compliant outputs and provides explainable dataflow traces.

---

## 2. Problem Statement & Motivation
Memory corruption and injection flaws in C/C++ remain among the most dangerous classes of software vulnerabilities (e.g., CWE Top 25). Modern software security demands detection tools that are:
1. **Context-Aware:** Capable of understanding semantic dataflow and control branches rather than simple keyword matches.
2. **Performant:** Rapid enough to run in continuous integration pipelines without path explosion.
3. **Transparent & Explainable:** Providing developers with exact variable propagation paths and remediation guidance.
4. **Resilient to Over-Suppression:** Ensuring that machine learning models do not drop true vulnerabilities due to imperfect classification boundaries.

---

## 3. System Architecture & Methodology

```
┌────────────────────────────────────────────────────────┐
│               Input: C/C++ Source / ZIP                │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│        Tree-sitter Concrete Syntax Tree Parser         │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│                8 STATIC ANALYSIS LAYERS                │
│  1. RuleAnalyzer (Lexical patterns & dangerous APIs)   │
│  2. ASTAnalyzer (Syntactic structures & bad idioms)   │
│  3. AdvancedASTAnalyzer (Pointer lifecycle & UAF)      │
│  4. TaintAnalyzer (Forward source-to-sink dataflow)    │
│  5. RangeAnalyzer (Loop interval bounds & off-by-one)  │
│  6. CFGAnalyzer (Control flow reachability & blocks)   │
│  7. InterProceduralAnalyzer (Cross-file summaries)     │
│  8. CppAnalyzer (RAII, move safety, smart pointers)    │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│     Multi-Analyzer Deduplicator & Evidence Merger      │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│  Uncertainty Analyzer (CONFIRMED/LIKELY/NEEDS_REVIEW)  │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│              Heuristic Ambiguity Reviewer              │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│     Auxiliary ML Verifier (Random Forest Classifier)    │
│   (Non-destructive: attaches verification score/status) │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│    Calibrated Risk Scorer & Output (SARIF / JSON / UI)  │
└────────────────────────────────────────────────────────┘
```

---

## 4. Main Techniques Implemented

### A. Syntactic & Lifecycle AST Analysis
Tree-sitter CST nodes are analyzed to detect format string vulnerabilities (`printf(variable)`), buffer allocation size mismatches (`malloc(strlen(s))` without null terminator adjustment), and integer multiplication overflows in allocation arguments. Statement-order lifecycle tracking monitors allocation, deallocation, and dereferencing states to detect Use-After-Free (`CWE-416`) and Double Free (`CWE-415`).

### B. Forward Source-to-Sink Taint Tracking
Untrusted input sources (`getenv`, `argv`, `scanf`, `read`) are tracked along variable assignment chains across local and interprocedural calls. Sinks are categorized by risk (`system`, `popen`, `exec`, `fopen`). If sanitized along the path, taint is cleared; otherwise, a complete step-by-step dataflow trajectory is captured.

### C. Integer Range & Loop Interval Analysis
Loop terminating conditions, iteration step sizes, and array capacities are evaluated using abstract interval arithmetic. The range analyzer flags boundary mismatches where the maximum loop index equals array capacity (`i <= SIZE`), detecting off-by-one read and write errors (`CWE-193`).

### D. Control Flow Graph (CFG) Construction
Source functions are transformed into basic blocks interconnected by directed control-flow edges (`True`/`False`). The engine validates reachability, detects dead code, and confirms whether potential sinks are dominated by conditional validation blocks.

### E. Bottom-Up Interprocedural Call-Graph Summaries
The analyzer scans all compilation units in a project, constructing an interprocedural call-graph. Function summaries record taint propagation from arguments to returns and memory ownership transfers, allowing cross-file vulnerability detection without re-analyzing call targets redundantly.

---

## 5. Machine Learning Component

- **Paradigm:** Auxiliary finding-level verification (triage scoring), not primary vulnerability detection.
- **Input Features (12):**
  1. `analyzer_confidence`
  2. `cwe_family_id`
  3. `dataflow_step_count`
  4. `has_dataflow_path`
  5. `has_sanitizer_in_path`
  6. `is_constant_literal_sink`
  7. `pointer_deref_present`
  8. `line_length_norm`
  9. `has_guard_in_snippet`
  10. `is_interprocedural`
  11. `analysis_status_code`
  12. `is_multi_layer`
- **Model:** `RandomForestClassifier` (`n_estimators=100`, `max_depth=5`, `class_weight='balanced'`, `random_state=42`).
- **Safety Invariant:** Finding preservation. ML only outputs verification scores and validity indicators; static findings are never discarded.

---

## 6. Dataset & Experimental Setup

- **Benchmark Dataset:** 24 C/C++ fixtures across 11 categories (A to K) totaling 145 LOC (14 vulnerable, 10 safe). Completely isolated from ML training.
- **ML Dataset:** 56 finding-level samples (28 true positive findings, 28 false positive / benign findings).
- **Partitioning:** Grouped split by code family (32 train, 12 validation, 12 test). Zero group leakage. Random seed 42.

---

## 7. Experimental Results

### Table I: Static Analysis Benchmark Across Configurations

| Configuration | TP | FP | FN | TN | Precision | Recall | F1 Score | Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BASELINE_REGEX` | 6 | 0 | 8 | 10 | 100.0% | 42.9% | 60.0% | 7.0 ms |
| `AST_ONLY` | 9 | 0 | 5 | 10 | 100.0% | 64.3% | 78.3% | 20.5 ms |
| `AST_CFG` | 8 | 0 | 6 | 10 | 100.0% | 57.1% | 72.7% | 22.3 ms |
| `AST_TAINT` | 7 | 0 | 7 | 10 | 100.0% | 50.0% | 66.7% | 15.6 ms |
| `AST_IPA` | 7 | 0 | 7 | 10 | 100.0% | 50.0% | 66.7% | 20.1 ms |
| `FULL_ENGINE` | **12** | **0** | **2** | **10** | **100.0%** | **85.7%** | **92.3%** | 287.6 ms |

### Table II: Auxiliary ML Model Performance Across Splits

| Split | Samples | Accuracy | Precision | Recall | F1 Score | ROC-AUC | Brier Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Train** | 32 | 93.8% | 93.8% | 93.8% | 0.9375 | 0.9922 | 0.0834 |
| **Validation** | 12 | 75.0% | 71.4% | 83.3% | 0.7692 | 0.7500 | 0.1963 |
| **Held-Out Test** | 12 | 75.0% | 80.0% | 66.7% | **0.7273** | **0.8750** | **0.1782** |

---

## 8. Summary of Contributions
1. A modular, 8-layer static analysis architecture that unifies syntactic, control-flow, taint, interval, and interprocedural reasoning on Tree-sitter CSTs.
2. A research-defensible finding-level ML design where negative samples reflect genuine static analyzer false alarms on benign code.
3. An architectural proof-of-concept demonstrating non-destructive auxiliary ML verification that preserves static findings while assisting human triage.
4. Taxonomic clarification showing how symptom-level benchmark labels (`CWE-125`/`CWE-787`) map to root-cause analyzer detections (`CWE-193`).

---

## 9. Limitations & Threats to Validity
- **Benchmark Scale:** The 24-case benchmark is curated and small; performance on large, complex codebases will exhibit lower precision due to unmodeled libraries and intricate pointer aliasing.
- **ML Sample Size:** 56 finding-level samples provide proof-of-concept validation for 4 CWE families but do not generalize across all C/C++ software defects.
- **Analysis Scope:** Does not employ heavyweight SMT solvers (e.g., Z3) or full interprocedural points-to alias analysis.
- **Calibration:** ML output scores represent uncalibrated random forest voting proportions.

---

## 10. Future Work
1. Expansion of finding-level datasets across open-source CVE repositories (e.g., Juliet Test Suite, SARD).
2. Incorporation of path-sensitive SMT constraint solving for complex arithmetic loop bounds.
3. Rigorous probability calibration via Platt scaling or isotonic regression.
4. Support for deeper C++ template metaprogramming and concurrency race conditions.
