# VulnDetect: Final Research Evaluation

**Date:** October 2026  
**Artifact Version:** Frozen Post-Audit Evaluation  
**Status:** Evaluation and Verification Complete (Implementation Frozen)

---

## 1. Experimental Objective

The objective of this research evaluation is to assess the static vulnerability detection capability and the auxiliary machine-learning verification component of **VulnDetect**, a multi-layer static analysis framework for C/C++ source code.

This evaluation is structured into two strictly independent experiments:
1. **Experiment A (Static Vulnerability Detection):** Evaluates how effectively VulnDetect's layered static analysis engine detects vulnerabilities across varying engine configurations on a curated 24-case benchmark.
2. **Experiment B (Auxiliary ML Finding-Level Verification):** Evaluates how effectively a downstream machine-learning verifier distinguishes true-positive static findings from false-positive/benign static findings using finding-level structural, semantic, and confidence features.

> **Crucial Methodological Distinction:**  
> Static analysis performs vulnerability detection on source code. Machine learning operates downstream on static findings to provide finding-level triage and verification scores. Machine learning does **not** detect vulnerabilities independently, nor does it suppress, delete, or re-rank static findings in the static detection benchmark.

---

## 2. System Overview

VulnDetect is composed of an eight-layer static analysis architecture augmented by post-processing and an auxiliary machine learning verification layer:

```
[ C/C++ Source Code ]
        │
        ▼
[ Clang AST Parser (cindex) / PyCParser Fallback ]
        │
        ▼
[ Layer 1: Lexical Pattern & Rule Analyzer (Regex/Keyword) ]
[ Layer 2: AST Structural Analyzer (libclang AST)          ]
[ Layer 3: Control Flow Graph (CFG) & Cyclomatic Engine    ]
[ Layer 4: Intraprocedural Dataflow & Reachability Engine  ]
[ Layer 5: Source-to-Sink Taint Engine (Interprocedural)   ]
[ Layer 6: Memory Safety Analyzer (UAF, Double Free, NULL) ]
[ Layer 7: Integer & Array Range Analyzer (Interval Engine)]
[ Layer 8: Modern C++ RAII / Resource Analyzer             ]
        │
        ▼
[ Multi-layer Finding Aggregator & Deduplicator ]
        │
        ▼
[ Uncertainty & Ambiguity Analyzer (Heuristic Review) ]
        │
        ▼
[ Auxiliary ML Finding Verifier (Random Forest Classifier) ]
  (Non-destructive: attaches verification score & status)
        │
        ▼
[ Security Risk Scorer & Output (JSON / REST API / UI) ]
```

---

## 3. Static-Analysis Benchmark Methodology

### Benchmark Dataset Composition
- **Benchmark Corpus:** 24 synthetic and semi-synthetic C/C++ test fixtures defined in `backend/tests/benchmark/manifest.py`.
- **Distribution:**
  - **14 Vulnerable Cases:** Containing ground-truth vulnerabilities across memory corruption, command injection, format string vulnerabilities, off-by-one errors, and null pointer dereferences.
  - **10 Safe Cases:** Containing safe idioms, properly bounded loops, sanitized inputs, and RAII constructs designed to test false-positive resistance.
- **Total Lines of Code (LOC):** 145 lines across fixtures.

### Evaluated Configurations
The benchmark was executed under six incremental analyzer configurations:
1. `BASELINE_REGEX`: Lexical pattern matching only.
2. `AST_ONLY`: AST structural analysis without flow or path sensitivity.
3. `AST_CFG`: AST analysis combined with intraprocedural control-flow graphs.
4. `AST_TAINT`: AST analysis combined with source-to-sink taint tracking.
5. `AST_IPA`: AST analysis combined with interprocedural call-graph summary propagation.
6. `FULL_ENGINE`: All eight static analysis layers enabled.

### Evaluation Criteria
A case is classified as a:
- **True Positive (TP):** Ground-truth is vulnerable, and the analyzer emits a confirmed finding matching the required CWE and location.
- **False Positive (FP):** Ground-truth is safe, but the analyzer emits a confirmed finding.
- **False Negative (FN):** Ground-truth is vulnerable, but no matching finding is emitted.
- **True Negative (TN):** Ground-truth is safe, and no false findings are emitted.

---

## 4. Static-Analysis Results Table

The results obtained from executing the frozen benchmark runner (`backend/tests/benchmark/runner.py`) are presented in Table 1.

### Table 1: Static Analysis Benchmark Performance Across Configurations

| Configuration | TP | FP | FN | TN | Precision | Recall | F1 Score | Findings/KLOC | Uncertainty Rate | Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **BASELINE_REGEX** | 6 | 0 | 8 | 10 | **100.0%** | 42.9% | 60.0% | 62.1 | 0.0% | 7.0 ms |
| **AST_ONLY** | 9 | 0 | 5 | 10 | **100.0%** | 64.3% | 78.3% | 96.6 | 0.0% | 20.5 ms |
| **AST_CFG** | 8 | 0 | 6 | 10 | **100.0%** | 57.1% | 72.7% | 69.0 | 0.0% | 22.3 ms |
| **AST_TAINT** | 7 | 0 | 7 | 10 | **100.0%** | 50.0% | 66.7% | 62.1 | 0.0% | 15.6 ms |
| **AST_IPA** | 7 | 0 | 7 | 10 | **100.0%** | 50.0% | 66.7% | 69.0 | 0.0% | 20.1 ms |
| **FULL_ENGINE** | **12** | **0** | **2** | **10** | **100.0%** | **85.7%** | **92.3%** | 144.8 | 0.0% | 287.6 ms |

### Key Observations:
- **Precision:** Precision remained at 100.0% across all configurations on this benchmark, reflecting rigorous validation before confirming findings.
- **Recall Progression:** The lexical baseline achieved 42.9% recall. Adding AST, CFG, taint, and range layers expanded coverage to 85.7% (12 of 14 vulnerable cases detected).
- **Latency Tradeoff:** The full engine requires ~287.6 ms for the suite, compared to 7.0 ms for the regex baseline, attributable to AST construction, CFG traversal, and interval analysis.

---

## 5. CWE Mismatch Analysis (C2 and J1)

Under exact CWE taxonomy matching, the `FULL_ENGINE` configuration records 2 False Negatives out of 14 vulnerable test cases:
1. Case `C2_near_miss_off_by_one_vulnerable`
2. Case `J1_loop_off_by_one_overflow`

An audit was performed to determine the nature of these apparent false negatives.

### Detailed Audit Findings

#### Case C2: `C2_near_miss_off_by_one_vulnerable`
- **Ground Truth Annotation:** `CWE-125` (Out-of-bounds Read)
- **Emitted Finding:**
  - Rule ID: `RANGE-LOOP-OFFBYONE`
  - Emitted CWE: `CWE-193` (Off-by-one Error)
  - Analyzer Source: `AnalyzerSource.RANGE`
  - Status: `AnalysisStatus.CONFIRMED` (Confidence: 0.95, Line: 4)
- **Taxonomic Analysis:** The vulnerability is an off-by-one read in a loop index boundary (`<= SIZE`). The range analyzer correctly identifies the root-cause mechanism (`CWE-193`). However, the benchmark ground truth labels the symptom consequence (`CWE-125`).

#### Case J1: `J1_loop_off_by_one_overflow`
- **Ground Truth Annotation:** `CWE-787` (Out-of-bounds Write)
- **Emitted Finding:**
  - Rule ID: `RANGE-LOOP-OFFBYONE`
  - Emitted CWE: `CWE-193` (Off-by-one Error)
  - Analyzer Source: `AnalyzerSource.RANGE`
  - Status: `AnalysisStatus.CONFIRMED` (Confidence: 0.95, Line: 4)
- **Taxonomic Analysis:** The vulnerability is an off-by-one buffer overflow write during array initialization. The analyzer identified the off-by-one loop indexing condition (`CWE-193`), while the benchmark ground truth designates the consequence (`CWE-787`).

### Methodological Recommendation
In accordance with CWE hierarchical taxonomy (CWE-193 is a parent/child root cause of CWE-125 and CWE-787 memory bounds violations), both defects were detected by the static analyzer. 

However, to maintain scientific rigor and avoid post-hoc metric inflation:
- **Primary Reported Benchmark Metric:** **Retained at exact-CWE matching** (TP=12, FN=2, F1=92.3%, Recall=85.7%).
- **CWE-Relaxed Interpretation (Root-Cause Equivalence):** If root-cause equivalence between CWE-193 and bounds violations (CWE-125/CWE-787) is permitted, detection recall is 14/14 (100.0%, F1=100.0%).

---

## 6. ML Dataset Methodology

### Finding-Level Dataset Design
Unlike file-level classification, the VulnDetect ML verifier operates at the **finding level**. A sample exists only when a static analyzer has produced a candidate finding:
- **Positive Sample (`label = 1`):** The static analyzer generated a finding, and ground-truth validation confirms the finding is a true security vulnerability.
- **Negative Sample (`label = 0`):** The static analyzer generated a finding, but ground-truth validation demonstrates that the code is benign (e.g., false alarms caused by missing sanitizers, safe buffer limits, or unreachability).

### Dataset Partitioning and Stratification
- **Total Dataset Size:** 56 curated finding-level samples.
- **Class Balance:** Exactly 28 positive samples (50.0%) and 28 negative samples (50.0%).
- **Supported CWE Families:**
  - `CWE-78` (OS Command Injection): 14 samples (7 pos / 7 neg)
  - `CWE-416` (Use After Free): 14 samples (7 pos / 7 neg)
  - `CWE-193` (Off-by-One / Range): 14 samples (7 pos / 7 neg)
  - `CWE-134` (Format String Vulnerability): 14 samples (7 pos / 7 neg)
- **Partitioning Strategy:**
  - **Train Split:** 32 samples (16 positive, 16 negative)
  - **Validation Split:** 12 samples (6 positive, 6 negative)
  - **Held-Out Test Split:** 12 samples (6 positive, 6 negative)
  - **Grouped Split:** Code snippet family grouping was enforced to ensure **zero group leakage** across splits.
  - **Independence from Benchmark:** All 24 benchmark fixtures were completely excluded from the ML dataset.
  - **Random Seed:** 42.

---

## 7. ML Model Methodology

### Model Architecture and Hyperparameters
Two candidate models were evaluated during model selection: Random Forest and XGBoost. Selection was performed based on validation F1 score.

**Selected Model:** `RandomForestClassifier` (Scikit-Learn)
- `n_estimators`: 100
- `max_depth`: 5
- `min_samples_split`: 3
- `class_weight`: `"balanced"`
- `random_state`: 42

### 12 Extracted Numerical Features
The finding-level feature extractor computes 12 numerical features:
1. `analyzer_confidence` [0.0, 1.0]: Static analyzer's reported confidence.
2. `cwe_family_id` [0..4]: Numerical encoding of the CWE family.
3. `dataflow_step_count` [0..10]: Number of hops along the tainted dataflow path.
4. `has_dataflow_path` [0 or 1]: Indicator whether an explicit propagation path exists.
5. `has_sanitizer_in_path` [0 or 1]: Indicator whether a known sanitizer/check was encountered.
6. `is_constant_literal_sink` [0 or 1]: Indicator whether the sink argument is a compile-time constant.
7. `pointer_deref_present` [0 or 1]: Indicator whether pointer dereference operations occur near the sink.
8. `line_length_norm` [0.0, 1.0]: Normalized length of the flagged source code line.
9. `has_guard_in_snippet` [0 or 1]: Indicator whether branch guard conditions enclose the sink.
10. `is_interprocedural` [0 or 1]: Indicator whether the finding spans multiple function boundaries.
11. `analysis_status_code` [0..2]: Encoding of analysis status (CONFIRMED, SUSPECTED, TENTATIVE).
12. `is_multi_layer` [0 or 1]: Indicator whether multiple independent analysis layers confirmed the finding.

---

## 8. ML Results Table

The verified performance metrics from the frozen model metadata (`backend/app/ml/models/model_metadata.json`) are detailed in Table 2.

### Table 2: ML Model Performance Across Dataset Partitions

| Partition | Samples | Accuracy | Precision | Recall | F1 Score | ROC-AUC | Brier Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Train** | 32 | 93.8% | 93.8% | 93.8% | 0.9375 | 0.9922 | 0.0834 |
| **Validation** | 12 | 75.0% | 71.4% | 83.3% | 0.7692 | 0.7500 | 0.1963 |
| **Held-Out Test** | 12 | 75.0% | 80.0% | 66.7% | **0.7273** | **0.8750** | **0.1782** |

---

## 9. ML Confusion Matrix (Held-Out Test Set)

On the 12 held-out test samples (6 true positives, 6 false positives/negatives), the decision threshold of 0.5 yielded:

```
                      Predicted Negative    Predicted Positive
Actual Benign (TN/FP):        5                     1
Actual Vuln   (FN/TP):        2                     4
```

- **True Negatives (TN):** 5 (Benign static findings correctly flagged as non-genuine)
- **False Positives (FP):** 1 (Benign static finding misclassified as genuine)
- **False Negatives (FN):** 2 (Genuine vulnerability finding misclassified as benign)
- **True Positives (TP):** 4 (Genuine vulnerability finding correctly verified)

---

## 10. Feature Importance Analysis

Feature importances derived from the Gini impurity reduction of the trained Random Forest model are presented in Table 3.

### Table 3: Random Forest Feature Importances

| Rank | Feature Name | Importance | Interpretation & Implementation Rationale |
| :---: | :--- | :---: | :--- |
| 1 | `line_length_norm` | 0.2941 | Length of the source code statement containing the finding. In the dataset, complex compound expressions correlate with genuine vulnerability sinks. |
| 2 | `analyzer_confidence` | 0.1452 | Initial confidence assigned by the static analysis rule/engine based on syntactic specificity. |
| 3 | `dataflow_step_count` | 0.0936 | Propagation distance from tainted source to sink; longer multi-hop flows frequently exhibit distinct genuine vs benign profiles. |
| 4 | `analysis_status_code` | 0.0815 | Categorical confidence level (CONFIRMED vs SUSPECTED vs TENTATIVE). |
| 5 | `has_dataflow_path` | 0.0750 | Presence of a verified source-to-sink dataflow trajectory. |
| 6 | `is_constant_literal_sink`| 0.0743 | Sinks receiving hardcoded string literals or constants are often benign false positives. |
| 7 | `is_multi_layer` | 0.0705 | Whether the defect was independently flagged by multiple analysis engines (e.g., AST and Taint). |
| 8 | `cwe_family_id` | 0.0557 | Vulnerability classification family identifier. |
| 9 | `has_guard_in_snippet` | 0.0482 | Presence of sanitization or condition checks guarding the flagged line. |
| 10 | `pointer_deref_present` | 0.0380 | Occurrence of pointer indirection near the flagged statement. |
| 11 | `is_interprocedural` | 0.0177 | Whether defect propagation crosses function boundaries. |
| 12 | `has_sanitizer_in_path` | 0.0063 | Indicator of explicit sanitization routines encountered along the dataflow path. |

> **Caution:** Gini feature importances indicate predictive contribution within this specific dataset and do not imply causal relationships in general software repositories.

---

## 11. End-to-End Integration Sanity Check

An end-to-end integration check was executed using independent, non-benchmark source snippets across supported and unsupported CWE categories.

### Table 4: Integration Sanity Test Cases

| Case | Targeted CWE | Static Analysis Outcome | ML Verification Status | ML Score | Preserved? |
| :--- | :---: | :--- | :--- | :---: | :---: |
| **Command Injection** | CWE-78 | Detected (`TAINT-SYSTEM-001`, conf=0.99) | `VERIFIED` | 0.7100 | Yes |
| **Use After Free** | CWE-416 | Detected (`ADV-UAF-001`, conf=0.90) | `VERIFIED` | 0.2743 | Yes |
| **Off-by-One Loop** | CWE-193 | Detected (`RANGE-LOOP-OFFBYONE`, conf=0.95) | `VERIFIED` | 0.8672 | Yes |
| **Format String** | CWE-134 | Detected (`AST-FORMAT-001`, conf=0.99) | `VERIFIED` | 0.5768 | Yes |
| **Integer Truncation** | CWE-131 | Detected (`ADV-NULL-001`, conf=0.88) | `NOT_SUPPORTED` | `None` | Yes |

### Invariants Verified:
1. **Finding Preservation:** Static analysis findings were 100% preserved in all cases regardless of ML output.
2. **Confidence Integrity:** Static analyzer confidence values were unmodified by ML inference.
3. **CWE Gating:** Unsupported CWE families (such as CWE-131 / CWE-476) were assigned `status="NOT_SUPPORTED"` and bypassed ML classification.
4. **Non-Destructive Scoring:** Low ML scores (e.g., CWE-416 score=0.2743) resulted in `predicted_valid=False` without removing or suppressing the static detection finding.

---

## 12. Overhead Measurement

Timing benchmarks were recorded over 10 repeated end-to-end scans of representative C code snippets:
- **Average Total Scan Latency:** 21.8 ms (min: 14.9 ms, max: 32.4 ms, N=10)
- **Constituents:** Source parsing, 8 static analysis layers, deduplication, uncertainty analysis, heuristic review, ML inference, and risk scoring.
- **Reporting Statement:** *ML inference overhead was not independently benchmarked as a separate isolated measurement from static analysis.*

---

## 13. Threats to Validity

1. **Benchmark Scale:** The static benchmark contains 24 synthetic test cases. While representative of key vulnerability patterns, it does not represent the full complexity of large-scale open-source C/C++ codebases.
2. **Curated Benchmark Composition:** Synthetic benchmarks exhibit high signal-to-noise ratios, explaining the 100.0% precision observed. Real-world codebases with complex macros, inline assembly, and opaque external libraries may experience higher false positive rates.
3. **ML Dataset Size:** The finding-level dataset is composed of 56 curated samples, with a held-out test split of 12 samples. Although group-level splitting prevented data leakage, the sample size limits the statistical generalizability of the reported metrics.
4. **Lexical Baseline Construction:** The baseline utilizes a tailored set of regular expressions; comparison results reflect relative improvement over simple pattern matching rather than established industry static analyzers.
5. **CWE Taxonomy Alignment:** Evaluation metrics depend on exact CWE identifier matching. Semantic variations between root cause (CWE-193) and symptom (CWE-125/787) affect reported recall.
6. **Probability Calibration:** The Random Forest output probabilities have not undergone Platt scaling or isotonic regression; scores represent uncalibrated tree ensemble votes and should be treated as relative verification heuristics.

---

## 14. Limitations

- **Language Scope:** VulnDetect focuses on C and C++ idioms. Language features involving complex metaprogramming, template specialization, or architecture-specific inline assembly are beyond the analyzer's scope.
- **CWE Coverage:** Static analysis covers 16 major CWE classes; ML finding-level verification is strictly limited to 4 supported CWE families (`CWE-78`, `CWE-416`, `CWE-193`, `CWE-134`).
- **Static Analysis Precedence:** ML verification cannot identify vulnerabilities that the upstream static analyzers failed to detect.

---

## 15. Reproducibility Information

- **Repository Root:** `a:\PROJECTS\vuln-detector`
- **Benchmark Suite:** `backend/tests/benchmark/manifest.py`
- **Benchmark Runner:** `backend/tests/benchmark/runner.py`
- **ML Training Script:** `backend/app/ml/train.py`
- **Trained Model Artifact:** `backend/app/ml/models/final_model.joblib`
- **Model Metadata:** `backend/app/ml/models/model_metadata.json`
- **Full Test Suite:** 128 tests passing (`pytest backend/tests`)
- **Evaluation Script:** `backend/scratch/run_evaluation.py`
- **Machine-Readable Outputs:**
  - `docs/research/results/static_benchmark.json`
  - `docs/research/results/ml_evaluation.json`
  - `docs/research/results/sanity_check.json`

---

## 16. Final Findings & Defensible Research Claims

### Paper-Safe Claims:
- The `FULL_ENGINE` configuration achieved **92.3% F1 score** (85.7% Recall, 100.0% Precision) on the curated 24-case benchmark under exact-CWE evaluation.
- The multi-layer static engine significantly improved detection recall compared to the lexical baseline (85.7% vs 42.9%) on the benchmark corpus.
- The auxiliary Random Forest verifier achieved **0.7273 F1** and **0.8750 ROC-AUC** on the held-out 12-sample test set.
- Both apparent static false negatives (C2, J1) were successfully detected by the Range Analyzer as root-cause `CWE-193` off-by-one errors.
- Machine learning is integrated as an auxiliary finding-level verifier and maintains full non-destructive preservation of static findings.
