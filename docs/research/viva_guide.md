# VulnDetect: Comprehensive Viva & Defense Guide

---

## 1. Project in One Sentence
**VulnDetect** is a multi-layer static analysis tool for C/C++ source code that combines syntax, control-flow, data-flow, taint, interval, and interprocedural analysis to detect vulnerabilities, coupled with an auxiliary Random Forest classifier to verify finding genuineness without suppressing static alerts.

---

## 2. Problem Statement
C and C++ provide high runtime performance and direct hardware memory control, but lack automatic memory safety and safe string abstractions. Common vulnerabilities—such as buffer overflows, use-after-free, command injections, and off-by-one errors—account for a disproportionate number of critical security defects. 

Existing solutions have distinct operational limitations:
- **Simple Regex / Lexical Linters:** High false-alarm rate, no semantic context, and easily evaded by variable renaming or multi-line formatting.
- **Heavyweight Formal Methods / Symbolic Execution:** High computational overhead, state-explosion on non-trivial loops, and poor scalability for rapid developer feedback.
- **Pure Machine Learning / LLM Approaches:** Suffer from hallucinations, lack explainable deterministic proofs, and fail to guarantee reproducible detection.

---

## 3. Proposed Solution
VulnDetect implements a **hybrid, layered detection architecture**:
1. An **8-layer static analysis engine** built on Tree-sitter Concrete Syntax Trees (CSTs) that systematically reasons about code syntax, pointer lifecycles, loop intervals, and dataflow taint propagation across functions.
2. An **uncertainty classifier** and **heuristic reviewer** that categorize finding confidence into `CONFIRMED`, `LIKELY`, or `NEEDS_REVIEW`.
3. An **auxiliary finding-level machine learning verifier** (Random Forest) that inspects static evidence features to compute an estimated likelihood that a flagged finding is genuine, without suppressing or removing any static alerts.
4. An **OASIS SARIF v2.1.0** compliance export and interactive React visualization showing exact source lines, code snippets, and source-to-sink propagation traces.

---

## 4. System Architecture

```
[ C/C++ Source File / ZIP Project Archive ]
                     │
                     ▼
  [ Tree-sitter Parser (tree-sitter-c / tree-sitter-cpp) ]
                     │
                     ▼
  ┌────────────────────────────────────────────────────────┐
  │              8 STATIC ANALYSIS LAYERS                  │
  │  1. RuleAnalyzer (Lexical patterns & API hazards)      │
  │  2. ASTAnalyzer (Syntactic structures & bad idioms)    │
  │  3. AdvancedASTAnalyzer (Pointer state & UAF tracking) │
  │  4. TaintAnalyzer (Source-to-sink dataflow paths)      │
  │  5. RangeAnalyzer (Integer range & off-by-one loops)   │
  │  6. CFGAnalyzer (Control flow reachability & blocks)   │
  │  7. InterProceduralAnalyzer (Cross-function summaries) │
  │  8. CppAnalyzer (RAII, smart pointer misuse, move)     │
  └────────────────────────────────────────────────────────┘
                     │
                     ▼
  [ Finding Deduplicator (Multi-source evidence merging) ]
                     │
                     ▼
  [ Uncertainty Analyzer (CONFIRMED / LIKELY / NEEDS_REVIEW) ]
                     │
                     ▼
  [ Heuristic Ambiguity Reviewer (Rule-based context check) ]
                     │
                     ▼
  [ Auxiliary ML Verifier (Random Forest Classifier) ]
    (Non-destructive: attaches verification score & status)
                     │
                     ▼
  [ Risk Scorer & Output Formatter (JSON / SARIF / UI) ]
```

---

## 5. Execution Pipeline Step-by-Step

1. **Upload & Ingestion:** The user uploads a `.c`, `.cpp`, `.h`, or `.zip` file via FastAPI (`/api/v1/scan`). ZIP uploads are checked by [`SecurityGuard`](file:///a:/PROJECTS/vuln-detector/backend/app/core/security_guard.py) for path traversal (ZipSlip) and zip bombs.
2. **Parsing:** [`parse_source()`](file:///a:/PROJECTS/vuln-detector/backend/app/engine/parser.py) runs Tree-sitter to generate an AST and builds an `AnalysisContext` holding source lines, syntax trees, and language flags.
3. **Static Detection Layers:** The 8 analyzers run sequentially. Each analyzer inspects the syntax tree or propagates state, emitting internal `Finding` objects.
4. **Deduplication:** [`FindingDeduplicator`](file:///a:/PROJECTS/vuln-detector/backend/app/engine/deduplicator.py) collapses findings targeting the same file, line, and CWE. If multiple layers detect the same bug, evidence is merged and confidence is promoted.
5. **Uncertainty Classification:** [`UncertaintyAnalyzer`](file:///a:/PROJECTS/vuln-detector/backend/app/engine/uncertainty_analyzer.py) assesses whether the finding is deterministic (`CONFIRMED`) or hindered by unresolvable pointer indirection, complex macros, or external library calls (`NEEDS_REVIEW`).
6. **Heuristic Review:** [`HeuristicAmbiguityReviewer`](file:///a:/PROJECTS/vuln-detector/backend/app/engine/heuristic_reviewer.py) attaches supporting or contradicting context to ambiguous findings without altering deterministic facts.
7. **ML Finding Verification:** For supported CWEs (`CWE-78`, `CWE-416`, `CWE-193`, `CWE-134`), [`MLFindingPredictor`](file:///a:/PROJECTS/vuln-detector/backend/app/ml/predictor.py) extracts 12 numerical features and evaluates the Random Forest model. It attaches `ml_verification_score` and `ml_predicted_valid`. Non-supported CWEs receive `NOT_SUPPORTED`. **No findings are removed or suppressed.**
8. **Scoring & Response:** [`FindingScorer`](file:///a:/PROJECTS/vuln-detector/backend/app/engine/scorer.py) computes a normalized risk score [0.0, 1.0] and maps it to CRITICAL, HIGH, MEDIUM, or LOW severity. Results are saved in MongoDB and returned as JSON / SARIF.

---

## 6. Detailed Static Analysis Layers

1. **Layer 1: RuleAnalyzer**  
   *Technique:* Lexical and tokenized regex matching.  
   *Target:* Legacy, banned C functions (`gets`, `strcpy`, `strcat`, `sprintf`, `scanf("%s")`).  
   *Viva Defense:* Quick triage filter; catches obvious banned functions with zero parse overhead.
2. **Layer 2: ASTAnalyzer**  
   *Technique:* Syntactic AST pattern matching on Tree-sitter nodes.  
   *Target:* Format string attacks (`printf(user_var)`), memory allocation size mismatches (`malloc(strlen(s))` without `+ 1`), integer overflow in malloc arguments (`malloc(n * sizeof(int))`), and unchecked return values (`setuid`).  
   *Viva Defense:* Structural inspection immune to whitespace variations and line-breaks.
3. **Layer 3: AdvancedASTAnalyzer**  
   *Technique:* Statement-order and intraprocedural lifecycle state tracking.  
   *Target:* Null pointer dereference (origin-to-dereference tracking without `NULL` guards), Use-After-Free (`free(p)` followed by `*p`), Double Free (`free(p)` repeated without reassignment), and uninitialized variable reads.  
   *Viva Defense:* Maintains a symbolic map of variable allocation states through linear and branch statements.
4. **Layer 4: TaintAnalyzer**  
   *Technique:* Forward taint tracking over intraprocedural assignment graphs.  
   *Target:* Command Injection (`CWE-78`), Path Traversal (`CWE-22`).  
   *Mechanism:* Identifies sources (`getenv`, `argv`, `scanf`, `read`), tracks propagation through pointer/string assignments and format calls, flags dangerous sinks (`system`, `popen`, `exec`, `fopen`), and recognizes sanitizers.  
   *Viva Defense:* Reconstructs the exact source-to-sink variable trajectory.
5. **Layer 5: RangeAnalyzer**  
   *Technique:* Abstract interpretation using symbolic integer interval bounds.  
   *Target:* Off-by-one errors (`CWE-193`), buffer overflows (`CWE-125`/`CWE-787`), negative array indexing.  
   *Mechanism:* Evaluates array declaration sizes, loop initialization, terminating conditions (`<=` vs `<`), and increment steps.  
   *Viva Defense:* Pinpoints loop boundary flaws where index exceeds capacity by exactly 1.
6. **Layer 6: CFGAnalyzer**  
   *Technique:* Intraprocedural Control Flow Graph construction into Basic Blocks.  
   *Target:* Reachability analysis, dead code detection, cyclomatic complexity computation, and unconstrained infinite loop paths.  
   *Viva Defense:* Models conditional branch edges (`True`/`False`) to verify whether security-critical checks actually guard the sink.
7. **Layer 7: InterProceduralAnalyzer (IPA)**  
   *Technique:* Bottom-up call-graph summary computation across functions and translation units.  
   *Target:* Cross-function and cross-file vulnerabilities (e.g., function A fetches untrusted input, passes it to function B, which calls `system()`).  
   *Viva Defense:* Computes function summaries (taint in/out, memory ownership transfer) so callers are analyzed without re-analyzing the callee from scratch.
8. **Layer 8: CppAnalyzer**  
   *Technique:* C++ semantic object model inspection.  
   *Target:* Use-after-move (`std::move`), mismatched array deallocation (`new[]` with `delete` instead of `delete[]`), exceptions escaping destructors, and raw pointer escapes from `std::unique_ptr`.  
   *Viva Defense:* Enforces modern C++ RAII and move semantics.

---

## 7. The Machine Learning Verification Layer

- **What ML Does:** Operates as a secondary finding-level verifier. When static analysis emits a candidate finding, the ML model estimates whether the finding is a true vulnerability or a false positive based on structural features.
- **What ML Does NOT Do:** It does **not** scan raw source code. It does **not** detect vulnerabilities independently. It does **not** suppress, delete, or override static findings.
- **Model Choice:** `RandomForestClassifier` (100 estimators, max depth 5, balanced class weights).
- **Why Random Forest over XGBoost:** On the validation split, Random Forest achieved an F1 score of **0.7692** vs XGBoost's **0.6154**. Random Forest's bagged averaging provided lower variance on the small, structured feature space.
- **Feature Vector (12 features):**
  1. `analyzer_confidence` [0.0–1.0]: Static analyzer's reported confidence.
  2. `cwe_family_id` [0–4]: Categorical integer encoding of the vulnerability family.
  3. `dataflow_step_count` [0–10]: Number of propagation hops along the taint path.
  4. `has_dataflow_path` [0/1]: Whether an explicit source-to-sink path exists.
  5. `has_sanitizer_in_path` [0/1]: Whether a known sanitization function was passed.
  6. `is_constant_literal_sink` [0/1]: Whether the sink argument is a hardcoded literal.
  7. `pointer_deref_present` [0/1]: Whether pointer dereference syntax occurs near the sink.
  8. `line_length_norm` [0.0–1.0]: Normalized length of the flagged source line.
  9. `has_guard_in_snippet` [0/1]: Whether an `if` branch guards the statement.
  10. `is_interprocedural` [0/1]: Whether the defect spans multiple functions.
  11. `analysis_status_code` [0–2]: Categorical encoding of `CONFIRMED`, `LIKELY`, or `TENTATIVE`.
  12. `is_multi_layer` [0/1]: Whether multiple independent analyzers confirmed the defect.

---

## 8. Research Contributions

1. **Multi-Layer Static Reasoning Pipeline:** Integration of 8 distinct static analysis dimensions (syntactic, CFG, dataflow, taint, interval range, memory lifecycle, interprocedural summaries, and C++ semantics) on top of Tree-sitter CSTs.
2. **Defensible Negative-Class ML Design:** Formulation of finding-level triage where negative samples are defined as *real static findings on benign code*, avoiding the flawed assumption that clean files represent negative samples for finding-level classifiers.
3. **Non-Destructive ML Verifier Integration:** Demonstrates an architectural pattern where machine learning assists human triage through verification scores without risking false negatives caused by ML suppression.
4. **Taxonomic Dissection of Loop Vulnerabilities:** Analysis demonstrating that discrepancies between benchmark annotations (`CWE-125`/`CWE-787`) and analyzer detections (`CWE-193`) stem from root-cause vs symptom taxonomy definitions.

---

## 9. Key Experimental Results

### Static Analysis Benchmark (24 Fixtures)
- **Baseline Regex:** Precision: 100.0%, Recall: 42.9%, F1: 60.0%
- **Full Engine:** Precision: 100.0%, Recall: 85.7%, **F1: 92.3%**
- **Findings:** The multi-layer static engine increased recall by 42.8 percentage points over the baseline without introducing false positives on the curated suite.

### Auxiliary ML Verifier (Held-Out Test Set)
- **Dataset:** 56 total finding-level samples (28 pos / 28 neg), grouped 32 train / 12 validation / 12 test. Zero group leakage. Benchmark fixtures completely excluded.
- **Held-Out Test Metrics:**
  - **F1 Score:** **0.7273**
  - **ROC-AUC:** **0.8750**
  - **Precision:** 80.0% (4 TP, 1 FP)
  - **Recall:** 66.7% (4 TP, 2 FN)
  - **Accuracy:** 75.0%

---

## 10. Limitations

1. **Synthetic & Curated Benchmark Size:** The 24-case static benchmark is small and curated; 100% precision on this benchmark does **not** imply zero false positives on massive real-world projects.
2. **ML Dataset Scale:** The dataset consists of 56 finding-level samples, with 12 in the test split. While split without leakage, it represents proof-of-concept validation rather than broad generalizability.
3. **No SMT / Symbolic Execution:** VulnDetect uses interval abstract interpretation and path reachability, not full SMT constraint solvers (e.g., Z3). It cannot solve deeply nested non-linear arithmetic constraints.
4. **Shallow Pointer Alias Analysis:** Pointer tracking handles direct assignments (`q = p`) and single indirection, but does not perform full May-Alias points-to analysis for arbitrary multi-level pointers (`***p`).
5. **Uncalibrated ML Scores:** Random Forest probability outputs represent tree vote fractions, not rigorously calibrated posterior probabilities.

---

## 11. Common Viva Questions & Answers

#### Q1: Why C and C++?
**Answer:** C and C++ remain critical for operating systems, embedded firmware, browsers, and game engines. Because they lack memory safety, safe arrays, and automatic garbage collection, memory corruption defects (UAF, buffer overflows) remain high-severity security threats.

#### Q2: Why static analysis rather than dynamic analysis?
**Answer:** Static analysis scans code without executing it, providing 100% path exploration potential without requiring compilable environments, test inputs, mock dependencies, or test harnesses. It detects defects early in development (shift-left security).

#### Q3: Why not just use regex?
**Answer:** Regex has no understanding of syntax, scope, or flow. It cannot distinguish between a variable named `password` and a comment `/* password */`, cannot trace data across lines, and triggers huge false positives on safe patterns. On our benchmark, regex achieved only 42.9% recall.

#### Q4: Why Tree-sitter?
**Answer:** Tree-sitter generates full Concrete Syntax Trees (CSTs) with exact byte offsets, line numbers, and token locations. It is resilient to syntax errors, extremely fast (written in C), and parses C and C++ natively without requiring full compiler header inclusion.

#### Q5: What is the difference between an AST and a CFG?
**Answer:** An AST (Abstract Syntax Tree) represents the grammatical, hierarchical structure of code (e.g., an `IfStatement` containing a condition and a body). A CFG (Control Flow Graph) represents execution order, where nodes are basic blocks (straight-line instructions) and directed edges represent jump or branch transitions (`True`/`False`).

#### Q6: Why do you need data-flow and taint analysis?
**Answer:** Many vulnerabilities depend on where data comes from and where it goes. A call to `system("ls")` is completely safe, but `system(user_input)` is critical command injection. Taint analysis tracks untrusted input from sources to dangerous sinks.

#### Q7: Why is interprocedural analysis (IPA) necessary?
**Answer:** In modular code, inputs are often read in one helper function, passed through parameters, and consumed in another function across files. Intraprocedural analysis only inspects one function at a time and would miss these defects.

#### Q8: Why not use symbolic execution or SMT solvers?
**Answer:** Symbolic execution suffers from path explosion on loops and complex branches, and SMT solving is NP-complete. Our goal was rapid, scalable scanning taking milliseconds per file rather than minutes or hours.

#### Q9: Why not use a Large Language Model (LLM)?
**Answer:** LLMs suffer from non-deterministic hallucinations, token context limits, high inference latency, network dependency, and potential data privacy leakage. VulnDetect relies on deterministic static analysis algorithms with local, reproducible machine learning.

#### Q10: Why use Machine Learning at all?
**Answer:** Static analysis rules often struggle with triage: deciding whether an ambiguous finding in complex code is worth developer attention. ML uses numerical features extracted from the finding's context to assign a verification score for triage prioritization.

#### Q11: Why is ML not the primary detector?
**Answer:** Machine learning cannot guarantee syntactic correctness or explainable proofs. If ML were the primary detector, it would produce false negatives that a developer cannot verify. Static analysis provides deterministic detection; ML serves as an auxiliary verifier.

#### Q12: Why Random Forest?
**Answer:** On our tabular finding-level feature dataset, Random Forest outperformed XGBoost on validation F1 (0.7692 vs 0.6154), avoids overfitting on small feature spaces, and requires no external heavy GPU runtime.

#### Q13: Why only 4 CWE families for ML?
**Answer:** To maintain defensibility, we selected the four most prominent vulnerability classes in our dataset (`CWE-78`, `CWE-416`, `CWE-193`, `CWE-134`) with equal representation (14 samples each). Unsupported CWEs bypass the model with `status="NOT_SUPPORTED"`.

#### Q14: Why is the ML dataset 56 samples?
**Answer:** We strictly avoided generating synthetic duplicates or near-identical code snippets that would artificially inflate metrics. Every sample is a curated finding with verified ground truth.

#### Q15: Why separate the ML dataset from the benchmark?
**Answer:** To prevent data contamination. If benchmark fixtures were used to train or validate the ML model, the evaluation would be invalid due to evaluation set leakage.

#### Q16: What is group-based splitting?
**Answer:** If multiple findings originate from the same code snippet or family, placing one in the train set and one in the test set causes group leakage (the model recognizes the code, not the concept). Grouped splitting ensures all findings from the same code group reside entirely in train, val, or test.

#### Q17: Why don't you allow ML to suppress or delete findings?
**Answer:** In security, suppressing a true vulnerability is catastrophic (False Negative). By keeping static analysis authoritative, all findings are preserved, and ML only adds triage metadata (`ml_verification_score`).

#### Q18: What is OASIS SARIF?
**Answer:** Static Analysis Results Interchange Format (SARIF) is an OASIS standard JSON format supported by GitHub Advanced Security, VS Code, and CI/CD pipelines. Supporting SARIF allows VulnDetect to integrate into standard developer workflows.

#### Q19: What happens if the ML model fails to load?
**Answer:** The system is fault-tolerant. If the model artifact is missing or corrupted, the scanner continues running static analysis normally, setting `status="MODEL_UNAVAILABLE"` without crashing.

#### Q20: What happens if static analysis is uncertain?
**Answer:** [`UncertaintyAnalyzer`](file:///a:/PROJECTS/vuln-detector/backend/app/engine/uncertainty_analyzer.py) marks the finding as `NEEDS_REVIEW`, documents the specific unknowns (e.g., external unresolvable pointer), and generates a checklist for manual human verification.

---

## 12. Difficult Technical Questions & Deep Defenses

#### Q21: "Your benchmark reports 100% precision. Does that mean your tool has zero false positives?"
**Defense:** "No. 100% precision is an artifact of the curated 24-case benchmark where each safe case contains an explicit sanitization or safe construct that our rules are designed to handle. In large-scale real-world codebases with complex pointer arithmetic, third-party libraries, and macros, false positives will certainly occur due to analysis limitations."

#### Q22: "In the benchmark, cases C2 and J1 are marked as false negatives. Why does the benchmark say CWE-125/CWE-787 while your tool reports CWE-193?"
**Defense:** "C2 and J1 are off-by-one loop errors. The benchmark annotations describe the *symptom* (Out-of-bounds Read CWE-125, Out-of-bounds Write CWE-787), whereas our Range Analyzer identifies the *root-cause mechanism* (Off-by-one loop indexing CWE-193). Both were successfully detected on line 4 with 0.95 confidence. However, to maintain strict scientific honesty and avoid modifying benchmark criteria post-hoc, we report the exact-CWE metric where they are counted as mismatches."

#### Q23: "Your training accuracy is 93.8% but test accuracy is 75.0%. Is the model overfitting?"
**Defense:** "Some degree of generalization gap is expected with tree-based models on small datasets. However, we controlled overfitting by constraining tree depth (`max_depth=5`) and requiring minimum samples per split (`min_samples_split=3`). On the held-out test set, the model achieved an ROC-AUC of 0.8750, indicating good discriminatory capability across decision thresholds."

#### Q24: "Why do you normalize line length as a feature, and why is its Gini importance so high (0.2941)?"
**Defense:** "In our dataset, complex compound expressions containing nested function calls or array subscripts tend to have longer line lengths and correlate with genuine vulnerability sinks, whereas simple guard checks or safe returns are shorter. However, Gini importance reflects predictive utility in this dataset, not causal proof that longer lines cause vulnerabilities."

#### Q25: "Is your static analysis sound or complete?"
**Defense:** "Neither. Like almost all practical SAST tools, VulnDetect is 'soundy'—it aims to catch high-impact bugs using sound principles where possible, but makes deliberate engineering trade-offs (e.g., shallow pointer aliasing, unanalyzed external libraries) to avoid infinite loops and high false-positive rates."

---

## 13. Clean 3–5 Minute Live Demonstration Flow

### Recommended Primary Demo: Command Injection with Taint Flow
1. **Launch Web UI:** Open browser to `http://localhost:3000`.
2. **Select Demo File:** Upload [`samples/auth_handler.c`](file:///a:/PROJECTS/vuln-detector/samples/auth_handler.c) (or paste into input).
3. **Execute Scan:** Click **Scan Code**.
4. **Show Detection Result:**
   - Locate the **CRITICAL** finding: `Command Injection (CWE-78)` at line 35.
   - Expand the card to show the code snippet:
     ```c
     sprintf(cmd, "echo '%s logged in' >> /var/log/auth.log", user);
     system(cmd);
     ```
5. **Show Taint & Dataflow Evidence:**
   - Point out the **Data-Flow & Taint Propagation Path**:
     - *Source:* `user` parameter in `log_login`.
     - *Propagation:* Formatted into `cmd` buffer via `sprintf`.
     - *Sink:* Executed by `system(cmd)`.
6. **Show ML Verification:**
   - Highlight the **ML Verification (Auxiliary Triage)** badge:
     - Model: `RandomForestClassifier`
     - Score: `71%` (`Likely genuine vulnerability`)
7. **Show Fix Remediation:**
   - Point out the remediation advice: `Avoid system(); replace with execve() using an explicit argument array.`
8. **Export SARIF:**
   - Click the SARIF export button or query `GET /api/v1/scan/{id}/sarif` to show standards-compliant output.

### Backup Demo: Off-by-One Loop Bounds
If command injection is questioned, upload a loop snippet (`for (int i = 0; i <= 10; i++) arr[i] = 0;`):
- Shows the **Range Analyzer** in action (`RANGE-LOOP-OFFBYONE`, `CWE-193`).
- Highlights interval calculation: array capacity `10` vs loop maximum index `10` (attempting index `10` on a 0-indexed 10-element array).
- Demonstrates ML verification score: `87%` genuine.

---

## 14. 30-Second Viva Pitch
> *"VulnDetect is a static vulnerability detector for C/C++ code. Instead of relying on naive regex or heavy symbolic execution, it combines 8 static analysis layers—including syntax, taint tracking, control flow, and range analysis—to detect security flaws like command injection and memory corruption. We pair this with an auxiliary Random Forest classifier that evaluates finding features to help developers triage alerts. Importantly, static analysis remains authoritative: the ML model never deletes or suppresses findings. On our 24-case benchmark, the full engine achieved an F1 score of 92.3%."*

---

## 15. 2-Minute Technical Summary
> *"The core problem we address is that C and C++ lack memory safety, leading to critical vulnerabilities such as buffer overflows, use-after-free, and command injections. Existing tools either use simple regex that lacks flow context, or heavy formal methods that suffer from path explosion.*
>
> *VulnDetect solves this using an 8-layer static analysis architecture built on Tree-sitter. We start with syntax inspection, then perform intraprocedural taint tracking from sources to sinks, evaluate loop bounds using symbolic interval arithmetic, construct basic block control flow graphs, and propagate function summaries across files.*
>
> *After deduplicating findings across layers, our engine classifies analysis certainty into Confirmed, Likely, or Needs Review based on missing context like unresolvable pointers. Next, candidate findings pass through an auxiliary Random Forest verifier trained on 12 finding-level features. The ML model predicts whether a static finding is genuine, achieving 0.7273 F1 and 0.8750 ROC-AUC on our held-out test set.*
>
> *Crucially, we maintain an architectural invariant: static analysis is authoritative for detection. The ML model cannot delete or suppress findings, avoiding dangerous false negatives. Results are exportable in OASIS SARIF v2.1.0 for CI/CD integration.*
>
> *On our 24-case benchmark, the full static engine achieved 100% precision and 85.7% recall, yielding an F1 score of 92.3%, compared to 60.0% for the lexical baseline. The two benchmark misses were off-by-one errors where our tool correctly identified the root-cause CWE-193, while the benchmark labeled the consequential symptom CWE-125 and 787.*
>
> *In summary, VulnDetect demonstrates how layered static analysis and non-destructive machine learning can be combined for explainable, rapid vulnerability detection."*
