# VulnDetect: Multi-Layer Static Analysis & Finding-Level Verification System

A research-oriented vulnerability detection platform for C/C++ source code combining an **8-layer static analysis architecture** with an **auxiliary machine learning finding verifier** (Random Forest).

---

## Architecture

VulnDetect evaluates source code through an eight-layer static analysis pipeline followed by post-processing and auxiliary finding-level machine learning verification:

```
[ C/C++ Source File / ZIP Project ]
                 │
                 ▼
[ Tree-sitter AST & CST Parser (tree-sitter-c / tree-sitter-cpp) ]
                 │
                 ▼
 ┌──────────────────────────────────────────────────────────────┐
 │                  8 STATIC ANALYSIS LAYERS                    │
 │ 1. RuleAnalyzer (Lexical patterns & dangerous API keywords)  │
 │ 2. ASTAnalyzer (Syntactic structures & bad sizeof/malloc)    │
 │ 3. AdvancedASTAnalyzer (State & lifecycle: UAF, NULL deref)  │
 │ 4. TaintAnalyzer (Source-to-sink untrusted dataflow paths)   │
 │ 5. RangeAnalyzer (Loop bounds & off-by-one interval checks)  │
 │ 6. CFGAnalyzer (Control flow graph, reachability, dead code) │
 │ 7. InterProceduralAnalyzer (Call-graph summary propagation)  │
 │ 8. CppAnalyzer (RAII semantics, move safety, smart pointers) │
 └──────────────────────────────────────────────────────────────┘
                 │
                 ▼
[ Finding Deduplicator & Multi-Analyzer Correlator ]
                 │
                 ▼
[ Uncertainty & Ambiguity Analyzer (CONFIRMED / LIKELY / NEEDS_REVIEW) ]
                 │
                 ▼
[ Heuristic Ambiguity Reviewer (Supporting / Contradicting Evidence) ]
                 │
                 ▼
[ Auxiliary ML Finding Verifier (Random Forest Classifier) ]
  (Non-destructive: attaches verification score & status to findings)
                 │
                 ▼
[ Calibrated Risk Scorer & Output (JSON / OASIS SARIF v2.1.0 / React Dashboard) ]
```

---

## Repository Structure

```
vuln-detector/
├── backend/
│   ├── main.py                     # FastAPI application entry point
│   ├── app/
│   │   ├── api/routes.py           # REST endpoints (/scan, /scan/{id}, /sarif)
│   │   ├── core/
│   │   │   ├── config.py           # Application settings
│   │   │   ├── analyzer.py         # Analysis bridge to orchestrator
│   │   │   ├── file_scanner.py     # Safe file & ZIP upload extraction
│   │   │   ├── security_guard.py   # Security quotas & path traversal protection
│   │   │   └── database.py         # MongoDB scan persistence
│   │   ├── engine/                 # 8-layer static analysis pipeline
│   │   │   ├── parser.py           # Tree-sitter AST parser
│   │   │   ├── rule_analyzer.py    # Layer 1: Lexical & regex patterns
│   │   │   ├── ast_analyzer.py     # Layer 2: Syntactic AST analyzer
│   │   │   ├── advanced_ast_analyzer.py # Layer 3: Lifecycle state tracker
│   │   │   ├── taint_analyzer.py   # Layer 4: Source-to-sink taint engine
│   │   │   ├── range_analyzer.py   # Layer 5: Integer interval & off-by-one
│   │   │   ├── cfg_analyzer.py     # Layer 6: Control flow graph analysis
│   │   │   ├── ipa_analyzer.py     # Layer 7: Interprocedural summary engine
│   │   │   ├── cpp_analyzer.py     # Layer 8: Modern C++ RAII analyzer
│   │   │   ├── deduplicator.py     # Multi-layer finding deduplication
│   │   │   ├── uncertainty_analyzer.py # Certainty classification
│   │   │   ├── heuristic_reviewer.py   # Heuristic ambiguity reviewer
│   │   │   └── scorer.py           # Calibrated risk scorer
│   │   ├── ml/                     # Auxiliary ML finding verifier
│   │   │   ├── feature_extractor.py # 12 finding-level numerical features
│   │   │   ├── predictor.py        # Non-destructive finding triage inference
│   │   │   ├── train.py            # Model training & evaluation pipeline
│   │   │   ├── dataset/            # 56 curated finding-level samples
│   │   │   └── models/             # Trained final_model.joblib & metadata
│   │   ├── sarif/sarif.py          # OASIS SARIF v2.1.0 exporter
│   │   └── schemas/models.py       # Pydantic data models
│   └── tests/                      # 128 automated unit & regression tests
│       └── benchmark/              # 24-case static benchmark & runner
│
├── frontend/                       # React 18 + Vite dashboard
│   ├── src/
│   │   ├── App.jsx                 # Application shell
│   │   ├── store.js                # State store
│   │   ├── hooks/useScan.js        # Scan API dispatch
│   │   ├── components/             # Dashboard, Upload, Results, VulnCard
│   │   └── utils/api.js            # Axios client
│   └── package.json
│
├── docs/research/                  # Research evaluation & documentation
│   ├── final_evaluation.md         # Full research evaluation report
│   ├── results/                    # Machine-readable evaluation JSONs
│   ├── viva_guide.md               # Oral defense (viva) guide
│   └── project_summary.md          # Project summary
│
└── samples/                        # Test C/C++ sample files
    ├── vulnerable_app.c
    ├── auth_handler.c
    ├── string_utils.cpp
    └── advanced_vulns.c
```

---

## Machine Learning Verification Component

The ML verifier operates exclusively on candidate findings produced by the static analysis pipeline:

- **Role:** Auxiliary finding-level triage (verification score: $P(\text{Valid Finding} \mid \text{Static Features})$).
- **Architectural Invariant:** Static analysis is authoritative for detection. ML never suppresses, removes, or modifies static findings.
- **Model:** `RandomForestClassifier` (`n_estimators=100`, `max_depth=5`, `class_weight='balanced'`, `random_state=42`).
- **Features:** 12 numerical features derived from finding attributes, dataflow paths, AST context, and engine confidence.
- **Supported Families:** `CWE-78` (Command Injection), `CWE-416` (Use-After-Free), `CWE-193` (Off-by-One), `CWE-134` (Format String). Unsupported CWEs bypass ML with `status="NOT_SUPPORTED"`.

---

## Experimental Results Summary

### Static Analysis Benchmark (24-Case Curated Benchmark)
- **Baseline Regex:** Precision = 100.0%, Recall = 42.9%, F1 = 60.0%
- **Full Static Engine:** Precision = 100.0%, Recall = 85.7%, F1 = **92.3%**
- *Note:* Both apparent false negatives (C2, J1) were detected as root-cause `CWE-193` by the Range Analyzer; exact-CWE scoring is retained for evaluation rigor.

### Auxiliary ML Verifier (Held-Out Test Set, 12 Samples)
- **Held-Out Test F1:** **0.7273**
- **Held-Out Test ROC-AUC:** **0.8750**
- **Test Confusion Matrix:** TN = 5, FP = 1, FN = 2, TP = 4

---

## Getting Started

### Local Development

**Backend:**
```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Run backend test suite (128 tests)
pytest tests -v

# Start development server
uvicorn main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

- Web UI: `http://localhost:3000`
- API Documentation: `http://localhost:8000/docs`
- SARIF Export: `GET /api/v1/scan/{scan_id}/sarif`
