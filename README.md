# VulnDetect — AI-Based Code Vulnerability Detection System

A production-ready web application that detects vulnerabilities in C/C++ code using **static analysis** and **machine learning** (Random Forest + XGBoost ensemble).

---

## Architecture

```
vuln-detector/
├── backend/                  # Python + FastAPI
│   ├── main.py               # App entry point
│   ├── app/
│   │   ├── api/routes.py     # REST endpoints
│   │   ├── core/
│   │   │   ├── config.py     # Settings (Pydantic)
│   │   │   ├── analyzer.py   # ML + rules fusion
│   │   │   ├── file_scanner.py  # Upload handling, zip traversal
│   │   │   └── database.py   # MongoDB (Motor async)
│   │   ├── ml/
│   │   │   ├── parser.py     # Feature extraction (35 features)
│   │   │   └── model.py      # RF + XGBoost ensemble training & inference
│   │   ├── rules/
│   │   │   └── detector.py   # Rule-based pattern matching
│   │   └── schemas/
│   │       └── models.py     # Pydantic response schemas
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/                 # React 18 + Vite + Tailwind
│   ├── src/
│   │   ├── App.jsx           # Root component + routing
│   │   ├── store.js          # Zustand global state
│   │   ├── hooks/useScan.js  # Scan orchestration (backend → AI fallback)
│   │   ├── utils/api.js      # Axios API layer
│   │   ├── utils/demoData.js # Demo scan fixtures
│   │   └── components/
│   │       ├── Header.jsx
│   │       ├── Sidebar.jsx
│   │       ├── UploadScreen.jsx   # Drag-and-drop upload
│   │       ├── ScanScreen.jsx     # Animated progress
│   │       ├── ResultsScreen.jsx  # Dashboard
│   │       ├── VulnCard.jsx       # Expandable vulnerability cards
│   │       └── Charts.jsx         # Bar + donut charts
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   └── Dockerfile
│
├── samples/                  # Test C/C++ files
│   ├── vulnerable_app.c
│   ├── string_utils.cpp
│   └── auth_handler.c
│
└── docker-compose.yml
```

---

## Quick Start

### Option A — Docker Compose (recommended)

```bash
git clone <repo>
cd vuln-detector
docker-compose up --build
```

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API docs: http://localhost:8000/docs
- MongoDB: localhost:27017

### Option B — Local development

**Backend**
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Start MongoDB (or use Atlas URI in .env)
mongod --dbpath /tmp/mongo &

# Run dev server
uvicorn main:app --reload --port 8000
```

**Frontend**
```bash
cd frontend
npm install
npm run dev        # http://localhost:3000
```

---

## ML Model

### Features (35 total per line)
- **Unsafe API flags** — `has_gets`, `has_strcpy`, `has_sprintf`, `has_scanf`, `has_system`, etc.
- **Safe alternative proximity** — `safe_fgets_nearby`, `safe_snprintf_nearby`, …
- **Memory operation flags** — `mem_malloc`, `mem_free`, `mem_realloc`, …
- **Structural features** — `ptr_deref`, `has_format_string`, `has_cast`, `line_length`, `paren_depth`
- **Bounds-check presence** — `has_null_check`, `has_bounds_check`, `has_large_index`

### Ensemble
| Model | Weight | Notes |
|-------|--------|-------|
| Random Forest (200 trees, depth 10) | 45% | Low variance, calibrated probabilities |
| XGBoost (150 rounds, lr=0.1)        | 55% | Better on non-linear feature interactions |

### Risk fusion
```
final_risk = 0.60 × rule_base_risk + 0.40 × ml_score
# Boosted ×1.15 when both agree risk > 0.70 (capped at 1.0)
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scan` | Upload `.c`, `.cpp`, `.h`, `.hpp`, or `.zip` |
| `GET`  | `/api/v1/scan/{id}` | Retrieve stored scan result |
| `GET`  | `/api/v1/scans` | List recent scans (summaries) |
| `GET`  | `/api/v1/health` | Health check |

### Response format
```json
{
  "scan_id": "uuid",
  "timestamp": "2025-01-01T00:00:00Z",
  "summary": {
    "total_files": 1,
    "total_vulnerabilities": 7,
    "high_risk": 4,
    "medium_risk": 2,
    "low_risk": 1,
    "scan_duration_ms": 312,
    "vulnerability_types": { "Unsafe API: gets()": 1, "...": 2 }
  },
  "results": [
    {
      "file": "vulnerable_app.c",
      "line": 12,
      "vulnerability": "Unsafe API: gets()",
      "risk_score": 0.95,
      "severity": "CRITICAL",
      "explanation": "gets() reads input with no bounds checking...",
      "fix": "Replace gets(buf) with fgets(buf, sizeof(buf), stdin)...",
      "code_snippet": "10: char buffer[64];\n11: printf(...);\n12: gets(buffer);"
    }
  ]
}
```

---

## Detected Vulnerabilities

| Pattern | Severity | Risk Score |
|---------|----------|-----------|
| `gets()` | CRITICAL | 0.95 |
| `printf(var)` format string | CRITICAL | 0.90 |
| `system()` with user input | CRITICAL | 0.88–0.92 |
| `scanf("%s", ...)` | HIGH | 0.85 |
| `strcpy()` | HIGH | 0.80–0.88 |
| `strcat()` | HIGH | 0.78–0.82 |
| Double `free()` | HIGH | 0.82 |
| `sprintf()` | HIGH | 0.75–0.85 |
| `memcpy()` without bounds | MEDIUM | 0.65–0.70 |
| Unchecked `malloc()` | MEDIUM | 0.50–0.60 |
| Fixed char buffer | LOW | 0.28–0.35 |

---

## Fix Mappings

| Unsafe | Safe replacement |
|--------|-----------------|
| `gets(buf)` | `fgets(buf, sizeof(buf), stdin)` |
| `strcpy(d, s)` | `strncpy(d, s, sizeof(d)-1)` |
| `strcat(d, s)` | `strncat(d, s, sizeof(d)-strlen(d)-1)` |
| `sprintf(b, f, ...)` | `snprintf(b, sizeof(b), f, ...)` |
| `scanf("%s", b)` | `scanf("%255s", b)` or `fgets()` |
| `printf(var)` | `printf("%s", var)` |
| `system(cmd)` | `execve()` with arg array |

---

## Environment Variables

```env
# backend/.env
MONGO_URI=mongodb://localhost:27017
MONGO_DB=vuln_detector
DEBUG=true
MAX_FILE_SIZE_MB=50
```

---

## Testing with samples

```bash
# Single file
curl -X POST http://localhost:8000/api/v1/scan \
  -F "file=@samples/vulnerable_app.c"

# Zip folder
zip -r samples.zip samples/
curl -X POST http://localhost:8000/api/v1/scan \
  -F "file=@samples.zip"
```
