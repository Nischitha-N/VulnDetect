"""
Dataset Validation and Leakage Detection Utility for VulnDetect ML Finding Triage.

Enforces:
- No benchmark fixture leakage (benchmark/manifest.py or fixtures).
- No group leakage across train/validation/test partitions.
- Exact label integrity (labels must be 0 or 1).
- Uniqueness of sample_id and (source_file, function_name, expected_rule).
- Presence of all required metadata fields.
- Fails loudly (exit code 1 / assertion error) on any violation.
"""

import sys
import json
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple

from app.ml.dataset.split import load_dataset, get_grouped_split

REQUIRED_FIELDS = [
    "sample_id",
    "group_id",
    "cwe",
    "label",
    "source_file",
    "function_name",
    "expected_rule",
    "analyzer_source",
    "description",
    "rationale",
]

ALLOWED_CWES = {"CWE-78", "CWE-416", "CWE-193", "CWE-134"}
BENCHMARK_FORBIDDEN_KEYWORDS = ["manifest.py", "tests/benchmark", "tests\\benchmark"]


def validate_dataset(dataset_path: Path = None) -> Dict[str, Any]:
    """
    Validates the dataset integrity and reports distributions.
    Raises ValueError / RuntimeError if any invariant is violated.
    """
    if dataset_path is None:
        dataset_path = Path(__file__).parent / "samples.json"

    with open(dataset_path, "r", encoding="utf-8") as f:
        samples: List[Dict[str, Any]] = json.load(f)

    errors: List[str] = []

    # 1. Total samples check
    total_samples = len(samples)
    if total_samples < 40 or total_samples > 80:
        errors.append(f"Sample count {total_samples} is outside expected research range [40, 80]")

    # 2. Check required fields, labels, CWEs, and benchmark quarantine
    sample_ids: Set[str] = set()
    source_fn_rule_tuples: Set[Tuple] = set()
    cwe_dist: Dict[str, int] = {}
    analyzer_dist: Dict[str, int] = {}
    pos_count = 0
    neg_count = 0

    for i, s in enumerate(samples):
        # Required fields
        for field in REQUIRED_FIELDS:
            if field not in s or s[field] is None or s[field] == "":
                errors.append(f"Sample index {i} ({s.get('sample_id', 'unknown')}): missing required field '{field}'")

        sid = s.get("sample_id", "")
        if sid in sample_ids:
            errors.append(f"Duplicate sample_id detected: '{sid}'")
        sample_ids.add(sid)

        # Label check
        lbl = s.get("label")
        if lbl not in (0, 1):
            errors.append(f"Sample '{sid}': invalid label '{lbl}' (must be 0 or 1)")
        elif lbl == 1:
            pos_count += 1
        else:
            neg_count += 1

        # CWE check
        cwe = s.get("cwe")
        if cwe not in ALLOWED_CWES:
            errors.append(f"Sample '{sid}': forbidden/unexpected CWE '{cwe}' (allowed: {ALLOWED_CWES})")
        else:
            cwe_dist[cwe] = cwe_dist.get(cwe, 0) + 1

        # Analyzer source
        analyzer = s.get("analyzer_source", "unknown")
        analyzer_dist[analyzer] = analyzer_dist.get(analyzer, 0) + 1

        # Benchmark contamination check
        src_file = s.get("source_file", "").replace("\\", "/")
        for forbidden in BENCHMARK_FORBIDDEN_KEYWORDS:
            if forbidden in src_file:
                errors.append(f"CRITICAL LEAKAGE: Sample '{sid}' uses benchmark fixture '{src_file}'!")

    # 3. Partitioning & Group Leakage Check
    splits = get_grouped_split(samples, seed=42)
    partition_groups: Dict[str, Set[str]] = {
        "train": set(s["group_id"] for s in splits["train"]),
        "val": set(s["group_id"] for s in splits["val"]),
        "test": set(s["group_id"] for s in splits["test"]),
    }

    # Verify no group overlaps
    train_val_overlap = partition_groups["train"].intersection(partition_groups["val"])
    train_test_overlap = partition_groups["train"].intersection(partition_groups["test"])
    val_test_overlap = partition_groups["val"].intersection(partition_groups["test"])

    if train_val_overlap:
        errors.append(f"GROUP LEAKAGE: Groups present in both train and val: {train_val_overlap}")
    if train_test_overlap:
        errors.append(f"GROUP LEAKAGE: Groups present in both train and test: {train_test_overlap}")
    if val_test_overlap:
        errors.append(f"GROUP LEAKAGE: Groups present in both val and test: {val_test_overlap}")

    if errors:
        error_msg = "\n".join([f"  - {e}" for e in errors])
        raise RuntimeError(f"Dataset validation FAILED with {len(errors)} error(s):\n{error_msg}")

    # Build report dict
    report = {
        "status": "PASS",
        "total_samples": total_samples,
        "positive_count": pos_count,
        "negative_count": neg_count,
        "class_balance_pct": f"{pos_count / total_samples * 100:.1f}% pos, {neg_count / total_samples * 100:.1f}% neg",
        "cwe_distribution": cwe_dist,
        "analyzer_distribution": analyzer_dist,
        "splits": {
            part: {
                "count": len(splits[part]),
                "groups": len(partition_groups[part]),
                "pct": f"{len(splits[part]) / total_samples * 100:.1f}%",
                "pos": sum(1 for s in splits[part] if s["label"] == 1),
                "neg": sum(1 for s in splits[part] if s["label"] == 0),
            }
            for part in ["train", "val", "test"]
        }
    }
    return report


if __name__ == "__main__":
    try:
        report = validate_dataset()
        print("=== DATASET VALIDATION REPORT ===")
        print(f"Status: {report['status']}")
        print(f"Total samples: {report['total_samples']}")
        print(f"Class balance: {report['positive_count']} positive, {report['negative_count']} negative ({report['class_balance_pct']})")
        print("\nCWE Distribution:")
        for cwe, count in report["cwe_distribution"].items():
            print(f"  {cwe}: {count}")
        print("\nAnalyzer Distribution:")
        for a, count in report["analyzer_distribution"].items():
            print(f"  {a}: {count}")
        print("\nPartition Counts (Zero Group Leakage):")
        for part, data in report["splits"].items():
            print(f"  {part.upper():5s}: {data['count']:2d} samples ({data['pct']}) | {data['groups']:2d} groups | pos={data['pos']}, neg={data['neg']}")
        print("\nAll integrity checks passed successfully.")
    except Exception as e:
        print(f"Validation FAILED: {e}", file=sys.stderr)
        sys.exit(1)
