"""
Project Configuration Loader (.vulndetect.yml / .vulndetect.json).
"""

import os
import json
import fnmatch
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any

try:
    import yaml
    _has_yaml = True
except ImportError:
    _has_yaml = False


@dataclass
class ProjectConfig:
    enabled_analyzers: List[str] = field(default_factory=lambda: ["rule", "ast", "advanced_ast", "taint", "uncertainty"])
    severity_threshold: str = "LOW"        # LOW, MEDIUM, HIGH, CRITICAL
    fail_on_severity: Optional[str] = None  # None, or HIGH, CRITICAL (for CI/CD exit code)
    ignore_paths: List[str] = field(default_factory=lambda: [
        "vendor/**", "build/**", "dist/**", "node_modules/**", ".git/**", "tests/**", "third_party/**"
    ])
    suppressions: List[Dict[str, Any]] = field(default_factory=list)
    custom_sources: List[str] = field(default_factory=list)
    custom_sinks: List[str] = field(default_factory=list)
    custom_sanitizers: List[str] = field(default_factory=list)
    enable_llm_review: bool = False


DEFAULT_CONFIG_FILES = [".vulndetect.yml", ".vulndetect.yaml", ".vulndetect.json"]


class ConfigLoader:
    """Discovers and loads project configuration file."""

    @staticmethod
    def load_config(config_path: Optional[str] = None, root_dir: str = ".") -> ProjectConfig:
        if config_path and os.path.exists(config_path):
            return ConfigLoader._parse_file(config_path)

        # Search in root_dir
        for name in DEFAULT_CONFIG_FILES:
            target = os.path.join(root_dir, name)
            if os.path.exists(target):
                return ConfigLoader._parse_file(target)

        return ProjectConfig()

    @staticmethod
    def _parse_file(filepath: str) -> ProjectConfig:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            if filepath.endswith(".json"):
                data = json.loads(content)
            elif _has_yaml:
                data = yaml.safe_load(content) or {}
            else:
                # Basic line-by-line fallback if yaml is unavailable
                data = json.loads(content) if content.strip().startswith("{") else {}

            return ProjectConfig(
                enabled_analyzers=data.get("analyzers", ["rule", "ast", "advanced_ast", "taint", "uncertainty"]),
                severity_threshold=data.get("severity_threshold", "LOW").upper(),
                fail_on_severity=data.get("fail_on", data.get("fail_on_severity")),
                ignore_paths=data.get("ignore_paths", [
                    "vendor/**", "build/**", "dist/**", "node_modules/**", ".git/**", "tests/**", "third_party/**"
                ]),
                suppressions=data.get("suppressions", []),
                custom_sources=data.get("custom_sources", []),
                custom_sinks=data.get("custom_sinks", []),
                custom_sanitizers=data.get("custom_sanitizers", []),
                enable_llm_review=data.get("enable_llm_review", False),
            )
        except Exception as e:
            print(f"[ConfigLoader] Warning: Failed to load {filepath}: {e}. Using defaults.")
            return ProjectConfig()

    @staticmethod
    def is_path_ignored(file_path: str, ignore_patterns: List[str]) -> bool:
        """Check if file_path matches any configured glob pattern."""
        norm_path = file_path.replace("\\", "/")
        for pattern in ignore_patterns:
            norm_pattern = pattern.replace("\\", "/")
            if fnmatch.fnmatch(norm_path, norm_pattern) or fnmatch.fnmatch(os.path.basename(norm_path), norm_pattern):
                return True
        return False
