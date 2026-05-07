"""Declarative detection rules loaded from YAML.

Rule schema (one rule):

    - id: brute_force_login
      name: "Brute force login attempts"
      severity: HIGH
      # Match condition (all must be true):
      match:
        event_type: failed_login           # exact match (string or list)
        message_contains: ["failed", "login"]   # substring match (case-insensitive)
        severity: [WARNING, ERROR, CRITICAL]
      # Optional threshold rule: N matches in WINDOW seconds, grouped by KEY
      threshold:
        count: 5
        window_seconds: 300
        group_by: source_ip                # or username, or [source_ip, username]
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Threshold:
    count: int
    window_seconds: int
    group_by: list[str] = field(default_factory=lambda: ["source_ip"])


@dataclass
class Rule:
    id: str
    name: str
    severity: str = "MEDIUM"
    match: dict[str, Any] = field(default_factory=dict)
    threshold: Threshold | None = None
    description: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        thr = None
        if "threshold" in d and d["threshold"]:
            t = d["threshold"]
            gb = t.get("group_by", "source_ip")
            if isinstance(gb, str):
                gb = [gb]
            thr = Threshold(
                count=int(t["count"]),
                window_seconds=int(t["window_seconds"]),
                group_by=list(gb),
            )
        return cls(
            id=d["id"],
            name=d.get("name", d["id"]),
            severity=d.get("severity", "MEDIUM").upper(),
            match=d.get("match", {}) or {},
            threshold=thr,
            description=d.get("description", ""),
        )


@dataclass
class RuleSet:
    rules: list[Rule]

    @classmethod
    def from_yaml(cls, path: str | Path) -> "RuleSet":
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or []
        if not isinstance(data, list):
            raise ValueError(f"rules file must be a YAML list, got {type(data).__name__}")
        return cls(rules=[Rule.from_dict(r) for r in data])
