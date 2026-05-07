"""Stateful detection engine.

Two modes per rule:
  - simple match  -> fires an alert per matching event
  - threshold     -> fires when N matching events occur in a sliding time window,
                     grouped by one or more fields (e.g. source_ip)

The threshold tracker uses a deque per group key so it stays O(1) per event
even with high-volume input.
"""
from __future__ import annotations

from collections import deque, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Any, Iterable, Iterator

from ..event import Event
from .rules import Rule, RuleSet


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    severity: str
    timestamp: datetime
    description: str
    triggering_events: list[Event] = field(default_factory=list)
    group_key: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "description": self.description,
            "group_key": self.group_key,
            "triggering_events": [e.to_dict() for e in self.triggering_events],
        }


def _matches(event: Event, match_spec: dict[str, Any]) -> bool:
    """Check whether an event satisfies all conditions in match_spec."""
    for key, expected in match_spec.items():
        if key == "message_contains":
            terms = [expected] if isinstance(expected, str) else list(expected)
            haystack = (event.message or "").lower()
            if not all(term.lower() in haystack for term in terms):
                return False
            continue

        # Field-based match: support exact string OR list-of-allowed-values.
        actual = getattr(event, key, None)
        if actual is None:
            actual = event.extra.get(key)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        else:
            if actual != expected:
                return False
    return True


def _group_key(event: Event, fields: list[str]) -> tuple:
    return tuple(getattr(event, f, None) or event.extra.get(f) for f in fields)


class DetectionEngine:
    def __init__(self, ruleset: RuleSet):
        self.ruleset = ruleset
        # rule_id -> group_key tuple -> deque of (timestamp, event)
        self._buffers: dict[str, dict[tuple, deque]] = defaultdict(lambda: defaultdict(deque))
        # rule_id -> set of group_keys currently in a fired state (debounce)
        self._fired: dict[str, set[tuple]] = defaultdict(set)

    def feed(self, events: Iterable[Event]) -> Iterator[Alert]:
        for event in events:
            yield from self.process(event)

    def process(self, event: Event) -> Iterator[Alert]:
        for rule in self.ruleset.rules:
            if not _matches(event, rule.match):
                continue

            if rule.threshold is None:
                yield Alert(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    timestamp=event.timestamp or datetime.now(),
                    description=rule.description or rule.name,
                    triggering_events=[event],
                )
                continue

            # Threshold rule
            t = rule.threshold
            key = _group_key(event, t.group_by)
            buf = self._buffers[rule.id][key]
            now = event.timestamp or datetime.now()
            buf.append((now, event))

            # Evict old entries outside the window
            cutoff = now - timedelta(seconds=t.window_seconds)
            while buf and buf[0][0] < cutoff:
                buf.popleft()

            if len(buf) >= t.count and key not in self._fired[rule.id]:
                self._fired[rule.id].add(key)
                yield Alert(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    timestamp=now,
                    description=(
                        rule.description
                        or f"{rule.name}: {len(buf)} events within {t.window_seconds}s"
                    ),
                    triggering_events=[e for _, e in buf],
                    group_key=dict(zip(t.group_by, key)),
                )
            elif len(buf) < t.count and key in self._fired[rule.id]:
                # Window emptied below threshold — allow re-firing later.
                self._fired[rule.id].discard(key)
