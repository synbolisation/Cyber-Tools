"""Normalized event model.

All parsers emit `Event` objects. All detectors consume them.
This is the contract that keeps parsers and detectors decoupled.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Optional


@dataclass
class Event:
    """A single normalized log event."""

    timestamp: Optional[datetime] = None
    severity: Optional[str] = None        # INFO / WARNING / ERROR / CRITICAL ...
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: Optional[str] = None      # failed_login, successful_login, etc.
    message: str = ""
    raw: str = ""                         # original log line, untouched
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.timestamp is not None:
            d["timestamp"] = self.timestamp.isoformat()
        return d
