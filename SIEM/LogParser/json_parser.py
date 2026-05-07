"""Parser for JSON-lines logs.

Accepts any JSON object per line. Maps common field names to Event fields.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from ..event import Event
from .base import BaseParser, ParseError

# Common field aliases seen in the wild — fall through in order.
TS_KEYS = ("timestamp", "@timestamp", "time", "ts", "eventTime")
SEV_KEYS = ("severity", "level", "log_level", "loglevel")
IP_KEYS = ("source_ip", "src_ip", "client_ip", "remote_addr", "ip")
USER_KEYS = ("username", "user", "user_name", "principal", "account")
TYPE_KEYS = ("event_type", "event", "action", "type")
MSG_KEYS = ("message", "msg", "description")


def _first(d: dict, keys: tuple[str, ...]):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def _parse_ts(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        # Epoch seconds (or ms — heuristic on magnitude)
        if value > 1e12:
            value = value / 1000.0
        return datetime.fromtimestamp(value, tz=timezone.utc).replace(tzinfo=None)
    if isinstance(value, str):
        # Try ISO 8601 first; fall back to common formats.
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return None
    return None


class JSONLogParser(BaseParser):
    name = "json"

    def parse_line(self, line: str) -> Event:
        line = line.strip()
        if not line:
            raise ParseError("empty line")
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            raise ParseError(f"invalid JSON: {e}") from e
        if not isinstance(obj, dict):
            raise ParseError("JSON line must be an object")

        ts = _parse_ts(_first(obj, TS_KEYS))
        sev = _first(obj, SEV_KEYS)
        if isinstance(sev, str):
            sev = sev.upper()

        # Anything we didn't pull into the structured fields stays in `extra`.
        consumed = set(TS_KEYS + SEV_KEYS + IP_KEYS + USER_KEYS + TYPE_KEYS + MSG_KEYS)
        extra = {k: v for k, v in obj.items() if k not in consumed}

        return Event(
            timestamp=ts,
            severity=sev,
            source_ip=_first(obj, IP_KEYS),
            username=_first(obj, USER_KEYS),
            event_type=_first(obj, TYPE_KEYS),
            message=_first(obj, MSG_KEYS) or "",
            raw=line,
            extra=extra,
        )
