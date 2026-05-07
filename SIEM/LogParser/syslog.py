"""Parser for syslog-style lines like:

    2025-03-06 08:23:11 INFO 192.168.1.1 User 'admin' logged in successfully
    2025-03-06 08:45:32 WARNING 192.168.1.105 Failed login attempt for user 'root' (attempt 3/5)

Format: <YYYY-MM-DD HH:MM:SS> <SEVERITY> <IP> <message>
"""
from __future__ import annotations

import re
from datetime import datetime

from ..event import Event
from .base import BaseParser, ParseError

# Anchored: timestamp + severity + ip + everything else.
# Severity is loose on purpose so we can pick up custom levels too.
LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{1,2}:\d{2}:\d{2})\s+"
    r"(?P<sev>[A-Z]+)\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<msg>.+)$"
)

USER_RE = re.compile(r"user(?:name)?\s+'([^']+)'", re.IGNORECASE)
ALT_USER_RE = re.compile(r"User\s+'([^']+)'")


def _classify(message: str) -> str | None:
    """Heuristically assign an event_type so detectors don't have to grep raw text."""
    m = message.lower()
    if "failed login" in m or "authentication failure" in m:
        return "failed_login"
    if "logged in successfully" in m or "successful login" in m or "accepted password" in m:
        return "successful_login"
    if "unauthorized" in m:
        return "unauthorized_access"
    if "connection timeout" in m or "unable to reach" in m:
        return "connection_error"
    if "sudo" in m or "privilege" in m or "elevated" in m:
        return "privilege_use"
    if "port scan" in m or "scan detected" in m:
        return "port_scan"
    return None


class SyslogParser(BaseParser):
    name = "syslog"

    def parse_line(self, line: str) -> Event:
        m = LINE_RE.match(line)
        if not m:
            raise ParseError(f"line did not match syslog pattern: {line!r}")

        ts_raw = m.group("ts").replace("T", " ")
        try:
            ts = datetime.strptime(ts_raw, "%Y-%m-%d %H:%M:%S")
        except ValueError as e:
            raise ParseError(f"bad timestamp {ts_raw!r}: {e}") from e

        message = m.group("msg")
        user_match = USER_RE.search(message) or ALT_USER_RE.search(message)
        username = user_match.group(1) if user_match else None

        return Event(
            timestamp=ts,
            severity=m.group("sev"),
            source_ip=m.group("ip"),
            username=username,
            event_type=_classify(message),
            message=message,
            raw=line,
        )
