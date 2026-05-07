"""Auto-detecting parser. Sniffs format on first call, then sticks with it."""
from __future__ import annotations

from ..event import Event
from .base import BaseParser, ParseError
from .syslog import SyslogParser
from .json_parser import JSONLogParser


class AutoParser(BaseParser):
    name = "auto"

    def __init__(self):
        self._chosen: BaseParser | None = None

    def _detect(self, line: str) -> BaseParser:
        stripped = line.lstrip()
        if stripped.startswith("{"):
            return JSONLogParser()
        return SyslogParser()

    def parse_line(self, line: str) -> Event:
        if self._chosen is None:
            self._chosen = self._detect(line)
        try:
            return self._chosen.parse_line(line)
        except ParseError:
            # Format may be mixed — try the other parser before giving up.
            other = JSONLogParser() if isinstance(self._chosen, SyslogParser) else SyslogParser()
            return other.parse_line(line)
