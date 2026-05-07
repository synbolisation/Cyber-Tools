"""Base parser interface."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, Iterator, TextIO

from ..event import Event


class ParseError(Exception):
    """Raised when a line cannot be parsed by the chosen parser."""


class BaseParser(ABC):
    """Subclass and implement parse_line. Everything else is plumbing."""

    name: str = "base"

    @abstractmethod
    def parse_line(self, line: str) -> Event:
        """Parse a single line into an Event. Raise ParseError on failure."""

    def parse_stream(self, stream: TextIO, *, strict: bool = False) -> Iterator[Event]:
        """Parse an iterable text stream lazily.

        strict=False: skip unparseable lines (still counted via .skipped)
        strict=True: raise on first failure
        """
        self.skipped = 0
        for raw in stream:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            try:
                yield self.parse_line(line)
            except ParseError:
                self.skipped += 1
                if strict:
                    raise

    def parse_lines(self, lines: Iterable[str], *, strict: bool = False) -> list[Event]:
        return list(self.parse_stream(iter(lines), strict=strict))
