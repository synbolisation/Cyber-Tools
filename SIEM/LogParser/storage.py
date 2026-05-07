"""JSON-lines storage for events and alerts.

JSONL is the lingua franca of log pipelines — easy to grep, easy to ship to
Elastic / Splunk / Loki / Vector / a database, easy to diff. One record per line.
"""
from __future__ import annotations

import json
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, TextIO


@contextmanager
def open_sink(path: str | None) -> Iterator[TextIO]:
    """Open a writeable sink — file path, or stdout when path is None or '-'."""
    if path in (None, "-"):
        yield sys.stdout
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        yield f


def write_jsonl(record: dict, sink: TextIO) -> None:
    sink.write(json.dumps(record, default=str) + "\n")
    sink.flush()
