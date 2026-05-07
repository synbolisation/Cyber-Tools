from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

DEFAULT_BASELINE = "baseline.json"
CHUNK = 65536


def sha256_of(path: Path) -> str:
    """Return the SHA-256 hex digest of a file, streamed in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_files(target: Path, exclude: Path | None = None) -> list[Path]:
    """Return a sorted list of files under target (single file or directory).

    `exclude` is skipped if it falls inside target — used to keep the
    baseline file itself from being baselined.
    """
    exclude_resolved = exclude.resolve() if exclude else None

    def keep(p: Path) -> bool:
        return exclude_resolved is None or p.resolve() != exclude_resolved

    if target.is_file():
        return [target] if keep(target) else []
    if target.is_dir():
        return sorted(p for p in target.rglob("*") if p.is_file() and keep(p))
    raise FileNotFoundError(f"no such file or directory: {target}")


def cmd_baseline(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve()
    baseline_path = Path(args.baseline)
    files = collect_files(target, exclude=baseline_path)

    baseline = {str(p): sha256_of(p) for p in files}

    with open(args.baseline, "w", encoding="utf-8") as f:
        json.dump({"root": str(target), "hashes": baseline}, f, indent=2)

    print(f"Baselined {len(baseline)} file(s) -> {args.baseline}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    try:
        with open(args.baseline, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"error: baseline file not found: {args.baseline}", file=sys.stderr)
        print("       run 'baseline' first.", file=sys.stderr)
        return 2

    saved: dict[str, str] = data["hashes"]
    target = Path(data["root"])

    try:
        current_files = collect_files(target, exclude=Path(args.baseline))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    current = {str(p): sha256_of(p) for p in current_files}

    saved_paths = set(saved.keys())
    current_paths = set(current.keys())

    added    = sorted(current_paths - saved_paths)
    removed  = sorted(saved_paths - current_paths)
    modified = sorted(p for p in (saved_paths & current_paths) if saved[p] != current[p])
    unchanged = len(saved_paths & current_paths) - len(modified)

    if not (added or removed or modified):
        print(f"OK — all {unchanged} file(s) match baseline.")
        return 0

    print(f"INTEGRITY MISMATCH against {args.baseline}")
    print(f"  unchanged: {unchanged}")
    print(f"  modified:  {len(modified)}")
    print(f"  added:     {len(added)}")
    print(f"  removed:   {len(removed)}")
    print()

    for p in modified:
        print(f"  [MODIFIED] {p}")
        print(f"    baseline: {saved[p]}")
        print(f"    current:  {current[p]}")
    for p in added:
        print(f"  [ADDED]    {p}")
    for p in removed:
        print(f"  [REMOVED]  {p}")

    return 1  # non-zero so it plays nicely with cron / scripts


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fim",
        description="Basic file integrity monitor using SHA-256.",
    )
    p.add_argument("-b", "--baseline", default=DEFAULT_BASELINE,
                   help=f"path to baseline file (default: {DEFAULT_BASELINE})")
    sub = p.add_subparsers(dest="cmd", required=True)

    pb = sub.add_parser("baseline", help="record SHA-256 hashes for a file or directory")
    pb.add_argument("path", help="file or directory to baseline")
    pb.set_defaults(func=cmd_baseline)

    pc = sub.add_parser("check", help="check current files against the baseline")
    pc.set_defaults(func=cmd_check)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
