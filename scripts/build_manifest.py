#!/usr/bin/env python3
"""Write deterministic SHA-256 checksums for the public release payload."""

from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "MANIFEST.sha256"
SKIP_PARTS = {".git", ".venv", "__pycache__", ".pytest_cache", "runs"}


def main() -> int:
    lines = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or path == OUTPUT or any(part in SKIP_PARTS for part in path.parts):
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(ROOT).as_posix()}")
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(lines)} checksums to {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
