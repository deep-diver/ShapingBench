"""Import helpers for generated snapshots with differing package layouts."""

from __future__ import annotations

import sys
from pathlib import Path


def add_snapshot_import_roots(snapshot: Path) -> list[Path]:
    """Add conventional generated-package roots without installing the target."""

    candidates = [snapshot, snapshot / "src", snapshot / "lib", snapshot / "python"]
    roots = [path for path in candidates if path.is_dir()]
    for path in reversed(roots):
        value = str(path)
        if value in sys.path:
            sys.path.remove(value)
        sys.path.insert(0, value)
    return roots
