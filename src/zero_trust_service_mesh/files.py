"""Atomic file writes: a crash leaves the old file or the new one, never half of either."""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path


def write_atomic(path: Path, data: bytes, mode: int = 0o644) -> None:
    """Write data to a fresh, unpredictable sibling temp file, fsync it, then rename it over path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # mkstemp creates the file with O_EXCL (owner-only, never through an existing name or symlink).
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(name)
    try:
        with os.fdopen(fd, "wb") as f:
            os.chmod(tmp, mode)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise
