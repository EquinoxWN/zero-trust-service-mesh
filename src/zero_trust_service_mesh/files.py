"""Atomic file writes: a crash leaves the old file or the new one, never half of either."""

from __future__ import annotations

import contextlib
import os
from pathlib import Path


def write_atomic(path: Path, data: bytes, mode: int = 0o644) -> None:
    """Write data to a sibling temp file, fsync it, then rename it over path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise
