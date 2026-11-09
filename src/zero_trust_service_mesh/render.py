"""Render every generated file from the spec, or check that the committed copies are current."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .envoy import bootstrap
from .files import write_atomic
from .k8s import spire_manifests, workload_manifests
from .mesh import MeshSpec
from .spire import agent_conf, register_script, server_conf


def _json(obj: Any) -> bytes:
    """Stable, diff-friendly JSON."""
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode()


def render(spec: MeshSpec) -> dict[str, bytes]:
    """Relative path to file content, for everything generated from the spec."""
    out = {
        "spire.json": _json(spire_manifests(spec)),
        "workloads.json": _json(workload_manifests(spec)),
        "register.sh": register_script(spec).encode(),
        "spire/server.conf": server_conf(spec).encode(),
        "spire/agent.conf": agent_conf(spec).encode(),
    }
    for w in spec.workloads:
        out[f"envoy/{w.name}.json"] = _json(bootstrap(spec, w))
    return out


def stale_files(spec: MeshSpec, out_dir: Path) -> list[str]:
    """Generated files that are missing or differ from what the spec renders."""
    return sorted(
        rel
        for rel, data in render(spec).items()
        if not (out_dir / rel).is_file() or (out_dir / rel).read_bytes() != data
    )


def write_all(spec: MeshSpec, out_dir: Path) -> list[str]:
    """Write every generated file atomically; return the paths that changed."""
    changed = stale_files(spec, out_dir)
    files = render(spec)
    for rel in changed:
        write_atomic(out_dir / rel, files[rel], mode=0o755 if rel.endswith(".sh") else 0o644)
    return changed
