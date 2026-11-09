"""The mesh spec: one JSON file that every generated config and test is derived from."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .spiffe import SpiffeId, validate_label, validate_trust_domain

MAX_SPEC_BYTES = 1 << 20
MIN_SVID_TTL = 60
MAX_SVID_TTL = 3600
OUTBOUND_PORT_OFFSET = 10000


class SpecError(ValueError):
    """The mesh spec is malformed or inconsistent."""


@dataclass(frozen=True)
class Workload:
    """A deployed workload: its Kubernetes identity and how it talks to others."""

    name: str
    namespace: str
    service_account: str
    port: int | None = None
    allowed_callers: tuple[str, ...] = ()
    upstreams: tuple[str, ...] = ()
    registered: bool = True

    def spiffe_id(self, trust_domain: str) -> SpiffeId:
        """This workload's SPIFFE ID under the ns/sa convention."""
        return SpiffeId.for_service_account(trust_domain, self.namespace, self.service_account)

    @property
    def dns_name(self) -> str:
        """The in-cluster DNS name of this workload's Service."""
        return f"{self.name}.{self.namespace}.svc.cluster.local"


@dataclass(frozen=True)
class MeshSpec:
    """Trust domain, cluster name, SVID lifetime and the workloads."""

    trust_domain: str
    cluster: str
    svid_ttl_seconds: int
    workloads: tuple[Workload, ...] = field(default_factory=tuple)

    def get(self, name: str) -> Workload:
        """Workload by name, or SpecError."""
        for w in self.workloads:
            if w.name == name:
                return w
        raise SpecError(f"unknown workload {name!r}")

    @property
    def registered(self) -> tuple[Workload, ...]:
        """Workloads that get a SPIRE registration entry."""
        return tuple(w for w in self.workloads if w.registered)

    @property
    def agent_id(self) -> SpiffeId:
        """The node alias every SPIRE agent in the cluster maps to (parent of workload entries)."""
        return SpiffeId(self.trust_domain, "/ns/spire/sa/spire-agent")

    def outbound_port(self, upstream: str) -> int:
        """Local port on which a caller's sidecar forwards to an upstream."""
        port = self.get(upstream).port
        if port is None:
            raise SpecError(f"{upstream!r} has no port")
        return port + OUTBOUND_PORT_OFFSET


def _int(obj: dict[str, Any], key: str, lo: int, hi: int) -> int:
    """A bounded integer field (booleans rejected)."""
    v = obj.get(key)
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise SpecError(f"{key} must be an integer in [{lo}, {hi}], got {v!r}")
    return v


def _names(obj: dict[str, Any], key: str) -> tuple[str, ...]:
    """A list of workload names (strings, no duplicates)."""
    v = obj.get(key, [])
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v) or len(set(v)) != len(v):
        raise SpecError(f"{key} must be a list of distinct names, got {v!r}")
    return tuple(v)


def _workload(raw: Any, registered: bool) -> Workload:
    """One workload entry, strictly checked."""
    if not isinstance(raw, dict):
        raise SpecError(f"workload must be an object, got {raw!r}")
    allowed = {"name", "namespace", "service_account", "port", "allowed_callers", "upstreams"}
    if extra := set(raw) - allowed:
        raise SpecError(f"unknown workload keys {sorted(extra)}")
    try:
        name = validate_label("name", raw.get("name"))
        ns = validate_label("namespace", raw.get("namespace"))
        sa = validate_label("service account", raw.get("service_account"))
    except ValueError as e:
        raise SpecError(str(e)) from e
    port = _int(raw, "port", 1, 65535 - OUTBOUND_PORT_OFFSET) if "port" in raw else None
    callers = _names(raw, "allowed_callers")
    if callers and port is None:
        raise SpecError(f"{name}: allowed_callers needs a port")
    if not registered and (port is not None or callers):
        raise SpecError(f"{name}: an unregistered workload cannot serve")
    return Workload(name, ns, sa, port, callers, _names(raw, "upstreams"), registered)


def parse_spec(data: Any) -> MeshSpec:
    """Validate a decoded spec and return it; every cross reference is checked."""
    if not isinstance(data, dict):
        raise SpecError("spec must be a JSON object")
    allowed = {"trust_domain", "cluster", "svid_ttl_seconds", "workloads", "unregistered"}
    if extra := set(data) - allowed:
        raise SpecError(f"unknown spec keys {sorted(extra)}")
    try:
        td = validate_trust_domain(data.get("trust_domain", ""))
        cluster = validate_label("cluster", data.get("cluster"))
    except ValueError as e:
        raise SpecError(str(e)) from e
    ttl = _int(data, "svid_ttl_seconds", MIN_SVID_TTL, MAX_SVID_TTL)
    regs, unregs = data.get("workloads"), data.get("unregistered", [])
    if not isinstance(regs, list) or not regs or not isinstance(unregs, list):
        raise SpecError("workloads must be a non-empty list and unregistered a list")
    workloads = tuple(_workload(w, True) for w in regs) + tuple(_workload(w, False) for w in unregs)
    spec = MeshSpec(td, cluster, ttl, workloads)
    names = [w.name for w in workloads]
    if len(set(names)) != len(names):
        raise SpecError("workload names must be unique")
    accounts = [(w.namespace, w.service_account) for w in workloads]
    if len(set(accounts)) != len(accounts):
        raise SpecError("two workloads share a namespace and service account (and so an identity)")
    for w in workloads:
        for c in w.allowed_callers:
            if not spec.get(c).registered:
                raise SpecError(f"{w.name}: caller {c!r} is unregistered and can never be allowed")
        for u in w.upstreams:
            up = spec.get(u)
            if up.port is None:
                raise SpecError(f"{w.name}: upstream {u!r} has no port")
            if w.registered and w.name not in up.allowed_callers:
                raise SpecError(f"{w.name}: calls {u!r} but is not in its allowed_callers")
    return spec


def load_spec(path: Path) -> MeshSpec:
    """Read, bound and validate a spec file."""
    size = path.stat().st_size
    if size > MAX_SPEC_BYTES:
        raise SpecError(f"{path}: {size} bytes is over the {MAX_SPEC_BYTES} limit")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SpecError(f"{path}: not valid JSON: {e}") from e
    return parse_spec(data)
