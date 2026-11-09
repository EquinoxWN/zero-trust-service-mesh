"""SPIRE's registration and workload attestation semantics, as a small reference model.

An entry matches a workload when every selector on the entry is among the selectors the agent
discovered for the workload, and the entry is parented to the agent that is asking.
"""

from __future__ import annotations

from dataclasses import dataclass

from .mesh import MeshSpec
from .spiffe import SpiffeId


class NoIdentityError(LookupError):
    """No registration entry matches the workload, so it gets no SVID."""


@dataclass(frozen=True, order=True)
class Selector:
    """A typed attribute such as k8s:ns:demo."""

    type: str
    value: str

    def __post_init__(self) -> None:
        """Reject empty parts and separators in the type."""
        if not self.type or not self.value or ":" in self.type:
            raise ValueError(f"invalid selector {self.type!r}:{self.value!r}")

    def __str__(self) -> str:
        """SPIRE CLI form type:value."""
        return f"{self.type}:{self.value}"


@dataclass(frozen=True)
class KubernetesWorkload:
    """What the k8s workload attestor learns about a calling process from the kubelet."""

    namespace: str
    service_account: str
    pod_name: str
    labels: tuple[tuple[str, str], ...] = ()

    def selectors(self) -> frozenset[Selector]:
        """The selectors SPIRE's k8s workload attestor would emit."""
        out = {
            Selector("k8s", f"ns:{self.namespace}"),
            Selector("k8s", f"sa:{self.service_account}"),
            Selector("k8s", f"pod-name:{self.pod_name}"),
        }
        out.update(Selector("k8s", f"pod-label:{k}:{v}") for k, v in self.labels)
        return frozenset(out)


@dataclass(frozen=True)
class RegistrationEntry:
    """Maps a selector set, under one parent (agent), to a SPIFFE ID with a TTL."""

    spiffe_id: SpiffeId
    parent_id: SpiffeId
    selectors: frozenset[Selector]
    x509_svid_ttl: int

    def __post_init__(self) -> None:
        """An entry without selectors would match every workload: refuse it."""
        if not self.selectors:
            raise ValueError(f"entry for {self.spiffe_id} has no selectors")
        if self.x509_svid_ttl <= 0:
            raise ValueError(f"entry for {self.spiffe_id} has a non-positive TTL")
        if self.spiffe_id.trust_domain != self.parent_id.trust_domain:
            raise ValueError(f"entry for {self.spiffe_id} is parented outside its trust domain")
        if not self.spiffe_id.path:
            raise ValueError("an entry cannot issue the trust domain ID itself")

    def matches(self, discovered: frozenset[Selector]) -> bool:
        """True when every entry selector was discovered for the workload."""
        return self.selectors <= discovered

    def cli_args(self) -> list[str]:
        """Arguments for `spire-server entry create`."""
        args = [
            "entry",
            "create",
            "-spiffeID",
            str(self.spiffe_id),
            "-parentID",
            str(self.parent_id),
        ]
        for s in sorted(self.selectors):
            args += ["-selector", str(s)]
        return [*args, "-x509SVIDTTL", str(self.x509_svid_ttl)]


def node_selectors(spec: MeshSpec) -> list[Selector]:
    """Selectors of the node alias: agents attested by k8s_psat with the agent service account."""
    return [
        Selector("k8s_psat", f"cluster:{spec.cluster}"),
        Selector("k8s_psat", "agent_ns:spire"),
        Selector("k8s_psat", "agent_sa:spire-agent"),
    ]


def entries_for(spec: MeshSpec) -> list[RegistrationEntry]:
    """One entry per registered workload, selected by namespace and service account."""
    return [
        RegistrationEntry(
            spiffe_id=w.spiffe_id(spec.trust_domain),
            parent_id=spec.agent_id,
            selectors=frozenset(
                {Selector("k8s", f"ns:{w.namespace}"), Selector("k8s", f"sa:{w.service_account}")}
            ),
            x509_svid_ttl=spec.svid_ttl_seconds,
        )
        for w in spec.registered
    ]


def attest(
    workload: KubernetesWorkload, entries: list[RegistrationEntry], agent_id: SpiffeId
) -> list[RegistrationEntry]:
    """Entries the agent may serve to this workload; NoIdentityError when there are none."""
    found = workload.selectors()
    matched = [e for e in entries if e.parent_id == agent_id and e.matches(found)]
    if not matched:
        raise NoIdentityError(
            f"no registration entry for pod {workload.pod_name} "
            f"(ns {workload.namespace}, sa {workload.service_account}) under {agent_id}"
        )
    return sorted(matched, key=lambda e: e.spiffe_id)
