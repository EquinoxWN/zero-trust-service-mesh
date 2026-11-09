"""Local end-to-end run: attest workloads from the spec, issue SVIDs, and run real mTLS handshakes."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path

from .attestation import KubernetesWorkload, NoIdentityError, attest, entries_for
from .ca import TrustDomainCA, X509Svid
from .mesh import MeshSpec
from .mtls import Clock, Decision, Endpoint, connect, utc_now
from .spiffe import SpiffeId
from .verify import PeerPolicy


@dataclass(frozen=True)
class Scenario:
    """One connection attempt and the verdict it must get."""

    name: str
    expect_allowed: bool
    server: Decision
    client: Decision

    @property
    def allowed(self) -> bool:
        """True when both sides accepted the other."""
        return self.server.verdict == "allow" and self.client.verdict == "allow"

    @property
    def as_expected(self) -> bool:
        """True when the outcome matches the expectation."""
        return self.allowed == self.expect_allowed


def _pod(spec: MeshSpec, name: str) -> KubernetesWorkload:
    """What the kubelet would report for this workload's pod."""
    w = spec.get(name)
    return KubernetesWorkload(w.namespace, w.service_account, f"{w.name}-0", (("app", w.name),))


def svid_for(spec: MeshSpec, ca: TrustDomainCA, name: str, now: dt.datetime) -> X509Svid:
    """Attest the workload's pod and issue the SVID of its first matching entry."""
    entry = attest(_pod(spec, name), entries_for(spec), spec.agent_id)[0]
    return ca.issue(entry.spiffe_id, now, dt.timedelta(seconds=entry.x509_svid_ttl))


def run_demo(
    spec: MeshSpec,
    server_name: str,
    client_name: str,
    intruder_name: str,
    workdir: Path,
    clock: Clock = utc_now,
) -> list[Scenario]:
    """Allowed call, then five refused ones: no identity, forged CA, expired, unlisted caller, wrong server."""
    now = clock()
    td = spec.trust_domain
    ca = TrustDomainCA(td, now - dt.timedelta(hours=3))
    server_w, client_w = spec.get(server_name), spec.get(client_name)
    server_id, client_id = server_w.spiffe_id(td), client_w.spiffe_id(td)
    server_policy = PeerPolicy(
        frozenset(spec.get(c).spiffe_id(td) for c in server_w.allowed_callers)
    )
    client_policy = PeerPolicy(frozenset({server_id}))
    server_svid = svid_for(spec, ca, server_name, now)
    client_svid = svid_for(spec, ca, client_name, now)
    server = Endpoint(server_name, server_svid, ca.bundle, server_policy)

    def client(label: str, svid: X509Svid | None, policy: PeerPolicy = client_policy) -> Endpoint:
        """A client endpoint trusting the real bundle."""
        return Endpoint(label, svid, ca.bundle, policy)

    out: list[Scenario] = []

    def run(name: str, expect: bool, srv: Endpoint, cli: Endpoint) -> None:
        """Connect once and record the scenario."""
        s, c = connect(srv, cli, workdir, clock=clock)
        out.append(Scenario(name, expect, s, c))

    run(
        f"{client_name} -> {server_name} (both SVIDs valid)",
        True,
        server,
        client(client_name, client_svid),
    )

    try:
        intruder_svid: X509Svid | None = svid_for(spec, ca, intruder_name, now)
    except NoIdentityError:
        intruder_svid = None
    run(
        f"{intruder_name} -> {server_name} (no registration entry, so no SVID)",
        False,
        server,
        client(intruder_name, intruder_svid),
    )

    rogue = TrustDomainCA(td, now)
    forged = rogue.issue(client_id, now)
    run(
        f"forged {client_name} SVID from a rogue CA -> {server_name}",
        False,
        server,
        client("forged", forged),
    )

    expired = ca.issue(client_id, now - dt.timedelta(hours=2), dt.timedelta(hours=1))
    run(
        f"{client_name} with an expired SVID -> {server_name}",
        False,
        server,
        client("expired", expired),
    )

    unlisted = ca.issue(SpiffeId(td, "/ns/demo/sa/reports"), now)
    run(
        f"valid SVID not in {server_name}'s allowed callers -> {server_name}",
        False,
        server,
        client("reports", unlisted),
    )

    impostor = Endpoint("impostor", unlisted, ca.bundle, server_policy)
    run(
        f"{client_name} -> server presenting another workload's SVID",
        False,
        impostor,
        client(client_name, client_svid),
    )
    return out
