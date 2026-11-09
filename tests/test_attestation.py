"""Workload attestation: an entry matches only when all its selectors are found under its parent."""

from pathlib import Path

import pytest

from zero_trust_service_mesh.attestation import (
    KubernetesWorkload,
    NoIdentityError,
    RegistrationEntry,
    Selector,
    attest,
    entries_for,
)
from zero_trust_service_mesh.mesh import load_spec
from zero_trust_service_mesh.spiffe import SpiffeId

SPEC = load_spec(Path(__file__).resolve().parents[1] / "deploy" / "mesh.json")
AGENT = SPEC.agent_id


def pod(ns: str, sa: str) -> KubernetesWorkload:
    return KubernetesWorkload(ns, sa, f"{sa}-abc", (("app", sa),))


def test_registered_workload_gets_its_own_id() -> None:
    [entry] = attest(pod("demo", "frontend"), entries_for(SPEC), AGENT)
    assert str(entry.spiffe_id) == "spiffe://mesh.example/ns/demo/sa/frontend"
    assert entry.x509_svid_ttl == 3600


def test_unregistered_service_account_gets_nothing() -> None:
    with pytest.raises(NoIdentityError, match="intruder"):
        attest(pod("demo", "intruder"), entries_for(SPEC), AGENT)


def test_right_service_account_in_wrong_namespace_gets_nothing() -> None:
    with pytest.raises(NoIdentityError):
        attest(pod("other", "frontend"), entries_for(SPEC), AGENT)


def test_entries_under_another_agent_are_not_served() -> None:
    other = SpiffeId("mesh.example", "/ns/spire/sa/other-agent")
    with pytest.raises(NoIdentityError):
        attest(pod("demo", "frontend"), entries_for(SPEC), other)


def test_extra_discovered_selectors_do_not_prevent_a_match() -> None:
    w = KubernetesWorkload("demo", "backend", "backend-1", (("app", "backend"), ("tier", "api")))
    assert attest(w, entries_for(SPEC), AGENT)[0].spiffe_id.path == "/ns/demo/sa/backend"


def test_selectors_emitted_by_the_k8s_attestor() -> None:
    sels = {str(s) for s in pod("demo", "frontend").selectors()}
    assert sels == {
        "k8s:ns:demo",
        "k8s:sa:frontend",
        "k8s:pod-name:frontend-abc",
        "k8s:pod-label:app:frontend",
    }


def test_entry_validation() -> None:
    sid = SpiffeId("mesh.example", "/x")
    with pytest.raises(ValueError, match="no selectors"):
        RegistrationEntry(sid, AGENT, frozenset(), 60)
    one = frozenset({Selector("k8s", "ns:demo")})
    with pytest.raises(ValueError, match="TTL"):
        RegistrationEntry(sid, AGENT, one, 0)
    with pytest.raises(ValueError, match="trust domain"):
        RegistrationEntry(SpiffeId("other.example", "/x"), AGENT, one, 60)
    with pytest.raises(ValueError, match="trust domain ID"):
        RegistrationEntry(SpiffeId("mesh.example", ""), AGENT, one, 60)
    with pytest.raises(ValueError, match="invalid selector"):
        Selector("k8s:ns", "demo")


def test_cli_args_for_spire_server() -> None:
    entry = entries_for(SPEC)[0]
    assert entry.cli_args() == [
        "entry",
        "create",
        "-spiffeID",
        "spiffe://mesh.example/ns/demo/sa/backend",
        "-parentID",
        "spiffe://mesh.example/ns/spire/sa/spire-agent",
        "-selector",
        "k8s:ns:demo",
        "-selector",
        "k8s:sa:backend",
        "-x509SVIDTTL",
        "3600",
    ]
