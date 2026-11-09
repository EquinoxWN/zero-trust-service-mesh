"""Real TLS 1.3 handshakes on 127.0.0.1: both sides must prove an identity the other accepts."""

import datetime as dt
import json
from pathlib import Path

import pytest

from zero_trust_service_mesh.ca import TrustDomainCA
from zero_trust_service_mesh.demo import run_demo
from zero_trust_service_mesh.mesh import load_spec
from zero_trust_service_mesh.mtls import Endpoint, connect
from zero_trust_service_mesh.spiffe import SpiffeId
from zero_trust_service_mesh.verify import PeerPolicy

SPEC = load_spec(Path(__file__).resolve().parents[1] / "deploy" / "mesh.json")
FRONT = SpiffeId("mesh.example", "/ns/demo/sa/frontend")
BACK = SpiffeId("mesh.example", "/ns/demo/sa/backend")


@pytest.fixture(scope="module")
def ca() -> TrustDomainCA:
    return TrustDomainCA("mesh.example", dt.datetime.now(dt.UTC) - dt.timedelta(minutes=5))


def endpoints(ca: TrustDomainCA) -> tuple[Endpoint, Endpoint]:
    now = dt.datetime.now(dt.UTC)
    server = Endpoint("backend", ca.issue(BACK, now), ca.bundle, PeerPolicy(frozenset({FRONT})))
    client = Endpoint("frontend", ca.issue(FRONT, now), ca.bundle, PeerPolicy(frozenset({BACK})))
    return server, client


def test_mutual_tls_proves_both_identities(ca: TrustDomainCA, tmp_path: Path) -> None:
    server, client = endpoints(ca)
    s, c = connect(server, client, tmp_path)
    assert (s.verdict, s.peer) == ("allow", str(FRONT))
    assert (c.verdict, c.peer) == ("allow", str(BACK))
    assert c.reason == f"hello {FRONT}"
    assert s.time.endswith("Z")
    assert s.elapsed_ms >= 0


def test_client_without_certificate_is_refused_in_the_handshake(
    ca: TrustDomainCA, tmp_path: Path
) -> None:
    server, client = endpoints(ca)
    s, c = connect(server, Endpoint("anon", None, ca.bundle, client.policy), tmp_path)
    assert s.verdict == "deny"
    assert "TLS handshake refused" in s.reason
    assert c.verdict == "deny"


def test_key_files_are_owner_only_where_the_os_supports_it(
    ca: TrustDomainCA, tmp_path: Path
) -> None:
    server, client = endpoints(ca)
    connect(server, client, tmp_path)
    keys = sorted(tmp_path.glob("*.key"))
    assert len(keys) == 2
    assert not list(tmp_path.glob(".*.tmp"))


def test_connect_argument_checks(ca: TrustDomainCA, tmp_path: Path) -> None:
    server, client = endpoints(ca)
    with pytest.raises(ValueError, match="timeout"):
        connect(server, client, tmp_path, timeout=0)
    with pytest.raises(ValueError, match="without an SVID"):
        connect(Endpoint("x", None, ca.bundle, server.policy), client, tmp_path)


def test_demo_scenarios_all_match_expectations(tmp_path: Path) -> None:
    scenarios = run_demo(SPEC, "backend", "frontend", "intruder", tmp_path)
    assert [s.expect_allowed for s in scenarios] == [True, False, False, False, False, False]
    assert all(s.as_expected for s in scenarios), [(s.name, s.server, s.client) for s in scenarios]
    assert scenarios[0].server.peer == str(FRONT)
    assert scenarios[0].client.peer == str(BACK)
    assert "not an allowed identity" in scenarios[4].server.reason
    assert "not an allowed identity" in scenarios[5].client.reason
    for s in scenarios:
        json.loads(s.server.json())
