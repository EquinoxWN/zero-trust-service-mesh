"""SVID issuance and verification: lifetime, profile, trust domain and chain checks."""

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from zero_trust_service_mesh.ca import Bundle, IssueError, TrustDomainCA
from zero_trust_service_mesh.spiffe import SpiffeId
from zero_trust_service_mesh.verify import PeerPolicy, SvidError, spiffe_id_of, verify_svid

NOW = dt.datetime(2026, 11, 9, 12, 0, tzinfo=dt.UTC)
FRONT = SpiffeId("mesh.example", "/ns/demo/sa/frontend")


@pytest.fixture(scope="module")
def ca() -> TrustDomainCA:
    return TrustDomainCA("mesh.example", NOW - dt.timedelta(hours=1))


def test_issued_svid_verifies_and_names_the_workload(ca: TrustDomainCA) -> None:
    svid = ca.issue(FRONT, NOW)
    assert verify_svid(svid.cert, ca.bundle, NOW) == FRONT
    assert svid.cert.not_valid_after_utc - NOW == dt.timedelta(hours=1)
    ku = svid.cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature
    assert not ku.key_cert_sign
    assert b"PRIVATE KEY" in svid.key_pem()
    assert svid.cert_pem().startswith(b"-----BEGIN CERTIFICATE-----")


def test_svid_rejected_after_expiry_and_before_start(ca: TrustDomainCA) -> None:
    svid = ca.issue(FRONT, NOW, dt.timedelta(minutes=5))
    verify_svid(svid.cert, ca.bundle, NOW + dt.timedelta(minutes=4))
    with pytest.raises(SvidError, match="not valid"):
        verify_svid(svid.cert, ca.bundle, NOW + dt.timedelta(minutes=6))
    with pytest.raises(SvidError, match="not valid"):
        verify_svid(svid.cert, ca.bundle, NOW - dt.timedelta(minutes=1))


def test_svid_never_outlives_its_ca() -> None:
    short = TrustDomainCA("mesh.example", NOW, dt.timedelta(minutes=30))
    svid = short.issue(FRONT, NOW, dt.timedelta(hours=1))
    assert svid.cert.not_valid_after_utc == short.cert.not_valid_after_utc


def test_issue_refusals(ca: TrustDomainCA) -> None:
    with pytest.raises(IssueError, match="trust domain"):
        ca.issue(SpiffeId("other.example", "/x"), NOW)
    with pytest.raises(IssueError, match="needs a path"):
        ca.issue(SpiffeId("mesh.example", ""), NOW)
    with pytest.raises(IssueError, match="TTL"):
        ca.issue(FRONT, NOW, dt.timedelta(0))
    with pytest.raises(IssueError, match="TTL"):
        ca.issue(FRONT, NOW, dt.timedelta(hours=25))
    with pytest.raises(IssueError, match="CA is not valid"):
        ca.issue(FRONT, NOW + dt.timedelta(days=2))
    with pytest.raises(ValueError, match="UTC"):
        ca.issue(FRONT, NOW.replace(tzinfo=None))


def test_forged_svid_from_a_rogue_ca_with_the_same_name_fails(ca: TrustDomainCA) -> None:
    rogue = TrustDomainCA("mesh.example", NOW - dt.timedelta(hours=1))
    with pytest.raises(SvidError, match="chain does not verify"):
        verify_svid(rogue.issue(FRONT, NOW).cert, ca.bundle, NOW)


def test_foreign_trust_domain_fails_before_chain_check(ca: TrustDomainCA) -> None:
    other = TrustDomainCA("other.example", NOW - dt.timedelta(hours=1))
    svid = other.issue(SpiffeId("other.example", "/x"), NOW)
    with pytest.raises(SvidError, match="not in trust domain"):
        verify_svid(svid.cert, ca.bundle, NOW)


def test_empty_bundle_and_naive_time_fail(ca: TrustDomainCA) -> None:
    svid = ca.issue(FRONT, NOW)
    with pytest.raises(SvidError, match="empty"):
        verify_svid(svid.cert, Bundle("mesh.example", ()), NOW)
    with pytest.raises(ValueError, match="aware"):
        verify_svid(svid.cert, ca.bundle, NOW.replace(tzinfo=None))


def _leaf(
    ca: TrustDomainCA, uris: list[str], is_ca: bool = False, cert_sign: bool = False
) -> x509.Certificate:
    """A hand-made certificate signed by the CA's key, to break one SVID rule at a time."""
    key = ec.generate_private_key(ec.SECP256R1())
    b = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(ca.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(minutes=1))
        .not_valid_after(NOW + dt.timedelta(minutes=10))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, cert_sign, False, False, False),
            critical=True,
        )
    )
    if uris:
        b = b.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(u) for u in uris]),
            critical=True,
        )
    return b.sign(ca._key, hashes.SHA256())


def test_svid_profile_rules(ca: TrustDomainCA) -> None:
    with pytest.raises(SvidError, match="no subject alternative name"):
        spiffe_id_of(_leaf(ca, []))
    with pytest.raises(SvidError, match="exactly one URI SAN"):
        spiffe_id_of(_leaf(ca, [str(FRONT), "spiffe://mesh.example/ns/demo/sa/backend"]))
    with pytest.raises(SvidError, match="scheme"):
        spiffe_id_of(_leaf(ca, ["https://mesh.example/x"]))
    with pytest.raises(SvidError, match="bare trust domain"):
        spiffe_id_of(_leaf(ca, ["spiffe://mesh.example"]))
    with pytest.raises(SvidError, match="must not be a CA"):
        verify_svid(_leaf(ca, [str(FRONT)], is_ca=True), ca.bundle, NOW)
    with pytest.raises(SvidError, match="keyCertSign"):
        verify_svid(_leaf(ca, [str(FRONT)], cert_sign=True), ca.bundle, NOW)


def test_peer_policy_allows_only_listed_ids() -> None:
    policy = PeerPolicy(frozenset({FRONT}))
    assert policy.check(FRONT) == FRONT
    with pytest.raises(SvidError, match="not an allowed identity"):
        policy.check(SpiffeId("mesh.example", "/ns/demo/sa/reports"))
