"""X.509-SVID verification: RFC 5280 path validation plus the SPIFFE X509-SVID rules."""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable
from dataclasses import dataclass

from cryptography import x509
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from .ca import Bundle
from .spiffe import SpiffeId, SpiffeIdError


class SvidError(ValueError):
    """The presented certificate is not a valid X.509-SVID for this bundle."""


def spiffe_id_of(cert: x509.Certificate) -> SpiffeId:
    """The single SPIFFE ID in the certificate's URI SAN, or SvidError."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as e:
        raise SvidError("certificate has no subject alternative name") from e
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1:
        raise SvidError(f"an X509-SVID has exactly one URI SAN, found {len(uris)}")
    try:
        sid = SpiffeId.parse(uris[0])
    except SpiffeIdError as e:
        raise SvidError(str(e)) from e
    if not sid.path:
        raise SvidError("a workload SVID cannot carry the bare trust domain ID")
    return sid


def _check_leaf_profile(cert: x509.Certificate) -> None:
    """Leaf rules from the X509-SVID spec: not a CA, may sign, may not sign certificates."""
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as e:
        raise SvidError(f"leaf lacks a required extension: {e}") from e
    if bc.ca:
        raise SvidError("leaf SVID must not be a CA")
    if not ku.digital_signature:
        raise SvidError("leaf SVID must allow digitalSignature")
    if ku.key_cert_sign or ku.crl_sign:
        raise SvidError("leaf SVID must not allow keyCertSign or cRLSign")


def verify_svid(
    leaf: x509.Certificate,
    bundle: Bundle,
    now: dt.datetime,
    intermediates: Iterable[x509.Certificate] = (),
) -> SpiffeId:
    """Validate the chain to the bundle at time now and return the peer's SPIFFE ID."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if not bundle.roots:
        raise SvidError(f"bundle for {bundle.trust_domain} is empty")
    sid = spiffe_id_of(leaf)
    if sid.trust_domain != bundle.trust_domain:
        raise SvidError(f"{sid} is not in trust domain {bundle.trust_domain}")
    _check_leaf_profile(leaf)
    verifier = (
        PolicyBuilder()
        .store(Store(list(bundle.roots)))
        .time(now)
        .max_chain_depth(4)
        .build_client_verifier()
    )
    try:
        verifier.verify(leaf, list(intermediates))
    except VerificationError as e:
        raise SvidError(f"chain does not verify against {bundle.trust_domain}: {e}") from e
    return sid


@dataclass(frozen=True)
class PeerPolicy:
    """Which SPIFFE IDs may be on the other end of a connection (Envoy's SAN matcher)."""

    allowed: frozenset[SpiffeId]

    def check(self, peer: SpiffeId) -> SpiffeId:
        """Return peer if allowed, otherwise SvidError."""
        if peer not in self.allowed:
            raise SvidError(f"peer {peer} is not an allowed identity")
        return peer
