"""A trust domain CA that issues X.509-SVIDs the way a SPIRE server does (signed by its CA)."""

from __future__ import annotations

import datetime as dt
import secrets
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .spiffe import SpiffeId, validate_trust_domain

DEFAULT_CA_TTL = dt.timedelta(hours=24)
DEFAULT_SVID_TTL = dt.timedelta(hours=1)
MAX_SVID_TTL = dt.timedelta(hours=24)
BACKDATE = dt.timedelta(seconds=10)
ORG = "zero-trust-service-mesh"


class IssueError(ValueError):
    """The CA refused to issue an SVID."""


def _utc(now: dt.datetime) -> dt.datetime:
    """Require an aware UTC timestamp."""
    if now.tzinfo is None or now.utcoffset() != dt.timedelta(0):
        raise ValueError("timestamps must be timezone-aware UTC")
    return now


def _pem(cert: x509.Certificate) -> bytes:
    """PEM encoding of a certificate."""
    return cert.public_bytes(serialization.Encoding.PEM)


@dataclass(frozen=True)
class Bundle:
    """The trust bundle of one trust domain: the root certificates peers verify against."""

    trust_domain: str
    roots: tuple[x509.Certificate, ...]

    def pem(self) -> bytes:
        """All roots, PEM concatenated."""
        return b"".join(_pem(c) for c in self.roots)


@dataclass(frozen=True)
class X509Svid:
    """A workload's identity document: leaf certificate, private key and SPIFFE ID."""

    spiffe_id: SpiffeId
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey

    def cert_pem(self) -> bytes:
        """Leaf certificate as PEM."""
        return _pem(self.cert)

    def key_pem(self) -> bytes:
        """Private key as unencrypted PKCS#8 PEM (written with owner-only permissions)."""
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


class TrustDomainCA:
    """Self-signed root for one trust domain, as SPIRE uses without an upstream authority."""

    def __init__(self, trust_domain: str, now: dt.datetime, ttl: dt.timedelta = DEFAULT_CA_TTL):
        """Create a fresh P-256 key and root certificate valid from now for ttl."""
        validate_trust_domain(trust_domain)
        _utc(now)
        if ttl <= dt.timedelta(0):
            raise ValueError("CA TTL must be positive")
        self.trust_domain = trust_domain
        self._key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
                x509.NameAttribute(NameOID.COMMON_NAME, f"{trust_domain} CA"),
            ]
        )
        ski = x509.SubjectKeyIdentifier.from_public_key(self._key.public_key())
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - BACKDATE)
            .not_valid_after(now + ttl)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(ski, critical=False)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(f"spiffe://{trust_domain}")]
                ),
                critical=False,
            )
            .sign(self._key, hashes.SHA256())
        )

    @property
    def bundle(self) -> Bundle:
        """The bundle peers use to verify SVIDs from this CA."""
        return Bundle(self.trust_domain, (self.cert,))

    def issue(
        self,
        spiffe_id: SpiffeId,
        now: dt.datetime,
        ttl: dt.timedelta = DEFAULT_SVID_TTL,
        key: ec.EllipticCurvePrivateKey | None = None,
    ) -> X509Svid:
        """Sign an X.509-SVID for spiffe_id, valid for ttl but never beyond the CA itself."""
        _utc(now)
        if spiffe_id.trust_domain != self.trust_domain:
            raise IssueError(f"{spiffe_id} is not in trust domain {self.trust_domain}")
        if not spiffe_id.path:
            raise IssueError("an SVID needs a path; the trust domain ID is not a workload")
        if not dt.timedelta(0) < ttl <= MAX_SVID_TTL:
            raise IssueError(f"SVID TTL {ttl} outside (0, {MAX_SVID_TTL}]")
        if not self.cert.not_valid_before_utc <= now < self.cert.not_valid_after_utc:
            raise IssueError("the CA is not valid at this time")
        key = key or ec.generate_private_key(ec.SECP256R1())
        not_after = min(now + ttl, self.cert.not_valid_after_utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
                        x509.NameAttribute(NameOID.SERIAL_NUMBER, secrets.token_hex(8)),
                    ]
                )
            )
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(max(now - BACKDATE, self.cert.not_valid_before_utc))
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(str(spiffe_id))]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()),
                critical=False,
            )
            .sign(self._key, hashes.SHA256())
        )
        return X509Svid(spiffe_id, cert, key)
