"""SPIFFE IDs as defined by the SPIFFE ID specification (spiffe://trust-domain/path)."""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_ID_BYTES = 2048
_TRUST_DOMAIN = re.compile(r"[a-z0-9._-]+")
_SEGMENT = re.compile(r"[A-Za-z0-9._-]+")
_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")


class SpiffeIdError(ValueError):
    """A string that is not a valid SPIFFE ID or trust domain."""


def validate_trust_domain(name: str) -> str:
    """Return the trust domain name or raise SpiffeIdError."""
    if not name or len(name) > 255 or not _TRUST_DOMAIN.fullmatch(name):
        raise SpiffeIdError(
            f"invalid trust domain {name!r}: lowercase letters, digits, '.', '-', '_' only"
        )
    return name


def validate_label(kind: str, value: object) -> str:
    """Return a Kubernetes DNS-1123 label or raise ValueError."""
    if not isinstance(value, str) or not _LABEL.fullmatch(value):
        raise ValueError(f"invalid {kind} {value!r}: a DNS-1123 label (a-z, 0-9, '-', at most 63)")
    return value


@dataclass(frozen=True, order=True)
class SpiffeId:
    """A parsed SPIFFE ID: trust domain plus path (empty or starting with '/')."""

    trust_domain: str
    path: str

    def __post_init__(self) -> None:
        """Reject IDs that break the spec."""
        validate_trust_domain(self.trust_domain)
        if self.path:
            if not self.path.startswith("/"):
                raise SpiffeIdError(f"path {self.path!r} must start with '/'")
            for segment in self.path[1:].split("/"):
                if segment in ("", ".", ".."):
                    raise SpiffeIdError(f"path {self.path!r} has an empty, '.' or '..' segment")
                if not _SEGMENT.fullmatch(segment):
                    raise SpiffeIdError(
                        f"path segment {segment!r} has characters outside [A-Za-z0-9._-]"
                    )
        if len(str(self).encode()) > MAX_ID_BYTES:
            raise SpiffeIdError(f"SPIFFE ID longer than {MAX_ID_BYTES} bytes")

    def __str__(self) -> str:
        """Canonical URI form."""
        return f"spiffe://{self.trust_domain}{self.path}"

    @property
    def trust_domain_id(self) -> str:
        """The trust domain's own ID (spiffe://td), used as the bundle name."""
        return f"spiffe://{self.trust_domain}"

    @classmethod
    def parse(cls, uri: str) -> SpiffeId:
        """Parse and validate a SPIFFE ID string."""
        if not isinstance(uri, str):
            raise SpiffeIdError("SPIFFE ID must be a string")
        if len(uri.encode()) > MAX_ID_BYTES:
            raise SpiffeIdError(f"SPIFFE ID longer than {MAX_ID_BYTES} bytes")
        prefix = "spiffe://"
        if not uri.startswith(prefix):
            raise SpiffeIdError(f"{uri!r}: scheme must be lowercase 'spiffe://'")
        rest = uri[len(prefix) :]
        if any(c in rest for c in "?#"):
            raise SpiffeIdError(f"{uri!r}: query and fragment are not allowed")
        td, slash, path = rest.partition("/")
        if any(c in td for c in "@:"):
            raise SpiffeIdError(f"{uri!r}: user info and port are not allowed")
        if not td:
            raise SpiffeIdError(f"{uri!r}: trust domain is missing")
        return cls(td, slash + path)

    @classmethod
    def for_service_account(
        cls, trust_domain: str, namespace: str, service_account: str
    ) -> SpiffeId:
        """The mesh's ID convention: spiffe://td/ns/<namespace>/sa/<service account>."""
        validate_label("namespace", namespace)
        validate_label("service account", service_account)
        return cls(trust_domain, f"/ns/{namespace}/sa/{service_account}")
