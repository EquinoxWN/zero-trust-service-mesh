"""Mutual TLS between two local endpoints that each present an X.509-SVID.

This is what an Envoy sidecar pair does, reduced to Python's ssl module: TLS 1.3, both sides must
present a certificate that chains to the trust bundle, and each side then checks the peer's
SPIFFE ID against the identities it expects.
"""

from __future__ import annotations

import datetime as dt
import json
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography import x509

from .ca import Bundle, X509Svid
from .files import write_atomic
from .verify import PeerPolicy, SvidError, verify_svid

Clock = Callable[[], dt.datetime]
MAX_MESSAGE = 4096


def utc_now() -> dt.datetime:
    """Current time in UTC."""
    return dt.datetime.now(dt.UTC)


@dataclass(frozen=True)
class Decision:
    """One side's verdict on one connection, as written to the decision log."""

    time: str
    side: str
    local: str
    peer: str | None
    verdict: str
    reason: str
    elapsed_ms: float

    def json(self) -> str:
        """One JSON line."""
        return json.dumps(asdict(self), sort_keys=True)


@dataclass(frozen=True)
class Endpoint:
    """A side of the connection: a label, its SVID (None if it has no identity), and its policy."""

    label: str
    svid: X509Svid | None
    bundle: Bundle
    policy: PeerPolicy


def _write_svid(svid: X509Svid, workdir: Path, label: str) -> tuple[Path, Path]:
    """Write the SVID's certificate and key (owner-only) for ssl to load."""
    cert, key = workdir / f"{label}.crt", workdir / f"{label}.key"
    write_atomic(cert, svid.cert_pem())
    write_atomic(key, svid.key_pem(), mode=0o600)
    return cert, key


def _context(ep: Endpoint, server: bool, workdir: Path) -> ssl.SSLContext:
    """TLS 1.3 context that presents ep's SVID and requires a certificate from the peer."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False  # SPIFFE identities are URI SANs, checked by PeerPolicy below
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=ep.bundle.pem().decode())
    if ep.svid is not None:
        cert, key = _write_svid(ep.svid, workdir, f"{ep.label}-{'srv' if server else 'cli'}")
        ctx.load_cert_chain(cert, key)
    return ctx


def _peer_identity(tls: ssl.SSLSocket, ep: Endpoint, clock: Clock) -> str:
    """Verify the peer's leaf as an SVID and apply the policy; return its ID."""
    der = tls.getpeercert(binary_form=True)
    if der is None:
        raise SvidError("peer presented no certificate")
    leaf = x509.load_der_x509_certificate(der)
    return str(ep.policy.check(verify_svid(leaf, ep.bundle, clock())))


def _decide(
    side: str, ep: Endpoint, peer: str | None, ok: bool, reason: str, t0: float, clock: Clock
) -> Decision:
    """Build a decision record with a UTC time and a monotonic duration."""
    return Decision(
        time=clock().isoformat().replace("+00:00", "Z"),
        side=side,
        local=ep.label,
        peer=peer,
        verdict="allow" if ok else "deny",
        reason=reason,
        elapsed_ms=round((time.monotonic() - t0) * 1000, 2),
    )


def _serve_one(
    listener: socket.socket,
    ctx: ssl.SSLContext,
    ep: Endpoint,
    timeout: float,
    clock: Clock,
    out: list[Decision],
) -> None:
    """Accept one connection, run the handshake and record the server's verdict."""
    t0 = time.monotonic()
    try:
        raw, _ = listener.accept()
    except OSError as e:
        out.append(_decide("server", ep, None, False, f"accept failed: {e}", t0, clock))
        return
    raw.settimeout(timeout)
    try:
        with ctx.wrap_socket(raw, server_side=True) as tls:
            peer = _peer_identity(tls, ep, clock)
            tls.recv(MAX_MESSAGE)
            tls.sendall(f"hello {peer}\n".encode())
            out.append(_decide("server", ep, peer, True, "peer SVID valid and allowed", t0, clock))
    except (ssl.SSLError, SvidError, OSError) as e:
        out.append(_decide("server", ep, None, False, _reason(e), t0, clock))
    finally:
        raw.close()


def _reason(e: BaseException) -> str:
    """Short text for a refused connection."""
    if isinstance(e, ssl.SSLError):
        return f"TLS handshake refused: {e.reason or e}"
    return f"{type(e).__name__}: {e}"


def connect(
    server: Endpoint, client: Endpoint, workdir: Path, timeout: float = 5.0, clock: Clock = utc_now
) -> tuple[Decision, Decision]:
    """Run one mTLS connection over 127.0.0.1 and return (server, client) decisions."""
    if not 0 < timeout <= 60:
        raise ValueError("timeout must be in (0, 60] seconds")
    workdir.mkdir(parents=True, exist_ok=True)
    if server.svid is None:
        raise ValueError("a server without an SVID cannot terminate mTLS")
    sctx, cctx = _context(server, True, workdir), _context(client, False, workdir)
    results: list[Decision] = []
    with socket.create_server(("127.0.0.1", 0)) as listener:
        listener.settimeout(timeout)
        port = listener.getsockname()[1]
        thread = threading.Thread(
            target=_serve_one, args=(listener, sctx, server, timeout, clock, results), daemon=True
        )
        thread.start()
        cdec = _client(port, cctx, client, timeout, clock)
        thread.join(timeout * 2)
        if thread.is_alive():
            raise TimeoutError("server side did not finish")
    return results[0], cdec


def _client(port: int, ctx: ssl.SSLContext, ep: Endpoint, timeout: float, clock: Clock) -> Decision:
    """Connect, verify the server's SVID, send one request and record the client's verdict."""
    t0 = time.monotonic()
    try:
        with (
            socket.create_connection(("127.0.0.1", port), timeout=timeout) as raw,
            ctx.wrap_socket(raw) as tls,
        ):
            peer = _peer_identity(tls, ep, clock)
            tls.sendall(b"GET /\n")
            reply = tls.recv(MAX_MESSAGE)
            if not reply:
                raise ConnectionError("server closed the connection")
            return _decide(
                "client", ep, peer, True, reply.decode(errors="replace").strip(), t0, clock
            )
    except (ssl.SSLError, SvidError, OSError) as e:
        return _decide("client", ep, None, False, _reason(e), t0, clock)
