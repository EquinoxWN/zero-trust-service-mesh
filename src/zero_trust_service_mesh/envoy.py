"""Envoy sidecar bootstrap: SVID and bundle from the SPIRE agent over SDS, mTLS both ways."""

from __future__ import annotations

from typing import Any

from .mesh import MeshSpec, Workload

AGENT_SOCKET = "/run/spire/sockets/agent.sock"
ADMIN_DIR = "/var/run/envoy-admin"
ADMIN_SOCKET = f"{ADMIN_DIR}/admin.sock"
SPIRE_CLUSTER = "spire_agent"
T = "type.googleapis.com/envoy."


def _sds(name: str) -> dict[str, Any]:
    """An SDS secret reference served by the SPIRE agent."""
    return {
        "name": name,
        "sds_config": {
            "resource_api_version": "V3",
            "api_config_source": {
                "api_type": "GRPC",
                "transport_api_version": "V3",
                "grpc_services": [{"envoy_grpc": {"cluster_name": SPIRE_CLUSTER}}],
            },
        },
    }


def tls_context(spec: MeshSpec, w: Workload, peers: list[str]) -> dict[str, Any]:
    """Common TLS: present w's SVID, trust the domain bundle, accept only the listed peer IDs."""
    if not peers:
        raise ValueError(f"{w.name}: a TLS context needs at least one allowed peer")
    td_id = f"spiffe://{spec.trust_domain}"
    return {
        "tls_params": {"tls_minimum_protocol_version": "TLSv1_3"},
        "tls_certificate_sds_secret_configs": [_sds(str(w.spiffe_id(spec.trust_domain)))],
        "combined_validation_context": {
            "default_validation_context": {
                "match_typed_subject_alt_names": [
                    {"san_type": "URI", "matcher": {"exact": p}} for p in sorted(peers)
                ]
            },
            "validation_context_sds_secret_config": _sds(td_id),
        },
    }


def _hcm(prefix: str, route: dict[str, Any], extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """HTTP connection manager filter with one catch-all virtual host."""
    cfg: dict[str, Any] = {
        "@type": T + "extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
        "stat_prefix": prefix,
        "request_timeout": "10s",
        "route_config": {
            "name": prefix,
            "virtual_hosts": [
                {"name": prefix, "domains": ["*"], "routes": [{"match": {"prefix": "/"}, **route}]}
            ],
        },
        "http_filters": [
            {
                "name": "envoy.filters.http.router",
                "typed_config": {"@type": T + "extensions.filters.http.router.v3.Router"},
            }
        ],
    }
    cfg.update(extra or {})
    return {"name": "envoy.filters.network.http_connection_manager", "typed_config": cfg}


def _addr(host: str, port: int) -> dict[str, Any]:
    """Socket address."""
    return {"socket_address": {"address": host, "port_value": port}}


def _spire_cluster() -> dict[str, Any]:
    """Static cluster for the SPIRE agent's SDS API on its Unix socket (HTTP/2)."""
    return {
        "name": SPIRE_CLUSTER,
        "connect_timeout": "1s",
        "type": "STATIC",
        "typed_extension_protocol_options": {
            "envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
                "@type": T + "extensions.upstreams.http.v3.HttpProtocolOptions",
                "explicit_http_config": {"http2_protocol_options": {}},
            }
        },
        "load_assignment": {
            "cluster_name": SPIRE_CLUSTER,
            "endpoints": [
                {"lb_endpoints": [{"endpoint": {"address": {"pipe": {"path": AGENT_SOCKET}}}}]}
            ],
        },
    }


def inbound_listener(spec: MeshSpec, w: Workload) -> dict[str, Any]:
    """mTLS listener on w's port; answers directly and echoes the caller's SPIFFE ID."""
    if w.port is None:
        raise ValueError(f"{w.name} has no port to listen on")
    td = spec.trust_domain
    peers = [str(spec.get(c).spiffe_id(td)) for c in w.allowed_callers]
    route = {
        "direct_response": {"status": 200, "body": {"inline_string": f"hello from {w.name}\n"}},
        "response_headers_to_add": [
            {"header": {"key": "x-peer-spiffe-id", "value": "%DOWNSTREAM_PEER_URI_SAN%"}},
            {"header": {"key": "x-local-spiffe-id", "value": "%DOWNSTREAM_LOCAL_URI_SAN%"}},
            {"header": {"key": "x-peer-cert-not-after", "value": "%DOWNSTREAM_PEER_CERT_V_END%"}},
        ],
    }
    return {
        "name": f"inbound_{w.name}",
        "address": _addr("0.0.0.0", w.port),  # noqa: S104 - the pod's mTLS port, reached through its Service
        "filter_chains": [
            {
                "filters": [_hcm(f"inbound_{w.name}", route)],
                "transport_socket": {
                    "name": "envoy.transport_sockets.tls",
                    "typed_config": {
                        "@type": T + "extensions.transport_sockets.tls.v3.DownstreamTlsContext",
                        "require_client_certificate": True,
                        "common_tls_context": tls_context(spec, w, peers),
                    },
                },
            }
        ],
    }


def outbound(spec: MeshSpec, w: Workload, upstream: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Plain-text listener on 127.0.0.1 for the app, and an mTLS cluster to the upstream."""
    up = spec.get(upstream)
    if up.port is None:
        raise ValueError(f"upstream {upstream} has no port")
    name = f"outbound_{up.name}"
    listener = {
        "name": name,
        "address": _addr("127.0.0.1", spec.outbound_port(upstream)),
        "filter_chains": [{"filters": [_hcm(name, {"route": {"cluster": name, "timeout": "5s"}})]}],
    }
    cluster = {
        "name": name,
        "connect_timeout": "2s",
        "type": "STRICT_DNS",
        "load_assignment": {
            "cluster_name": name,
            "endpoints": [
                {"lb_endpoints": [{"endpoint": {"address": _addr(up.dns_name, up.port)}}]}
            ],
        },
        "transport_socket": {
            "name": "envoy.transport_sockets.tls",
            "typed_config": {
                "@type": T + "extensions.transport_sockets.tls.v3.UpstreamTlsContext",
                "common_tls_context": tls_context(spec, w, [str(up.spiffe_id(spec.trust_domain))]),
            },
        },
    }
    return listener, cluster


def bootstrap(spec: MeshSpec, w: Workload) -> dict[str, Any]:
    """Full static bootstrap for w's sidecar."""
    listeners: list[dict[str, Any]] = []
    clusters: list[dict[str, Any]] = [_spire_cluster()]
    if w.port is not None:
        listeners.append(inbound_listener(spec, w))
    for u in w.upstreams:
        lis, clu = outbound(spec, w, u)
        listeners.append(lis)
        clusters.append(clu)
    return {
        "node": {"id": w.name, "cluster": w.name},
        # Admin on a Unix socket in a volume only the envoy container mounts: the app container
        # shares the pod network and could otherwise reach the unauthenticated admin API.
        "admin": {"address": {"pipe": {"path": ADMIN_SOCKET, "mode": 0o600}}},
        "static_resources": {"listeners": listeners, "clusters": clusters},
    }
