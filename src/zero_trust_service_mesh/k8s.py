"""Kubernetes manifests (kubectl List JSON) for SPIRE and the demo workloads in a kind cluster."""

from __future__ import annotations

import json
from typing import Any

from .envoy import ADMIN_DIR, bootstrap
from .mesh import MeshSpec, Workload
from .spire import HEALTH_PORT, SERVER_PORT, agent_conf, server_conf

IMAGES = {
    "spire-server": "ghcr.io/spiffe/spire-server:1.15.5@sha256:584a9c5cc95b9457f5033e7e4488d603fffe5ec48a80c4dba14b05c5e1c2c384",
    "spire-agent": "ghcr.io/spiffe/spire-agent:1.15.5@sha256:3652c732b0f0d36f4dd78394230a1b1cd0ddcc29548a46c67a996b1a78c14481",
    "envoy": "docker.io/envoyproxy/envoy:v1.39.5@sha256:8fc594a5d85eb76dca24155cfb9208882406873932b20cf33649a0a611194c43",
    "curl": "docker.io/curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777",
}
SOCKET_DIR = "/run/spire/sockets"


def _meta(name: str, namespace: str | None = None, **labels: str) -> dict[str, Any]:
    """Object metadata."""
    m: dict[str, Any] = {"name": name}
    if namespace:
        m["namespace"] = namespace
    if labels:
        m["labels"] = labels
    return m


def _obj(api: str, kind: str, meta: dict[str, Any], **body: Any) -> dict[str, Any]:
    """A Kubernetes object."""
    return {"apiVersion": api, "kind": kind, "metadata": meta, **body}


def _resources(cpu: str, mem: str) -> dict[str, Any]:
    """Small fixed requests and the given limits."""
    return {"requests": {"cpu": "25m", "memory": "32Mi"}, "limits": {"cpu": cpu, "memory": mem}}


def _hardened(uid: int | None, read_only: bool = True, drop_all: bool = True) -> dict[str, Any]:
    """Container security context: no privilege escalation, read-only root, no capabilities."""
    sc: dict[str, Any] = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": read_only}
    if drop_all:
        sc["capabilities"] = {"drop": ["ALL"]}
    if uid is not None:
        sc.update(runAsNonRoot=True, runAsUser=uid, runAsGroup=uid)
    return sc


def _probe(path: str, delay: int) -> dict[str, Any]:
    """HTTP probe on the SPIRE health port."""
    return {
        "httpGet": {"path": path, "port": HEALTH_PORT},
        "initialDelaySeconds": delay,
        "periodSeconds": 10,
        "timeoutSeconds": 3,
    }


def _rbac() -> list[dict[str, Any]]:
    """Least-privilege roles for the SPIRE server and agent."""
    rbac = "rbac.authorization.k8s.io/v1"
    return [
        _obj(
            rbac,
            "ClusterRole",
            _meta("spire-server"),
            rules=[
                {
                    "apiGroups": ["authentication.k8s.io"],
                    "resources": ["tokenreviews"],
                    "verbs": ["create"],
                },
                {"apiGroups": [""], "resources": ["pods", "nodes"], "verbs": ["get"]},
            ],
        ),
        _obj(
            rbac,
            "ClusterRoleBinding",
            _meta("spire-server"),
            subjects=[{"kind": "ServiceAccount", "name": "spire-server", "namespace": "spire"}],
            roleRef={
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "spire-server",
            },
        ),
        _obj(
            rbac,
            "Role",
            _meta("spire-bundle-writer", "spire"),
            rules=[
                {
                    "apiGroups": [""],
                    "resources": ["configmaps"],
                    "resourceNames": ["spire-bundle"],
                    "verbs": ["get", "patch"],
                },
            ],
        ),
        _obj(
            rbac,
            "RoleBinding",
            _meta("spire-bundle-writer", "spire"),
            subjects=[{"kind": "ServiceAccount", "name": "spire-server", "namespace": "spire"}],
            roleRef={
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": "spire-bundle-writer",
            },
        ),
        _obj(
            rbac,
            "ClusterRole",
            _meta("spire-agent"),
            rules=[
                {
                    "apiGroups": [""],
                    "resources": ["pods", "nodes", "nodes/proxy"],
                    "verbs": ["get"],
                },
            ],
        ),
        _obj(
            rbac,
            "ClusterRoleBinding",
            _meta("spire-agent"),
            subjects=[{"kind": "ServiceAccount", "name": "spire-agent", "namespace": "spire"}],
            roleRef={
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "spire-agent",
            },
        ),
    ]


def _server(spec: MeshSpec) -> list[dict[str, Any]]:
    """SPIRE server: ConfigMap, Service and a one-replica StatefulSet running as uid 1000."""
    labels = {"app": "spire-server"}
    pod = {
        "serviceAccountName": "spire-server",
        "securityContext": {
            "runAsNonRoot": True,
            "fsGroup": 1000,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [
            {
                "name": "spire-server",
                "image": IMAGES["spire-server"],
                "args": ["-config", "/run/spire/config/server.conf"],
                "ports": [
                    {"containerPort": SERVER_PORT, "name": "grpc"},
                    {"containerPort": HEALTH_PORT, "name": "health"},
                ],
                "livenessProbe": _probe("/live", 15),
                "readinessProbe": _probe("/ready", 5),
                "resources": _resources("500m", "256Mi"),
                "securityContext": _hardened(1000),
                "volumeMounts": [
                    {"name": "config", "mountPath": "/run/spire/config", "readOnly": True},
                    {"name": "data", "mountPath": "/run/spire/data"},
                    {"name": "tmp", "mountPath": "/tmp"},  # noqa: S108 - the server's admin socket, in an emptyDir
                ],
            }
        ],
        "volumes": [
            {"name": "config", "configMap": {"name": "spire-server"}},
            {"name": "data", "emptyDir": {}},
            {"name": "tmp", "emptyDir": {}},
        ],
    }
    return [
        _obj(
            "v1",
            "ConfigMap",
            _meta("spire-server", "spire"),
            data={"server.conf": server_conf(spec)},
        ),
        _obj(
            "v1",
            "Service",
            _meta("spire-server", "spire"),
            spec={
                "type": "ClusterIP",
                "selector": labels,
                "ports": [
                    {
                        "name": "grpc",
                        "port": SERVER_PORT,
                        "targetPort": SERVER_PORT,
                        "protocol": "TCP",
                    }
                ],
            },
        ),
        _obj(
            "apps/v1",
            "StatefulSet",
            _meta("spire-server", "spire", **labels),
            spec={
                "replicas": 1,
                "serviceName": "spire-server",
                "selector": {"matchLabels": labels},
                "template": {"metadata": {"labels": labels}, "spec": pod},
            },
        ),
    ]


def _agent(spec: MeshSpec) -> list[dict[str, Any]]:
    """SPIRE agent DaemonSet: host PID namespace to attest callers, socket shared through hostPath."""
    labels = {"app": "spire-agent"}
    pod = {
        "serviceAccountName": "spire-agent",
        "hostPID": True,
        "hostNetwork": True,
        "dnsPolicy": "ClusterFirstWithHostNet",
        "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [
            {
                "name": "spire-agent",
                "image": IMAGES["spire-agent"],
                "args": ["-config", "/run/spire/config/agent.conf"],
                "env": [
                    {
                        "name": "MY_NODE_NAME",
                        "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}},
                    }
                ],
                "livenessProbe": _probe("/live", 15),
                "readinessProbe": _probe("/ready", 5),
                "resources": _resources("500m", "256Mi"),
                "securityContext": _hardened(None, drop_all=False),
                "volumeMounts": [
                    {"name": "config", "mountPath": "/run/spire/config", "readOnly": True},
                    {"name": "bundle", "mountPath": "/run/spire/bundle", "readOnly": True},
                    {"name": "sockets", "mountPath": SOCKET_DIR},
                    {"name": "data", "mountPath": "/run/spire/data"},
                    {"name": "token", "mountPath": "/var/run/secrets/tokens", "readOnly": True},
                ],
            }
        ],
        "volumes": [
            {"name": "config", "configMap": {"name": "spire-agent"}},
            {"name": "bundle", "configMap": {"name": "spire-bundle"}},
            {"name": "sockets", "hostPath": {"path": SOCKET_DIR, "type": "DirectoryOrCreate"}},
            {"name": "data", "emptyDir": {}},
            {
                "name": "token",
                "projected": {
                    "sources": [
                        {
                            "serviceAccountToken": {
                                "path": "spire-agent",
                                "expirationSeconds": 7200,
                                "audience": "spire-server",
                            }
                        }
                    ]
                },
            },
        ],
    }
    return [
        _obj(
            "v1", "ConfigMap", _meta("spire-agent", "spire"), data={"agent.conf": agent_conf(spec)}
        ),
        _obj(
            "apps/v1",
            "DaemonSet",
            _meta("spire-agent", "spire", **labels),
            spec={
                "selector": {"matchLabels": labels},
                "template": {"metadata": {"labels": labels}, "spec": pod},
            },
        ),
    ]


def spire_manifests(spec: MeshSpec) -> dict[str, Any]:
    """Everything SPIRE needs, as one kubectl List."""
    items = [
        _obj("v1", "Namespace", _meta("spire")),
        _obj("v1", "ServiceAccount", _meta("spire-server", "spire")),
        _obj("v1", "ServiceAccount", _meta("spire-agent", "spire")),
        _obj("v1", "ConfigMap", _meta("spire-bundle", "spire")),
        *_rbac(),
        *_server(spec),
        *_agent(spec),
    ]
    return {"apiVersion": "v1", "kind": "List", "items": items}


def _deployment(spec: MeshSpec, w: Workload) -> dict[str, Any]:
    """Workload pod: Envoy sidecar (uid 101) and, for callers, a curl container as the app."""
    labels = {"app": w.name}
    containers: list[dict[str, Any]] = [
        {
            "name": "envoy",
            "image": IMAGES["envoy"],
            "args": ["-c", "/etc/envoy/envoy.json", "--log-level", "info"],
            "ports": [{"containerPort": w.port, "name": "mtls"}] if w.port else [],
            "resources": _resources("500m", "128Mi"),
            "securityContext": _hardened(101),
            "volumeMounts": [
                {"name": "envoy", "mountPath": "/etc/envoy", "readOnly": True},
                {"name": "envoy-admin", "mountPath": ADMIN_DIR},
                {"name": "spire-sockets", "mountPath": SOCKET_DIR, "readOnly": True},
            ],
        }
    ]
    if w.upstreams:
        containers.append(
            {
                "name": "app",
                "image": IMAGES["curl"],
                "command": ["sleep", "infinity"],
                "resources": _resources("100m", "64Mi"),
                "securityContext": _hardened(100),
            }
        )
    pod = {
        "serviceAccountName": w.service_account,
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": containers,
        "volumes": [
            {"name": "envoy", "configMap": {"name": f"envoy-{w.name}"}},
            {"name": "envoy-admin", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}},
            {"name": "spire-sockets", "hostPath": {"path": SOCKET_DIR, "type": "Directory"}},
        ],
    }
    return _obj(
        "apps/v1",
        "Deployment",
        _meta(w.name, w.namespace, **labels),
        spec={
            "replicas": 1,
            "selector": {"matchLabels": labels},
            "template": {"metadata": {"labels": labels}, "spec": pod},
        },
    )


def workload_manifests(spec: MeshSpec) -> dict[str, Any]:
    """Namespaces, service accounts, Envoy configs, Services and Deployments for every workload."""
    items: list[dict[str, Any]] = [
        _obj("v1", "Namespace", _meta(ns)) for ns in sorted({w.namespace for w in spec.workloads})
    ]
    for w in spec.workloads:
        items.append(
            _obj(
                "v1",
                "ServiceAccount",
                _meta(w.service_account, w.namespace),
                automountServiceAccountToken=False,
            )
        )
        items.append(
            _obj(
                "v1",
                "ConfigMap",
                _meta(f"envoy-{w.name}", w.namespace),
                data={
                    "envoy.json": json.dumps(bootstrap(spec, w), indent=2, sort_keys=True) + "\n"
                },
            )
        )
        if w.port is not None:
            items.append(
                _obj(
                    "v1",
                    "Service",
                    _meta(w.name, w.namespace),
                    spec={
                        "type": "ClusterIP",
                        "selector": {"app": w.name},
                        "ports": [
                            {
                                "name": "mtls",
                                "port": w.port,
                                "targetPort": w.port,
                                "protocol": "TCP",
                            }
                        ],
                    },
                )
            )
        items.append(_deployment(spec, w))
    return {"apiVersion": "v1", "kind": "List", "items": items}
