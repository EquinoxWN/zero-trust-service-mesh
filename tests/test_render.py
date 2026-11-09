"""Generated SPIRE, Envoy and Kubernetes configs: the security properties M1 relies on."""

import json
from pathlib import Path
from typing import Any

import pytest

from zero_trust_service_mesh.envoy import AGENT_SOCKET, bootstrap, tls_context
from zero_trust_service_mesh.k8s import IMAGES, spire_manifests, workload_manifests
from zero_trust_service_mesh.mesh import load_spec
from zero_trust_service_mesh.render import render, stale_files, write_all
from zero_trust_service_mesh.spire import _q, agent_conf, register_script, server_conf

ROOT = Path(__file__).resolve().parents[1]
SPEC = load_spec(ROOT / "deploy" / "mesh.json")


def walk(obj: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if isinstance(obj, dict):
        out.append(obj)
        for v in obj.values():
            out += walk(v)
    elif isinstance(obj, list):
        for v in obj:
            out += walk(v)
    return out


def test_committed_generated_files_are_current() -> None:
    assert stale_files(SPEC, ROOT / "deploy" / "generated") == []


def test_write_all_is_idempotent(tmp_path: Path) -> None:
    first = write_all(SPEC, tmp_path)
    assert len(first) == len(render(SPEC))
    assert write_all(SPEC, tmp_path) == []
    (tmp_path / "spire.json").write_text("{}", encoding="utf-8")
    assert stale_files(SPEC, tmp_path) == ["spire.json"]


def test_backend_inbound_requires_client_certificates_from_frontend_only() -> None:
    cfg = bootstrap(SPEC, SPEC.get("backend"))
    [listener] = cfg["static_resources"]["listeners"]
    ts = listener["filter_chains"][0]["transport_socket"]["typed_config"]
    assert ts["require_client_certificate"] is True
    ctx = ts["common_tls_context"]
    assert ctx["tls_params"]["tls_minimum_protocol_version"] == "TLSv1_3"
    sans = ctx["combined_validation_context"]["default_validation_context"][
        "match_typed_subject_alt_names"
    ]
    assert sans == [
        {"san_type": "URI", "matcher": {"exact": "spiffe://mesh.example/ns/demo/sa/frontend"}}
    ]
    assert (
        ctx["tls_certificate_sds_secret_configs"][0]["name"]
        == "spiffe://mesh.example/ns/demo/sa/backend"
    )
    assert (
        ctx["combined_validation_context"]["validation_context_sds_secret_config"]["name"]
        == "spiffe://mesh.example"
    )


def test_frontend_outbound_is_local_only_and_verifies_the_backend_id() -> None:
    cfg = bootstrap(SPEC, SPEC.get("frontend"))
    [listener] = cfg["static_resources"]["listeners"]
    assert listener["address"]["socket_address"] == {"address": "127.0.0.1", "port_value": 18443}
    cluster = next(
        c for c in cfg["static_resources"]["clusters"] if c["name"] == "outbound_backend"
    )
    ctx = cluster["transport_socket"]["typed_config"]["common_tls_context"]
    sans = ctx["combined_validation_context"]["default_validation_context"][
        "match_typed_subject_alt_names"
    ]
    assert [s["matcher"]["exact"] for s in sans] == ["spiffe://mesh.example/ns/demo/sa/backend"]
    assert cfg["admin"]["address"]["socket_address"]["address"] == "127.0.0.1"


def test_every_tls_context_and_sds_points_at_the_spire_agent_socket() -> None:
    for w in SPEC.workloads:
        cfg = bootstrap(SPEC, w)
        nodes = walk(cfg)
        assert any(n.get("pipe", {}).get("path") == AGENT_SOCKET for n in nodes)
        sds = [n for n in nodes if "sds_config" in n]
        assert sds
        assert all(
            n["sds_config"]["api_config_source"]["grpc_services"][0]["envoy_grpc"]["cluster_name"]
            == "spire_agent"
            for n in sds
        )
        for lis in cfg["static_resources"]["listeners"]:
            if lis["address"]["socket_address"]["address"] != "127.0.0.1":
                assert "transport_socket" in lis["filter_chains"][0], (
                    "non-local listener without TLS"
                )


def test_tls_context_needs_a_peer() -> None:
    with pytest.raises(ValueError, match="allowed peer"):
        tls_context(SPEC, SPEC.get("backend"), [])


def test_spire_configs_carry_spec_values() -> None:
    srv, agent = server_conf(SPEC), agent_conf(SPEC)
    assert 'trust_domain = "mesh.example"' in srv
    assert 'default_x509_svid_ttl = "3600s"' in srv
    assert '"zt-demo" = {' in srv
    assert 'service_account_allow_list = ["spire:spire-agent"]' in srv
    assert f'socket_path = "{AGENT_SOCKET}"' in agent
    assert 'cluster = "zt-demo"' in agent
    with pytest.raises(ValueError, match="refusing"):
        _q('x" ; evil = "y')


def test_register_script_creates_node_alias_and_registered_workloads_only() -> None:
    script = register_script(SPEC)
    assert script.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in script
    assert "-node -spiffeID spiffe://mesh.example/ns/spire/sa/spire-agent" in script
    assert "k8s_psat:cluster:zt-demo" in script
    assert "sa/backend" in script
    assert "sa/frontend" in script
    assert "intruder" not in script


def test_images_are_pinned_by_digest() -> None:
    for ref in IMAGES.values():
        assert "@sha256:" in ref
        assert len(ref.split("@sha256:")[1]) == 64
    for doc in (spire_manifests(SPEC), workload_manifests(SPEC)):
        images = [c["image"] for n in walk(doc) for c in n.get("containers", [])]
        assert images
        assert all(i in IMAGES.values() for i in images)


def test_containers_have_limits_and_no_privilege_escalation() -> None:
    for doc in (spire_manifests(SPEC), workload_manifests(SPEC)):
        for n in walk(doc):
            for c in n.get("containers", []):
                assert c["resources"]["limits"]["memory"]
                assert c["securityContext"]["allowPrivilegeEscalation"] is False
                assert c["securityContext"]["readOnlyRootFilesystem"] is True


def test_workloads_do_not_mount_api_tokens_and_only_callers_get_an_app() -> None:
    doc = workload_manifests(SPEC)
    deps = {i["metadata"]["name"]: i for i in doc["items"] if i["kind"] == "Deployment"}
    assert set(deps) == {"backend", "frontend", "intruder"}
    for d in deps.values():
        assert d["spec"]["template"]["spec"]["automountServiceAccountToken"] is False
    names = {
        k: [c["name"] for c in d["spec"]["template"]["spec"]["containers"]] for k, d in deps.items()
    }
    assert names == {
        "backend": ["envoy"],
        "frontend": ["envoy", "app"],
        "intruder": ["envoy", "app"],
    }
    services = [i["metadata"]["name"] for i in doc["items"] if i["kind"] == "Service"]
    assert services == ["backend"]


def test_bundle_role_is_limited_to_one_configmap() -> None:
    role = next(i for i in spire_manifests(SPEC)["items"] if i["kind"] == "Role")
    assert role["rules"] == [
        {
            "apiGroups": [""],
            "resources": ["configmaps"],
            "resourceNames": ["spire-bundle"],
            "verbs": ["get", "patch"],
        }
    ]


def test_rendered_json_parses() -> None:
    for rel, data in render(SPEC).items():
        if rel.endswith(".json"):
            json.loads(data)
