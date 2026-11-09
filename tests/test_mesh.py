"""Mesh spec validation: every malformed or inconsistent spec fails before anything is rendered."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from zero_trust_service_mesh.mesh import SpecError, load_spec, parse_spec

SPEC_FILE = Path(__file__).resolve().parents[1] / "deploy" / "mesh.json"


def base() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(SPEC_FILE.read_text(encoding="utf-8"))
    return data


def test_committed_spec_is_valid() -> None:
    spec = load_spec(SPEC_FILE)
    assert [w.name for w in spec.registered] == ["backend", "frontend"]
    assert not spec.get("intruder").registered
    assert spec.outbound_port("backend") == 18443
    assert str(spec.agent_id) == "spiffe://mesh.example/ns/spire/sa/spire-agent"
    assert spec.get("backend").dns_name == "backend.demo.svc.cluster.local"


def mutate(path: list[Any], value: Any) -> dict[str, Any]:
    data = copy.deepcopy(base())
    node = data
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return data


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (["trust_domain"], "Mesh.Example", "trust domain"),
        (["cluster"], "zt_demo", "cluster"),
        (["svid_ttl_seconds"], 7200, "svid_ttl_seconds"),
        (["svid_ttl_seconds"], 59, "svid_ttl_seconds"),
        (["svid_ttl_seconds"], True, "svid_ttl_seconds"),
        (["workloads"], [], "non-empty"),
        (["extra"], 1, "unknown spec keys"),
        (["workloads", 0, "port"], 0, "port"),
        (["workloads", 0, "port"], 60000, "port"),
        (["workloads", 0, "colour"], "red", "unknown workload keys"),
        (["workloads", 0, "allowed_callers"], ["frontend", "frontend"], "distinct"),
        (["workloads", 0, "allowed_callers"], ["intruder"], "unregistered"),
        (["workloads", 0, "allowed_callers"], ["nobody"], "unknown workload"),
        (["workloads", 1, "upstreams"], ["frontend"], "has no port"),
        (["workloads", 0, "allowed_callers"], [], "not in its allowed_callers"),
        (["workloads", 1, "name"], "backend", "unique"),
        (["workloads", 1, "service_account"], "backend", "share a namespace"),
        (["unregistered", 0, "port"], 9000, "cannot serve"),
        (["unregistered", 0, "service_account"], "frontend", "share a namespace"),
    ],
)
def test_bad_specs_are_rejected(path: list[Any], value: Any, message: str) -> None:
    with pytest.raises(SpecError, match=message):
        parse_spec(mutate(path, value))


def test_callers_need_a_port() -> None:
    data = base()
    del data["workloads"][0]["port"]
    with pytest.raises(SpecError, match="needs a port"):
        parse_spec(data)


def test_not_an_object_is_rejected() -> None:
    with pytest.raises(SpecError):
        parse_spec([])


def test_load_rejects_invalid_json_and_oversized_files(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    with pytest.raises(SpecError, match="not valid JSON"):
        load_spec(bad)
    big = tmp_path / "big.json"
    big.write_bytes(b" " * ((1 << 20) + 1))
    with pytest.raises(SpecError, match="limit"):
        load_spec(big)
