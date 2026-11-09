"""SPIFFE ID parsing against the rules of the SPIFFE ID specification."""

import pytest

from zero_trust_service_mesh.spiffe import SpiffeId, SpiffeIdError, validate_label


def test_parse_round_trips_a_workload_id() -> None:
    sid = SpiffeId.parse("spiffe://mesh.example/ns/demo/sa/frontend")
    assert sid.trust_domain == "mesh.example"
    assert sid.path == "/ns/demo/sa/frontend"
    assert str(sid) == "spiffe://mesh.example/ns/demo/sa/frontend"
    assert sid.trust_domain_id == "spiffe://mesh.example"


def test_trust_domain_id_has_an_empty_path() -> None:
    assert SpiffeId.parse("spiffe://mesh.example").path == ""


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "http://mesh.example/x",
        "SPIFFE://mesh.example/x",
        "spiffe:///x",
        "spiffe://Mesh.example/x",
        "spiffe://mesh.example:443/x",
        "spiffe://user@mesh.example/x",
        "spiffe://mesh.example/x?q=1",
        "spiffe://mesh.example/x#frag",
        "spiffe://mesh.example/",
        "spiffe://mesh.example//x",
        "spiffe://mesh.example/x/./y",
        "spiffe://mesh.example/x/../y",
        "spiffe://mesh.example/sp ace",
        "spiffe://mesh.example/x%2Fy",
        "spiffe://mesh.example/" + "a" * 2100,
    ],
)
def test_invalid_ids_are_rejected(bad: str) -> None:
    with pytest.raises(SpiffeIdError):
        SpiffeId.parse(bad)


def test_non_string_is_rejected() -> None:
    with pytest.raises(SpiffeIdError):
        SpiffeId.parse(42)  # type: ignore[arg-type]


def test_service_account_convention() -> None:
    sid = SpiffeId.for_service_account("mesh.example", "demo", "backend")
    assert str(sid) == "spiffe://mesh.example/ns/demo/sa/backend"


@pytest.mark.parametrize("bad", ["", "Demo", "-x", "x-", "a" * 64, "a_b", "a.b"])
def test_labels_must_be_dns_1123(bad: str) -> None:
    with pytest.raises(ValueError, match="DNS-1123"):
        validate_label("namespace", bad)
