"""The ztmesh command: exit codes, decision log and argument errors."""

import json
from pathlib import Path

import pytest

from zero_trust_service_mesh.cli import main
from zero_trust_service_mesh.files import write_atomic

SPEC = str(Path(__file__).resolve().parents[1] / "deploy" / "mesh.json")


def test_render_then_check(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = str(tmp_path / "gen")
    assert main(["check", "--spec", SPEC, "--out", out]) == 1
    assert main(["render", "--spec", SPEC, "--out", out]) == 0
    assert main(["check", "--spec", SPEC, "--out", out]) == 0
    assert "current" in capsys.readouterr().out


def test_demo_writes_a_decision_log(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = tmp_path / "decisions.jsonl"
    assert main(["demo", "--spec", SPEC, "--log", str(log)]) == 0
    assert "6/6 scenarios as expected" in capsys.readouterr().out
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 12
    assert sum(r["verdict"] == "allow" for r in records if r["side"] == "server") >= 1
    assert all(r["time"].endswith("Z") for r in records)


def test_bad_spec_and_unknown_workload_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    assert main(["check", "--spec", str(bad)]) == 2
    assert main(["check", "--spec", str(tmp_path / "missing.json")]) == 2
    assert main(["demo", "--spec", SPEC, "--client", "nobody"]) == 2
    assert "unknown workload" in capsys.readouterr().err


def test_write_atomic_replaces_whole_file_and_leaves_no_temp(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "f.txt"
    write_atomic(target, b"one")
    write_atomic(target, b"two")
    assert target.read_bytes() == b"two"
    assert [p.name for p in target.parent.iterdir()] == ["f.txt"]


def test_write_atomic_cleans_up_when_the_rename_fails(tmp_path: Path) -> None:
    target = tmp_path / "dir"
    target.mkdir()
    (target / "keep").write_text("x", encoding="utf-8")
    with pytest.raises(OSError):  # noqa: PT011 - the error differs by OS (IsADirectory, PermissionError)
        write_atomic(target, b"data")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dir"]
