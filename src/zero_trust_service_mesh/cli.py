"""ztmesh: render the mesh configs from the spec, check them, or run the local mTLS demo."""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from .demo import run_demo
from .files import write_atomic
from .mesh import SpecError, load_spec
from .render import stale_files, write_all


def _parser() -> argparse.ArgumentParser:
    """Command-line interface."""
    p = argparse.ArgumentParser(prog="ztmesh", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, text in (
        ("render", "write the generated configs"),
        ("check", "fail if generated configs are stale"),
    ):
        s = sub.add_parser(name, help=text)
        s.add_argument("--spec", type=Path, default=Path("deploy/mesh.json"))
        s.add_argument("--out", type=Path, default=Path("deploy/generated"))
    d = sub.add_parser("demo", help="attest, issue SVIDs and run mTLS handshakes on 127.0.0.1")
    d.add_argument("--spec", type=Path, default=Path("deploy/mesh.json"))
    d.add_argument("--server", default="backend")
    d.add_argument("--client", default="frontend")
    d.add_argument("--intruder", default="intruder")
    d.add_argument("--log", type=Path, help="write the decision log (JSON lines) here")
    return p


def main(argv: list[str] | None = None) -> int:
    """Entry point; returns the exit code."""
    args = _parser().parse_args(argv)
    try:
        spec = load_spec(args.spec)
    except (SpecError, OSError) as e:
        print(f"ztmesh: {e}", file=sys.stderr)
        return 2
    if args.cmd == "render":
        changed = write_all(spec, args.out)
        print(f"rendered {len(changed)} changed file(s) into {args.out}")
        return 0
    if args.cmd == "check":
        stale = stale_files(spec, args.out)
        for rel in stale:
            print(f"stale: {args.out / rel}", file=sys.stderr)
        print("generated configs are current" if not stale else "run `ztmesh render`")
        return 1 if stale else 0
    try:
        for name in (args.server, args.client, args.intruder):
            spec.get(name)
        with tempfile.TemporaryDirectory(prefix="ztmesh-") as work:
            scenarios = run_demo(spec, args.server, args.client, args.intruder, Path(work))
    except SpecError as e:
        print(f"ztmesh: {e}", file=sys.stderr)
        return 2
    lines = []
    for s in scenarios:
        mark = "ok  " if s.as_expected else "FAIL"
        outcome = "ALLOWED" if s.allowed else "REFUSED"
        print(f"{mark} {outcome:8} {s.name}")
        refused = [d for d in (s.server, s.client) if d.verdict == "deny"]
        for d in refused or [s.server]:
            print(f"       {d.side}: {d.reason}" + (f" (peer {d.peer})" if d.peer else ""))
        lines += [s.server.json(), s.client.json()]
    if args.log:
        write_atomic(args.log, ("\n".join(lines) + "\n").encode())
    good = sum(s.as_expected for s in scenarios)
    print(f"{good}/{len(scenarios)} scenarios as expected")
    return 0 if good == len(scenarios) else 1


if __name__ == "__main__":
    raise SystemExit(main())
