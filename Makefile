.PHONY: setup lint test render check demo bench audit ci

PY ?= python

setup:
	$(PY) -m pip install --upgrade pip && $(PY) -m pip install -e ".[dev]"

# ruff, ruff format and mypy --strict.
lint:
	$(PY) -m ruff check . && $(PY) -m ruff format --check . && $(PY) -m mypy

# Spec, attestation, CA and SVID checks, real mTLS handshakes on 127.0.0.1, rendered configs.
test:
	$(PY) -m pytest -q

# Regenerate deploy/generated from deploy/mesh.json.
render:
	ztmesh render

# Fail when deploy/generated does not match the spec.
check:
	ztmesh check

# One allowed and five refused mTLS connections, with a JSON-lines decision log.
demo:
	ztmesh demo --log .tmp/decisions.jsonl

bench:
	@echo "M3: a lateral-movement attempt that fails, with the denial visible in logs (see README Roadmap)"

# Known vulnerabilities in the installed Python dependencies.
audit:
	$(PY) -m pip_audit --skip-editable --cache-dir .tmp/pip-audit

ci: setup lint test
