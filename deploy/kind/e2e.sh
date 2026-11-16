#!/usr/bin/env bash
# End-to-end check in a kind cluster (CI only, ubuntu runner): SPIRE attests the workloads and
# Envoy sidecars use the SVIDs for mutual TLS. Expects kind and kubectl on PATH and the configs
# rendered in deploy/generated. Every wait is bounded.
set -euo pipefail

GEN=deploy/generated
NS=demo
FRONT=spiffe://mesh.example/ns/demo/sa/frontend
BACK=spiffe://mesh.example/ns/demo/sa/backend

k() { timeout 60 kubectl "$@"; }
srv() { k -n spire exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server "$@"; }

annotate() { # title, then text on stdin; one ::error annotation (job logs need a signed-in account)
  python3 -c 'import sys; t=sys.stdin.read()[-3500:]; print("::error title=" + sys.argv[1] + "::" + t.replace("%", "%25").replace("\r", "").replace("\n", "%0A"))' "$1"
}

diagnose() { # registration entries, agent selectors, the 503 body and Envoy TLS/SDS log lines
  { srv entry show 2>&1 | grep -E "Entry ID|SPIFFE ID|Parent ID|Selector|X509-SVID TTL" || true; } | annotate "debug: entry show"
  { srv agent list 2>&1 || true
    for id in $(srv agent list 2>/dev/null | awk '/SPIFFE ID/ {print $NF}'); do srv agent show -spiffeID "$id" 2>&1 || true; done
  } | annotate "debug: agents and node selectors"
  { k -n "$NS" exec deploy/frontend -c app -- curl -s --max-time 5 -D - http://127.0.0.1:18443/ 2>&1 || true; } | annotate "debug: frontend response"
  for d in frontend backend; do
    { k -n "$NS" logs "deploy/$d" -c envoy --tail=400 2>&1 | grep -iE "tls|ssl|sds|secret|warming|handshake|error" | tail -n 25 || true; } | annotate "debug: $d envoy"
  done
  { k -n spire logs daemonset/spire-agent --tail=400 2>&1 | grep -v 'sa/intruder\\"\]' | tail -n 25 || true; } | annotate "debug: spire-agent (intruder refusals left out)"
}
fail() { echo "::error title=kind e2e::$*"; diagnose || true; exit 1; }

echo "== SPIRE server and agent"
k apply -f "$GEN/spire.json"
timeout 330 kubectl -n spire rollout status statefulset/spire-server --timeout=300s
timeout 330 kubectl -n spire rollout status daemonset/spire-agent --timeout=300s

echo "== registration entries"
bash "$GEN/register.sh"
bash "$GEN/register.sh"   # a second run must succeed too (idempotent)

echo "::notice title=registration entries::$(srv entry show 2>&1 | grep -E '^(SPIFFE ID|Selector)' | awk '{print $NF}' | paste -sd ' ' -)"

echo "== workloads"
k apply -f "$GEN/workloads.json"
for d in backend frontend intruder; do
  timeout 200 kubectl -n "$NS" rollout status "deployment/$d" --timeout=180s
done

curl_from() { # pod-deployment, then curl args; prints status code and headers
  k -n "$NS" exec "deploy/$1" -c app -- curl -s -o /dev/null -D - --max-time 5 "${@:2}" || true
}

echo "== frontend -> backend through both sidecars (mTLS)"
ok=""
for _ in $(seq 1 40); do   # the SVID reaches Envoy within one agent sync (about 5 s)
  out=$(curl_from frontend http://127.0.0.1:18443/)
  if grep -q "^HTTP/1.1 200" <<<"$out"; then ok=1; break; fi
  sleep 3
done
[ -n "$ok" ] || fail "frontend never reached backend: $out"
peer=$(grep -i '^x-peer-spiffe-id:' <<<"$out" | tr -d '\r' | awk '{print $2}')
[ "$peer" = "$FRONT" ] || fail "backend saw peer '$peer', want $FRONT"
local_id=$(grep -i '^x-local-spiffe-id:' <<<"$out" | tr -d '\r' | awk '{print $2}')
[ "$local_id" = "$BACK" ] || fail "backend presented '$local_id', want $BACK"
echo "::notice title=mTLS allowed::frontend -> backend 200; backend saw $peer and presented $local_id"

echo "== lifetime of the frontend SVID, as seen by the backend's Envoy in the handshake"
# Envoy admin is on a Unix socket only the envoy container mounts, so the expiry comes from the
# peer certificate the backend received (x-peer-cert-not-after), not from the admin API.
not_after=$(grep -i '^x-peer-cert-not-after:' <<<"$out" | tr -d '\r' | awk '{print $2}')
ttl=$(python3 -c '
import datetime as dt, sys
exp = dt.datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00"))
print(int((exp - dt.datetime.now(dt.timezone.utc)).total_seconds()))
' "$not_after") || fail "could not parse x-peer-cert-not-after '$not_after'"
[ "$ttl" -gt 0 ] && [ "$ttl" -le 3600 ] || fail "frontend SVID lifetime left $ttl s, want (0, 3600]"
echo "::notice title=Short-lived SVID::frontend SVID expires in ${ttl} s (at most 3600), read from the mTLS handshake"

echo "== intruder (no registration entry) through its sidecar"
for _ in 1 2 3 4 5; do
  out=$(curl_from intruder http://127.0.0.1:18443/)
  grep -q "^HTTP/1.1 200" <<<"$out" && fail "intruder without an SVID reached backend"
  sleep 2
done
code=$(head -1 <<<"$out" | tr -d '\r')
echo "::notice title=No identity refused::intruder sidecar has no SVID; 5 of 5 attempts refused (last: ${code:-connection failed})"

echo "== intruder bypassing its sidecar: TLS without a client certificate"
if k -n "$NS" exec deploy/intruder -c app -- curl -sk --max-time 5 -o /dev/null "https://backend.$NS.svc.cluster.local:8443/"; then
  fail "backend accepted a TLS connection without a client certificate"
fi
echo "::notice title=No client certificate refused::backend refused TLS without a client certificate"

echo "== app container cannot reach the Envoy admin API"
if k -n "$NS" exec deploy/frontend -c app -- curl -s --max-time 5 -o /dev/null http://127.0.0.1:9901/; then
  fail "Envoy admin answered on 127.0.0.1:9901"
fi
if k -n "$NS" exec deploy/frontend -c app -- sh -c 'ls /var/run/envoy-admin' >/dev/null 2>&1; then
  fail "app container can see the Envoy admin socket directory"
fi
echo "::notice title=Admin not exposed::app container reaches no Envoy admin port or socket"

echo "== intruder bypassing its sidecar: plain HTTP"
if k -n "$NS" exec deploy/intruder -c app -- curl -s --max-time 5 -o /dev/null "http://backend.$NS.svc.cluster.local:8443/"; then
  fail "backend answered plain HTTP"
fi
echo "::notice title=Plain text refused::backend refused plain HTTP on its mTLS port"
echo "E2E PASS"
