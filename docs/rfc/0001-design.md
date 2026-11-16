# RFC 0001: zero-trust-service-mesh design

- **Status:** Accepted for M1
- **Author:** EquinoxWN
- **Created:** 2026-11-09

## Problem

In a flat cluster network, any pod that can open a TCP connection to a service can call it. If
one service is compromised, the attacker inherits that reach. Network addresses are not
identities: pods move, IPs are reused, and a shared network policy cannot say *which workload*
is on the other end of a connection.

The fix is cryptographic workload identity: every workload proves who it is on every connection,
and every server proves who it is to the client. This project builds that layer with SPIFFE
identities issued by SPIRE and enforced by Envoy sidecars, and keeps the whole configuration
derived from one small spec so it can be reviewed and tested.

**Users:** platform and security engineers who want to see, test and adapt a working SPIRE +
Envoy mutual-TLS setup, and engineers preparing for "design service-to-service authentication".

## Goals (M1)

- SPIRE attests each workload (Kubernetes namespace and service account) and issues short-lived
  X.509-SVIDs (1 hour by default, never more than 1 hour by spec validation).
- Envoy sidecars fetch the SVID and the trust bundle from the SPIRE agent over SDS and use them
  for mutual TLS: the server requires a client certificate, and both sides check the peer's
  SPIFFE ID, so every connection proves both identities.
- One spec (`deploy/mesh.json`) generates every SPIRE, Envoy and Kubernetes file; a check fails
  when the committed files drift from the spec.
- The same rules are testable locally without Kubernetes: a reference model of SPIRE's
  attestation, a trust domain CA, SVID verification and real TLS 1.3 handshakes on 127.0.0.1.

### Critical-to-quality measures (Define)

| CTQ | Target | How it is measured |
|---|---|---|
| A workload without a registration entry gets no SVID and no connection | 100% refused | attestation tests; demo scenario 2; kind e2e (intruder, 5 of 5 attempts) |
| A forged, expired or foreign SVID is refused | 100% refused | CA/verify tests; demo scenarios 3 and 4 |
| A valid identity that is not an allowed peer is refused, on both sides | 100% refused | demo scenarios 5 and 6; Envoy SAN matchers (render tests) |
| SVID lifetime | at most 3600 s | spec validation; CA cap; kind e2e reads the SVID expiry the backend's Envoy saw in the handshake |
| Generated configs match the spec | 0 stale files | `ztmesh check` in tests, CI and `.tmp/check.sh` |
| Test suite can fail | every hand mutation killed | `docs/quality/2026-11-01.md` (14 of 14) |

## Non-goals (M1)

- Certificate rotation proof and OPA per-route authorization (M2).
- Refusing pods without identity at admission, audit logging of every decision, and the
  lateral-movement proof (M3).
- Running as a hosted production mesh, multi-cluster federation, or replacing Istio/Linkerd.

## Design

```
deploy/mesh.json --ztmesh render--> deploy/generated/
                                      spire.json       SPIRE server (StatefulSet) + agent (DaemonSet), RBAC
                                      register.sh      node alias + one entry per registered workload
                                      workloads.json   Deployments: Envoy sidecar (+ curl app for callers)
                                      envoy/*.json     sidecar bootstraps
```

- **Identity.** SPIRE server with `k8s_psat` node attestation; agents run as a DaemonSet with the
  host PID namespace so the `k8s` workload attestor can map a caller's PID to its pod. Entries
  select on `k8s:ns` and `k8s:sa`; IDs follow `spiffe://<td>/ns/<namespace>/sa/<service account>`.
  All workload entries are parented to one node alias that every attested agent joins.
- **Transport.** Each workload's Envoy fetches its SVID (secret named by its SPIFFE ID) and the
  bundle (`spiffe://<td>`) from the SPIRE agent's SDS API on `/run/spire/sockets/agent.sock`.
  Inbound listeners require a client certificate and accept only the SPIFFE IDs listed in
  `allowed_callers`; outbound clusters accept only the upstream's SPIFFE ID. TLS 1.3 only (minimum and maximum both set).
  The app talks plain HTTP to its sidecar on 127.0.0.1 only. Envoy's admin API is not on the pod
  network: it listens on a Unix socket in a volume that only the envoy container mounts.
- **Local reference model.** `attestation.py` reproduces SPIRE's matching rule (all entry
  selectors must be discovered, under the right parent); `ca.py` issues SVIDs as the SPIRE server
  CA does; `verify.py` runs RFC 5280 path validation (`cryptography`) plus the X509-SVID rules
  (one URI SAN, not a CA, no keyCertSign); `mtls.py` runs real TLS handshakes with Python's
  `ssl` module and applies the same peer-ID rule as Envoy's SAN matcher.

## Alternatives considered

| Option | Why not (for M1) |
|---|---|
| Istio or Linkerd with their built-in CA | Fast to switch on, but identity issuance and Envoy config are hidden behind the control plane; the project's point is to show and test each piece. SPIRE is also what both can plug into. |
| SPIRE Controller Manager + SPIFFE CSI driver (official Helm chart) | The production-grade path (no hostPath, automatic entries). It adds CRDs, a webhook and a chart version to track; M1 uses raw manifests and explicit `entry create` so every object is visible. Recorded in ADR 0003 as the planned upgrade. |
| Kubernetes NetworkPolicy only | Restricts by IP and label, not by proven identity; it cannot tell a compromised pod from a healthy one with the same labels and does not encrypt. |
| Application-level mTLS with go-spiffe/py-spiffe | Strong, but every service must change; sidecars give the same guarantee without app changes. |

## Measurement plan

- Local: `pytest` (95 tests, 1 POSIX-only), `ztmesh check`, `ztmesh demo` with its JSON-lines decision log,
  hand mutations of the core checks.
- CI: `envoy --mode validate` on every generated bootstrap; a kind cluster runs SPIRE and the
  sidecars and checks: frontend reaches backend with both IDs seen, the SVID in Envoy expires
  within 3600 s, an unregistered pod is refused through its sidecar, and TLS without a client
  certificate or plain HTTP to the backend's port are refused. Each prints a `::notice`.

## Milestones

- **M1:** SPIRE attests each workload and issues short-lived SPIFFE identities (SVIDs). Envoy sidecars use them for mutual TLS, so every connection proves both identities.
- **M2:** Certificates rotate automatically, typically every hour. OPA decides per request which service may call which route.
- **M3:** A pod without an identity is refused, and a compromised service cannot reach anything its policy does not allow. Every decision is logged for audit.

## Risks and open questions

- The first kind run failed on Envoy's default client TLS maximum (1.2) against a 1.3 minimum;
  both ends are now set and run 43904492171 passed (`docs/results/m1.md`).
- The hostPath socket gives every pod on a node access to the Workload API; attestation still
  decides which identity it gets, but the CSI driver narrows this (ADR 0003).
- The local model mirrors SPIRE's rules; it is not SPIRE. The kind job is the check that the
  real components behave the same.
