# ADR 0002: A local reference model plus a kind cluster, not the cluster alone

- **Status:** Accepted

## Context

SPIRE and Envoy only show their real behaviour in Kubernetes. A kind cluster takes minutes to
start, needs Docker, and cannot run on the development machine used here (no Docker, about 4 GB
of free RAM shared with other builds). If the cluster were the only test, every change to an
identity rule would wait for CI, and a broken rule could hide behind a slow, noisy end-to-end job.

## Decision

Keep two layers:

1. A small Python reference model of the security rules (SPIRE's entry matching, SVID issuance,
   X509-SVID verification, peer-ID policy), exercised by real TLS 1.3 handshakes on 127.0.0.1.
   It runs in seconds and is where the edge cases and hand mutations live.
2. The real components in CI: `envoy --mode validate` on every generated bootstrap and a kind
   cluster with SPIRE and Envoy sidecars for the end-to-end claims.

Both layers read the same spec, and the configs for the cluster are generated from it.

## Consequences

- Edge cases (dot segments, several URI SANs, CA leaves, expiry, rogue CAs) are tested quickly
  and deterministically; 12 of 12 hand mutations are killed locally.
- The model can drift from SPIRE. The kind job is the check, and the README says which claims
  are verified only there.
- Two code paths to maintain: the model is kept small (about 700 lines in five modules) for that reason.
