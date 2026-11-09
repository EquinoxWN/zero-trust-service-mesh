# ADR 0003: Share the SPIRE agent socket through hostPath in M1, move to the SPIFFE CSI driver later

- **Status:** Accepted (to be revisited in M3)

## Context

Envoy has to reach the SPIRE agent's Workload API / SDS socket on its node. Two common ways:

- **hostPath** volume of `/run/spire/sockets` in every workload pod (the SPIRE quickstart).
- **SPIFFE CSI driver** (`csi.spiffe.io`), which mounts only the socket, read-only, without
  giving the pod a hostPath volume. It usually comes with the SPIRE Controller Manager and the
  official Helm chart.

## Decision

M1 uses hostPath, mounted read-only, with `type: Directory` in workload pods. Every other
object is a plain manifest generated from the spec.

## Consequences

- Fewer moving parts to get the first kind run green: no CSI driver DaemonSet, no CRDs, no chart.
- hostPath volumes are rejected by the Pod Security "baseline" and "restricted" levels, so the
  `demo` namespace cannot enforce them; workload containers are still non-root, read-only, with
  all capabilities dropped and no service account token.
- Any pod on the node can reach the socket. It still gets only the identity attestation grants
  it (the intruder gets none), but this widens the attack surface of the agent API. M3, which
  refuses pods without identity at admission, should switch to the CSI driver and enforce a Pod
  Security level on the namespace.
