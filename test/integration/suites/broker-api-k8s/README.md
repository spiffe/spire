# SPIFFE Broker API (Kubernetes) Suite

## Description

Spins up a KIND cluster and exercises the SPIFFE Broker API end-to-end against
real workloads. Covers:

* A broker fetches a pod workload's SVID via `WorkloadPIDReference` (legacy
  PID-based path).
* A broker fetches a pod workload's SVID via `KubernetesObjectReference`
  (`pods/core`) by both name and UID. The UID case uses the default UDS broker
  endpoint and the default `pod_reference_scope = "agent_node"`, matching the
  local ztunnel-style lookup shape.
* Cluster-scoped and agent-node-scoped brokers fetch same-node pod SVIDs, while
  only the cluster-scoped broker can fetch an other-node pod SVID. The
  agent-node-scoped broker gets `NotFound` for other-node pods because it only
  uses the local kubelet pod list. These scope checks are exercised by both pod
  name and pod UID.
* A broker fetches a **non-pod** object's SVID via `KubernetesObjectReference`
  (`kustomizations.kustomize.toolkit.fluxcd.io`) — exercises the generic
  object-attestation path that resolves the resource via the REST mapper and
  emits the uniform object-meta selector vocabulary.
* A broker whose `allowed_reference_types` is restricted to PID references
  gets `PermissionDenied` at the gRPC layer when it asks for a
  `KubernetesObjectReference`.
* With `experimental.broker.access_policy = "enforced"`, a broker whose `allowed_reference_types`
  permits PID and `KubernetesObjectReference` requests, but whose broker SPIFFE
  ID lacks `impersonate-via-spire` authorization, gets `PermissionDenied` from
  the k8s attestor's `SubjectAccessReview`.
* With `experimental.broker.access_policy = "permissive"`, that same broker can fetch the
  referenced workload SVID without Kubernetes `impersonate-via-spire` RBAC.
* If the k8s workload attestor `experimental.broker` block omits `access_policy`, the SPIRE
  agent plugin configuration fails and the agent does not roll out.
* A workload that is not in the agent's broker allowlist can still use the
  Workload API to fetch its own SVID, but is rejected at the mTLS layer when
  it tries to dial the broker endpoint as a broker.
* A broker can also reach the agent over the **TCP** broker listener (via a
  ClusterIP Service in front of the agent daemonset), proving the same mTLS
  and reference-type semantics apply to remote-style brokers.
* Per-reference `allow_over_tcp` denies PID and Kubernetes object references
  over TCP unless the specific reference type explicitly opts in - fail-closed
  against remote use of local-only reference types.
* A broker with a `selector_assertion` block fetches an SVID via
  `SelectorReference`, asserting selectors the agent never attests. The target
  entry is registered with `k8s_psat` selectors that no attestor in this suite
  produces, so a match proves the asserted set alone selected it.
* That same broker is denied with `PermissionDenied` when it asserts a selector
  type outside its `allowed_selector_types` (including when mixed in with
  allowed ones), and with `InvalidArgument` for an empty set or one exceeding
  `max_selectors`.
* A broker holding `type_url = "*"` is denied `SelectorReference` — the wildcard
  covers only reference types the agent can attest for itself, so an agent
  upgrade cannot silently grant selector assertion to brokers that already hold
  the wildcard. That broker retains access to PID references.
* Asserted selectors are denied over the TCP listener because the
  `SelectorReference` entry does not set `allow_over_tcp`, while the identical
  request still succeeds over UDS.

Only the Flux Kustomization CRD is installed (no controllers); the resource
just needs to exist in the API server so the broker can reference it.

The agent RBAC fixture grants `create` on
`subjectaccessreviews.authorization.k8s.io` because this suite opts in with
`experimental.broker.access_policy = "enforced"` and the k8s workload attestor uses
SubjectAccessReview API calls to authorize Broker API reference requests.
