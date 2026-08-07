# **ADR Centralized TLS Profile in ZTWIM Operator**

**Date:** Aug 3, 2026  
**Status:** Proposed  
**Authors:** [Nandan Hegde](mailto:nhegde@redhat.com)  
**Related docs:** [Analysis and Running notes Doc](https://docs.google.com/document/d/1bBssLlFt2T8Fd3GYXvqOKcvBJlyotuYkkFzVVX5kuDo/edit?tab=t.volqin675z0w#heading=h.k64j6t6v4t6d)

---

# **What**

The Zero Trust Workload Identity Manager (ZTWIM) operator will honor the cluster-wide TLS security profile defined on apiserver.config.openshift.io/cluster for its own TLS-serving endpoints. This ADR covers **Layer 1 — the operator only**. Operand TLS injection is planned under a separate ADR and is summarized here only for propagation context.

1. **Base image — PQ-ready OpenSSL.** ZTWIM operator images will be built from the Red Hat base image that ships with DEFAULT:PQ enabled, providing OpenSSL-based hybrid ML-KEM (post-quantum) curve support. The Go version chosen is 1.26 which has FIPS compliant hybrid ML-KEM groups.  
2. **Single source of truth.** The effective TLS policy and profile are read exclusively from config.openshift.io/v1 APIServer named cluster: spec.tlsAdherence and spec.tlsSecurityProfile. ZTWIM does not define or override cluster TLS policy in its own CRs.  
3. **Shared OpenShift TLS library.** Fetching, parsing, and reconciling the cluster profile for the operator will use github.com/openshift/controller-runtime-common/pkg/tls (FetchAPIServerTLSProfile, FetchAPIServerTLSAdherencePolicy, SecurityProfileWatcher). ZTWIM will not reimplement OpenShift TLS profile semantics.  
4. **Strict adherence gate.** The cluster profile is applied to operator TLS only when tlsAdherence is strict (i.e. StrictAllComponents and forward-compatible unknown strict values). When adherence is NoOpinion, empty, or LegacyAdheringComponentsOnly, the operator does **not** inject profile-based tls.Config customizations; metrics and webhook servers retain controller-runtime / Go default TLS behavior (Intermediate-equivalent in practice with minTLSVersion \= 1.2 and hybrid ML-KEM compatible and classical fallback).  
5. **Watch and reconcile via pod restart — no hot reload.** After the manager starts, SecurityProfileWatcher watches APIServer/cluster. On tlsSecurityProfile or tlsAdherence change, callbacks cancel the manager context; the process exits and Kubernetes restarts the operator pod, which re-runs startup fetch and reapplies the profile.  
6. **Graceful degradation on startup fetch failure.** If APIServer fetch fails at startup, ZTWIM logs the error, defaults adherence to NoOpinion and profile spec to empty, and continues without profile injection. SecurityProfileWatcher still runs so a later successful watch/restart can converge once the API is reachable. Go defaults (min=1.2) will be applied to tls endpoints.  
7. **Operand TLS \-** Layer 2 (SPIRE Server, Agent, OIDC, Controller Manager operands) will be documented in a dedicated Operand ADR. Planned approach for traceability only:  
   * Resolve profile once at operator startup into an immutable snapshot passed to operand reconcilers.  
   * Inject tlsProfile (minVersion, cipherSuites and CurvePreferences) into operand ConfigMaps  
   * Compute ConfigMap content hash; annotate operand workloads; rolling restart on hash change  
8. **Testing and validation in CI.**  
   * \*\*tls-scanner\*\* runs in CI against ZTWIM Operator TLS endpoints under representative cluster TLS profiles (Intermediate, Modern, Custom) to verify negotiated protocols and ciphers match the effective profile when strict adherence is enabled  
   * **FIPS validation** runs in CI (FIPS-enabled build or cluster configuration) to confirm operator TLS endpoints remain functional and compliant when FIPS mode is required

# **Why**

ZTWIM’s operator metrics and webhook servers do not today honor apiserver.config.openshift.io/cluster TLS settings. They rely on Go defaults or static scaffold configuration. When OpenShift enforces tlsAdherence: StrictAllComponents (OCP5.0 PQC readiness), non-compliant operators block cluster upgrades and fail customer compliance audits.

Customers who configure custom TLS profiles (cipher order, minimum version, PQ-capable groups) receive no enforcement from ZTWIM’s operator surfaces. Platform teams expect operators declaring tls-profiles to inherit cluster policy.

## **Goals**

* PQ readiness: operator stack (base image \+ profile inheritance path) supports ML-KEM / TLS 1.3 profiles configured cluster-wide  
* No behavior change when adherence is not strict (default Intermediate-equivalent experience)  
* Testing compliance via automated tls-scanner and FIPS.

## **Non-goals**

* TLS client configuration, unix-domain and plaintext health endpoints  
* Sorting or rewriting customer cipher/group order  
* Hot reload without pod restart

# **How**

## **OpenShift cluster TLS profiles**

ZTWIM reads the profile configured on apiserver.config.openshift.io/cluster. OpenShift defines four profile types:

| Profile | Min TLS version | Cipher suites (summary) |
| ----- | ----- | ----- |
| **Old** | TLS 1.0 | Broad list: Modern ciphers plus legacy ECDHE/RSA and CBC suites (includes DES-CBC3-SHA) |
| **Intermediate** (cluster default when unset) | TLS 1.2 | Modern ciphers plus ECDHE with AES-GCM and ChaCha20-Poly1305 |
| **Modern** | TLS 1.3 | TLS 1.3 modern ciphers only (TLS\_AES\_128\_GCM\_SHA256, TLS\_AES\_256\_GCM\_SHA384, TLS\_CHACHA20\_POLY1305\_SHA256) |
| **Custom** | Admin-defined | Admin-defined OpenSSL cipher list and minimum version from custom.tlsProfileSpec |

TLSProfile also aims to define **Groups** (curve preferences, e.g. X25519, X25519MLKEM768) as part of OCP 5.1 and hence **Curve preferences are not yet available** to the ZTWIM operator metrics or webhook servers; only minimum TLS version and cipher suites take effect today.

Cipher order from the cluster profile is preserved as declared (not sorted or deduplicated).

## **Flow**

### **Startup**

```
Operator pod starts
  → Read tlsAdherence + tlsSecurityProfile from APIServer/cluster
  → If strict adherence: apply resolved profile to metrics (:8443) and webhook TLS
  → If non-strict or fetch failed: use Go defaults (1.2 minTLSVersion & no cluster profile applied)
  → Start controller manager with fixed TLS settings for this process lifetime
```

### **Watcher**

```
Cluster admin changes tlsAdherence or tlsSecurityProfile on APIServer/cluster
  → SecurityProfileWatcher detects the change
  → Operator process shuts down gracefully
  → Kubernetes restarts the operator pod
  → Startup flow runs again with the new settings
```

No in-process TLS hot reload. Profile changes always take effect after a pod restart.

### **Parsing — profile type to operator settings**

| APIServer tlsSecurityProfile.type | Resolved to | Operator settings (strict adherence only) |
| ----- | ----- | ----- |
| Unset / empty | **Intermediate** | TLS 1.2 min \+ Intermediate cipher list |
| **Old** | Old profile | TLS 1.0 min \+ Old cipher list |
| **Intermediate** | Intermediate profile | TLS 1.2 min \+ Intermediate cipher list |
| **Modern** | Modern profile | TLS 1.3 min; Go enables all TLS 1.3 ciphers (no explicit cipher list) |
| **Custom** (valid) | Admin custom.tlsProfileSpec | Admin min TLS \+ cipher list (unsupported ciphers dropped) |
| **Custom** (missing custom block) | Error at watch time | Go defaults. No restart until APIServer CR is valid |

## **Effective TLS configuration (operator)**

| TLS Adherence | TLS Profile fetched | Effective TLS config (profile used) |
| ----- | ----- | ----- |
| **StrictAllComponents** (or other strict values) | Old / Intermediate / Modern / valid Custom | Matching named or custom profile — min TLS and ciphers as in parsing table above |
| **StrictAllComponents** | Unset (empty type) | **Intermediate** (cluster default) |
| **StrictAllComponents** | Fetch failed | TLS 1.2 min, empty cipher list until next successful restart |
| **StrictAllComponents** | Adherence fetch failed at startup (operator defaults to non-strict internally) | **Go defaults** — no cluster profile; watcher will restart operator once API is reachable |
| **NoOpinion**, **LegacyAdheringComponentsOnly**, or empty | Any (Old / Intermediate / Modern / Custom / unset) | **Go defaults** — cluster profile is **not** applied to operator endpoints. TLSProfile is not meant to be consumed by ztwim operator under this condition. |
| Adherence fetch failed at startup | Any | **Go defaults** — same as non-strict; watcher converges on restart |

**Summary:** Under strict adherence, the operator serves metrics and webhooks with the cluster-resolved profile. Under non-strict adherence, operator TLS is unchanged from Go defaults regardless of what is configured on the APIServer CR.

## **Testing and definition of done**

* Unit tests cover profile resolution, adherence gating, and ConfigMap hash stability (operand tests separate)  
* CI job runs \*\*tls-scanner\*\* against operator metrics and webhook under strict adherence with at least Intermediate and Modern profiles; failures block merge  
* Manual: **FIPS validation** for operator image/build matrix applicable to ZTWIM  
* Manual: change APIServer TLS profile with strict adherence → single operator restart  
* CSV tls-profiles: "true" published in shipped bundle  
* RBAC and SecurityProfileWatcher registered; no in-process TLS hot reload

## **Planned operand propagation (informational)**

```
APIServer TLS change
  → SecurityProfileWatcher restarts operator
  → Startup snapshot of OperandTLSProfile passed to reconcilers
  → ConfigMap generators inject tlsProfile block
  → Hash annotation change → StatefulSet / DaemonSet / Deployment rolling update
```

# **Alternatives**

1. Using the PQC ready base image with Go 1.26 based Operator and Operand images.  
   1. Rejected because the tlsProfile also consists of cipherSuites and minTLSVersion along with groups. TLSProfile is a superset of PQC curves.  

# **Risks**

| Risk | Category | Likelihood | Impact | Mitigation |
| :---- | :---- | :---- | :---- | :---- |
| Restart during tlsProfile or adherence change | Operational | High, triggered by admin | High | NA. This is likely to be a tradeoff. |
| Adherence change during upgrade | Operational | High, triggered by admin | High | Prevention at the APIServer level. No rolling back from strictAdherence. |

## Reviews

| Reviewed by | Date | Notes |
| :---- | :---- | :---- |
|  |  |  |

