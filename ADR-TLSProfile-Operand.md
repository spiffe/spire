# **ADR Central TLS Consistency — ZTWIM Operand**

**Date:** Aug 5, 2026  
**Status:** Proposed  
**Authors:** [Nandan Hegde](mailto:nhegde@redhat.com)  
**Related docs:** [ADR Centralized TLS Profile in ZTWIM Operator](ADR-TLSProfile-Operator.md) · [Operand TLS analysis — Running notes](Running%20notes.md)

---

# **What**

ZTWIM operands will inherit the cluster TLS security profile from `apiserver.config.openshift.io/cluster` via operator reconcilation. This ADR covers **Layer 2 — operands only**. Layer 1 (operator metrics and webhook) is defined in [ADR-TLSProfile-Operator.md](ADR-TLSProfile-Operator.md).

1. **Central TLS governance via `tls_profile`.** The operator injects a `tls_profile` block (`min_tls_version`, `cipher_suites`, `curve_preferences`) into operand ConfigMaps. Operands apply it **only on terminating TLS endpoints (listeners)**, not on outbound clients.
2. **No `require_pq_kem` in the ZTWIM operand CR.** The experimental upstream flag is **not** promoted as an operator-managed setting. Users who need strict PQ-only enforcement can run the operator in `**CREATE_ONLY_MODE`** (operator does not reconcile operand ConfigMaps) and manually add `experimental.require_pq_kem` to the relevant operand configuration.
3. **PQ-ready runtime.** Operand images are built from a Red Hat base image with **DEFAULT:PQ** OpenSSL, plus **Go 1.26**, so hybrid ML-KEM curves are available at runtime (including FIPS-compliant groups).
4. **Curve preferences — phased.** Full `curve_preferences` propagation from the cluster APIServer profile lands with **OCP 5.1** TLS profile Groups support. Until then, operands receive `min_tls_version` and `cipher_suites` from the central profile; curve negotiation relies on **Go 1.26 defaults**, which prefer hybrid ML-KEM with classical fallback. Hybrid ML-KEM preference will be verified in testing.
5. **Operands in scope vs out of scope.**


| Operand TLS listener                                        | Central `tls_profile` injection |
| ----------------------------------------------------------- | ------------------------------- |
| SPIRE Server — gRPC, federation bundle endpoint, Prometheus | **Yes**                         |
| SPIRE Agent — Prometheus                                    | **Yes**                         |
| OIDC Discovery Provider HTTPS                               | **Yes**                         |
| spire-controller-manager validating webhook                 | **Yes**                         |


1. **Outbound clients unchanged.** Agent→Server gRPC, upstream `"spire"` plugin, federation fetch, kube-apiserver, Vault, ACME, and all other outbound clients retain Go default TLS behavior. No profile or `require_pq_kem` is applied on client TLS configurations.
2. **Rolling restart on profile change.** ConfigMap content hash is annotated on operand workloads; a cluster TLS profile change triggers operand rolling update (same pattern as the operator ADR).

# **Why**

Customers expect ZTWIM operands to honor the same cluster TLS policy as the rest of OpenShift when `tlsAdherence: StrictAllComponents` is enforced. Today, SPIRE operands use hardcoded or Go-default TLS on their listeners and do not reflect APIServer profile changes.

### `**require_pq_kem` is not the right operator knob**

Upstream `experimental.require_pq_kem` hardcodes TLS 1.3 minimum and PQ-only hybrid curves on **both client and server** at each wired call site. Analysis in [Running notes — Executive summary](Running%20notes.md) shows why this is experimental and unsuitable for operator-managed rollout:


| Drawback                                            | Impact                                                                       |
| --------------------------------------------------- | ---------------------------------------------------------------------------- |
| Agent client inherits PQ policy                     | Cross-cluster or pre–ML-KEM remote SPIRE Server can break the handshake      |
| Upstream `"spire"` plugin client inherits PQ policy | Nested / federated SPIRE across clusters breaks on version skew              |
| Non-SPIRE inbound clients on listeners              | Prometheus scrapers and similar peers break when PQ is enforced on listeners |


**Escape hatch:** `CREATE_ONLY_MODE` lets advanced users opt in manually without the operator reconciling or endorsing the flag.

### `**tls_profile` is the superset**


| Capability             | `require_pq_kem`  | `tls_profile`                               |
| ---------------------- | ----------------- | ------------------------------------------- |
| Min TLS version        | Hardcoded TLS 1.3 | Configurable                                |
| Cipher suites          | Not configurable  | Configurable                                |
| Curve preferences      | Hardcoded PQ-only | Configurable (OCP 5.1+ via cluster profile) |
| Client vs server scope | Both              | **Listeners only**                          |
| Classical fallback     | No                | Yes/No depending on configured Curves       |


The server/listener is the authority for TLS governance; clients remain capable negotiators.

## **Goals**

- Operands honor cluster TLS profile on **listener endpoints** under strict adherence  including OIDC Discovery Provider or controller-manager webhook
- PQ readiness via DEFAULT:PQ base image + Go 1.26 without forcing PQ-only on clients  
- No duplicate or conflicting TLS knobs on the ZTWIM operand CR

## **Non-goals**

- TLS configuration on outbound SPIRE or external clients  
- In-process TLS hot reload without pod restart  
- Operator-managed `require_pq_kem`

# **How**

## **Propagation flow**

```
APIServer TLS profile / adherence change
  → SecurityProfileWatcher restarts ZTWIM operator (Layer 1 — see Operator ADR)
  → Operator resolves cluster profile snapshot at startup
  → If strict adherence: inject tls_profile into SPIRE Server / Agent ConfigMaps
  → ConfigMap hash annotation changes → StatefulSet / DaemonSet rolling update
  → Operands restart; ApplyPolicy applies profile on listeners only
```

## **Strict adherence gating**

Same gate as the operator ADR: profile injection applies only when `tlsAdherence` is strict (`StrictAllComponents` or forward-compatible unknown strict values). When adherence is `NoOpinion`, empty, or `LegacyAdheringComponentsOnly`, operands keep Go defaults (min TLS 1.2, hybrid ML-KEM preferred by Go 1.26 with classical fallback).

## **SPIRE `tls_profile` application (listeners only)**

Shared library `pkg/common/tlspolicy/tlspolicy.go`:

- `TLSProfile` fields map to `min_tls_version`, `cipher_suites`, `curve_preferences` in operand HCL ConfigMaps  
- `ApplyPolicy(config, policy, isTCPListener)` applies `TLSProfile` **only when `isTCPListener=true`**  
- `require_pq_kem`, if manually set, still applies to both client and server at wired call sites — another reason the operator does not manage it

## **Curve preferences before OCP 5.1**

Cluster APIServer `tlsSecurityProfile` does not yet expose Groups (curve preferences) to components. Until OCP 5.1:

- Operator injects `min_tls_version` and `cipher_suites` only  
- Go 1.26 operand runtime advertises hybrid ML-KEM groups by default ahead of classical curves  
- Testing confirms hybrid ML-KEM is preferred in negotiated handshakes with classical fallback available

After OCP 5.1, `curve_preferences` from the resolved cluster profile are added to operand ConfigMaps.

## **CREATE_ONLY_MODE and manual `require_pq_kem`**


| Mode               | Operator behavior                                          | `require_pq_kem`                                                                                    |
| ------------------ | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Normal reconcile   | Injects central `tls_profile`; manages ConfigMap lifecycle | Not injected; not in operand CR                                                                     |
| `CREATE_ONLY_MODE` | Creates operands but does not reconcile ConfigMap content  | User may manually add `experimental.require_pq_kem` to ConfigMap — operator takes no responsibility |


## **Testing and definition of done**

- **tls-scanner** against SPIRE Server and Agent listener endpoints under Intermediate, Modern, and Custom cluster profiles (strict adherence)  
- **ZTWIM functional tests** — attestation, SVID issuance, federation, and metrics remain healthy after profile injection and rolling restart  
- **Hybrid ML-KEM preference** — test evidence that Go 1.26 operands prefer hybrid ML-KEM negotiation with classical fallback when curve preferences are not injected  
- **FIPS validation (140-2 and 140-3)** — confirm operand TLS listeners remain functional in FIPS mode and hybrid ML-KEM curves are available where the FIPS-enabled Go 1.26 runtime supports them  
- Unit tests for ConfigMap hash stability and profile injection gating

# **Alternatives**

1. `require_pq_kem` exposed on the ZTWIM operand CR**
  **Rejected.** Binds PQ policy to outbound clients as well as listeners; can break cross-cluster SPIRE, nested upstream paths, and non-SPIRE inbound peers (see [Running notes](Running%20notes.md)). Becomes redundant when OCP 5.1 exposes curve preferences via the central TLS profile — two competing knobs would confuse users on the correct PQ enforcement path.
2. **Per-operand TLS config fields on the ZTWIM CR** (e.g. separate min TLS / ciphers / curves overrides per SPIRE Server and Agent)
  **Rejected.** Precedence and merge rules between operand CR fields and the central APIServer TLS profile add branching complexity and multiple sources of truth. Central profile inheritance keeps one knob.

# **Risks**


| Risk                                                           | Category      | Likelihood             | Impact                               | Mitigation                                                                                                                                                                                                |
| -------------------------------------------------------------- | ------------- | ---------------------- | ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rolling restart when cluster TLS profile changes               | Operational   | High (admin-triggered) | Medium — brief identity/metrics gaps | All affected client↔server paths **self-heal** after restart. Full communication matrix and handshake assessment: [Running notes — Section 5](Running%20notes.md). No permanent identity loss documented. |
| Inbound non-SPIRE clients on strict Modern / PQ-heavy profiles | Compatibility | Medium                 | Low–Medium (metrics scrape, broker)  | Document inbound peer TLS requirements. Profile applies to listeners only; outbound paths to kube-apiserver, Vault, ACME unaffected.                                                                      |
| Curve preferences unavailable until OCP 5.1                    | Functional    | Certain                | Low                                  | Go 1.26 default hybrid ML-KEM preference with classical fallback; will be verified in testing. Full curve governance converges when OCP 5.1 Groups land.                                                  |
| FIPS mode limits available curves                              | Compliance    | Medium                 | Medium                               | Explicit FIPS 140-2 / 140-3 validation in CI; confirm hybrid ML-KEM availability on DEFAULT:PQ + Go 1.26 FIPS build matrix.                                                                               |


## Reviews


| Reviewed by | Date | Notes |
| ----------- | ---- | ----- |
|             |      |       |


