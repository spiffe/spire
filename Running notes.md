# **Notes**

## **1. Terms & Significance**

### **Minimum TLS Version (minTLSVersion)**

Defines the lowest TLS protocol version that a client/server is willing to negotiate. It establishes the security baseline for all connections. TLS 1.3 is recommended for modern deployments and is a prerequisite for Hybrid ML-KEM key exchange.

### **Cipher Suites**

A cipher suite defines the symmetric encryption and integrity algorithms used to protect application data after the TLS handshake. In TLS 1.2, cipher suites also determine the key exchange and authentication algorithms. In TLS 1.3, they no longer control key exchange and therefore have no impact on PQC adoption.

### **Curves / Supported Groups**

Curves (or supported groups) define the key exchange algorithms used during the TLS handshake. Classical groups use Elliptic Curve Cryptography (ECC), while Hybrid ML-KEM groups combine classical ECC with post-quantum ML-KEM. The configured group priority determines the preferred key exchange mechanism.

- #### **Classical Curves**
  - Classical curves such as P-256, P-384, and X25519 provide secure key exchange for today's computing landscape. However, they are expected to become vulnerable to sufficiently capable quantum computers.
- #### **Hybrid ML-KEM Curves**
  - Hybrid groups combine a classical elliptic curve with an ML-KEM post-quantum algorithm. This provides protection against both classical and future quantum attacks while maintaining interoperability during the industry's migration to PQC.
- #### **Pure ML-KEM**
  - Pure ML-KEM performs key exchange using only post-quantum cryptography. Although technically feasible, it is not yet widely deployed because current standards and implementations recommend hybrid mode to provide a safety net while PQC algorithms gain long-term operational confidence.

## **2 TLS Configuration Parameters**


| minTLSVersion | Negotiated TLS Versions              | Cipher Suites Configurable?            | Curves / Supported Groups Configurable? | Hybrid ML-KEM Possible?                                 |
| ------------- | ------------------------------------ | -------------------------------------- | --------------------------------------- | ------------------------------------------------------- |
| **TLS 1.1**   | TLS 1.1, 1.2, 1.3 (if peer supports) | Yes (TLS 1.1 & 1.2 only)               | Yes                                     | **Yes, but only if the connection negotiates TLS 1.3.** |
| **TLS 1.2**   | TLS 1.2, 1.3 (if peer supports)      | Yes (TLS 1.2 only)                     | Yes                                     | **Yes, but only if the connection negotiates TLS 1.3.** |
| **TLS 1.3**   | TLS 1.3 only                         | No (TLS 1.3 defines the cipher suites) | Yes                                     | **Yes**                                                 |


### **Notes**

- #### **Cipher Suites**
  - Configurable only for TLS 1.1 and TLS 1.2.  
  - Once TLS 1.3 is negotiated, the configured TLS 1.1/1.2 cipher suites are ignored.
- #### **Curves / Supported Groups**
  - Always configurable.  
  - For TLS 1.1 and TLS 1.2, only **classical curves** (for example, P-256, P-384, X25519) are used.  
  - For TLS 1.3, the same configuration may additionally include **Hybrid ML-KEM groups**, enabling post-quantum key exchange.

### **2.1 Configuration possibilities**

1. #### **What happens if minTLSVersion is 1.1 or 1.2 and Hybrid ML-KEM groups are configured?**
  Answer: Nothing changes for TLS 1.1 or TLS 1.2 connections because those protocol versions do not support Hybrid ML-KEM. 
   However, if both peers support TLS 1.3, the connection will negotiate TLS 1.3 (the highest mutually supported version), and the configured Hybrid ML-KEM groups become eligible for negotiation. In other words, configuring hybrid groups while allowing TLS 1.1 or 1.2 prepares the deployment for TLS 1.3-capable peers without preventing legacy clients from connecting.
2. #### **What happens if minTLSVersion is 1.1 or 1.2 and only classical curves are configured?**
  The deployment continues to support TLS 1.1, TLS 1.2, and TLS 1.3 as determined by protocol negotiation. 
   Even when TLS 1.3 is negotiated, the key exchange will use only the configured classical groups because no Hybrid ML-KEM groups are available. As a result, the connection benefits from TLS 1.3 protocol improvements but does not provide post-quantum cryptographic protection.
3. #### **Can a client with minTLSVersion  1.2 connect to a server with minTLSVersion  1.3 and Strict Hybrid ML-KEM Enforcement?**
  Yes, if the client supports TLS 1.3 and advertises one of the required Hybrid ML-KEM groups. A client configured with minTLSVersion  1.2 is still allowed to negotiate TLS 1.3 because 1.2 is only the minimum acceptable version.

## **3 ApiServer CR related to TLSProfile**

```go
type APIServerSpec struct {

// tlsSecurityProfile specifies settings for TLS connections for externally exposed servers. When omitted, this means no opinion and the platform is left to choose a reasonable default, which is subject to change over time.
	// The current default is the Intermediate profile. LINK TO THE TLSSecurity Profile Definition
	// +optional

	TLSSecurityProfile *TLSSecurityProfile `json:"tlsSecurityProfile,omitempty"`

	// tlsAdherence controls if components in the cluster adhere to the TLS security profile configured on this APIServer resource. Valid values are "LegacyAdheringComponentsOnly" and "StrictAllComponents". When set to "LegacyAdheringComponentsOnly", components that already honor the cluster-wide TLS profile continue to do so. Components that do not already honor it continue to use their individual TLS configurations.

	// When set to "StrictAllComponents", all components must honor the configured TLS profile unless they have a component-specific TLS configuration that overrides it. This mode is recommended for security-conscious deployments and is required for certain compliance frameworks.
	
	// Note: Some components such as Kubelet and IngressController have their own dedicated TLS configuration mechanisms via KubeletConfig and IngressController CRs respectively. When these component-specific TLS configurations are set, they take precedence over the cluster-wide tlsSecurityProfile. When not set, these components fall back to the cluster-wide default.

	// Components that encounter an unknown value for tlsAdherence should treat it as "StrictAllComponents" and log a warning to ensure forward compatibility while defaulting to the more secure behavior.

	// This field is optional. When omitted, this means the user has no opinion and the platform is left to choose reasonable defaults. These defaults are subject to change over time. The current default is LegacyAdheringComponentsOnly.
	
	// Once set, this field may be changed to a different value, but may not be removed.
	// +openshift:enable:FeatureGate=TLSAdherence
	// +optional
	TLSAdherence TLSAdherencePolicy `json:"tlsAdherence,omitempty"`
```

## **4 Other Questions**

1. Default profile / fallback profile used by openshift api server in ocp 5
  Default/fallback profile is intermediate. When checked upon an ocp 5 cluster, it’s clearly showing the tlsSecurityProfile as unset:

```shell
oc get apiserver cluster -o yaml

apiVersion: config.openshift.io/v1
kind: APIServer
metadata:
  annotations:
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
  creationTimestamp: "2026-07-28T09:25:14Z"
  generation: 1
  name: cluster
  ownerReferences:
  - apiVersion: config.openshift.io/v1
    kind: ClusterVersion
    name: version
    uid: b0fbe2be-0844-4bec-8629-f7feeb2e8e7b
  resourceVersion: "836"
spec:
  audit:
    profile: Default
```

 Then I checked what is the profile being used by the configuration of openshift-kube-api-server. **That showed the default profile to be intermediate profile**:

```shell

oc exec -n openshift-kube-apiserver kube-apiserver-nhegde-2807261-mvh2x-master-0 -- cat /etc/kubernetes/static-pod-resources/configmaps/config/config.yaml

...
"servingInfo": {
    "bindAddress": "0.0.0.0:6443",
    "bindNetwork": "tcp4",
    "cipherSuites": [
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    ],
    "minTLSVersion": "VersionTLS12",
...
```

1. Openssl version in ztwim operator’s base image
  [brew.registry.redhat.io/rh-osbs/openshift-golang-builder:rhel9golang1.26](http://brew.registry.redhat.io/rh-osbs/openshift-golang-builder:rhel_9_golang_1.26) is the base image being used for Go 1.26.x build. Openssl version being used in this builder images is OpenSSL 3.0.7 1 Nov 2022 which doesn’t support hybrid ml-kem. We need to wait for builder image which has openssl version capable of hybrid ml-kem
   Workarounds:
  1. Wait for openssl 3.5 based image which has hybrid ml-kem natively
  2. Workaround via Third-Party Providers: You can add post-quantum and hybrid KEM functionality to OpenSSL 3.0.7 by loading an external provider, such as the [Open Quantum Safe Provider (oqs-provider)](https://github.com/open-quantum-safe/oqs-provider)
2. Slack conversation with SME: damian donati
  [https://redhat-internal.slack.com/archives/C098FU5MRAB/p1785223512645779](https://redhat-internal.slack.com/archives/C098FU5MRAB/p1785223512645779)

## **5. Client & Server Communication Table**

*Scope: **current upstream behaviour** with `experimental.require_pq_kem` only. Describes what breaks, what does not, and where enabling the flag is risky — especially on **client** rows talking outside the SPIRE perimeter.*

### **Baseline assumptions (review basis)**


| Assumption                                            | Implication                                                                                                                                                                                                                                                                                                                                                                             |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Go 1.26 runtime** on SPIRE operands (server, agent) | Default min TLS **1.2**; TLS **1.3 capable**.                                                                                                                                                                                                                                                                                                                                           |
| **kube-apiserver (OCP 5.0 / K8s 1.36)**               | **Intermediate** cluster TLS profile — min TLS **1.2**, at least one hybrid ML-KEM curve supported. Floor only; apiserver can negotiate TLS 1.3 upward.                                                                                                                                                                                                                                 |
| `**require_pq_kem` (current upstream)**               | When enabled on a call site that runs `ApplyPolicy`: sets **TLS 1.3 min**, restricts curves to **PQ hybrid ML-KEM only** (no classical fallback). Wired on server/agent listeners and clients (`server.experimental`, `agent.experimental`, upstream `"spire"` plugin client). **Not wired** on federation fetch client, OIDC, controller-manager, or any Category C/D outbound client. |


**Cross-cluster SPIRE rule (Go 1.26):** SPIRE-to-SPIRE handshakes succeed when both peers run Go 1.26, including `require_pq_kem` (e.g. PQ listener with a Go 1.26 client that advertises hybrid ML-KEM by default). **Breaks** when either peer is pre–ML-KEM, or when the **local client** has `require_pq_kem` and the remote peer cannot offer PQ hybrid curves.

**How to read the tables:** The **TLS handshake risk** column states plainly whether enabling `require_pq_kem` on this path can break the TLS handshake, and which party is affected. No cross-reference to a legend is needed.

### **Scenario categories**

- **A — Intra-cluster:** Agent, server, broker, workloads, OIDC provider, controller-manager webhook — all within one OpenShift cluster  
- **B — Inter-cluster:** Federation (`https_spiffe` / `https_web`), nested upstream SPIRE across clusters / trust domains  
- **C — External entities:** Vault, EJBCA, cloud APIs, ACME CAs, external trust-bundle URLs  
- **D — Kubernetes API:** SPIRE plugins calling kube-apiserver / kubelet; kube-apiserver calling webhooks

---

### **Category A — Intra-cluster**


| Client (min TLS)                                                                      | Server (min TLS)                                                                                           | Use case                                                   | `require_pq_kem` flag applies to                         | TLS handshake risk if flag enabled                                                                                                                                 | Operational impact on restart/upgrade            |
| ------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------ |
| **SPIRE Agent** — 1.2 default; **1.3 PQ-only** if `agent.experimental.require_pq_kem` | **SPIRE Server** — 1.2 explicit; **1.3 PQ-only** if `server.experimental.require_pq_kem`                   | Node attestation (initial & re-attestation)                | **Client + Server**                                      | **No break** at Go 1.26 when both peers are Go 1.26 SPIRE. **Break risk** if agent client has flag and remote server is pre–ML-KEM or cannot offer PQ hybrid curves. | Retries with backoff. **Self-heals**.            |
| Same                                                                                  | Same                                                                                                       | Agent SVID renewal / rotation                              | **Client + Server**                                      | Same as above.                                                                                                                                                     | Brief signing gap. **Self-heals**.               |
| Same                                                                                  | Same                                                                                                       | Workload entry synchronization                             | **Client + Server**                                      | Same as above.                                                                                                                                                     | Stale entries until sync. **Self-heals**.        |
| Same                                                                                  | Same                                                                                                       | JWT SVID signing                                           | **Client + Server**                                      | Same as above.                                                                                                                                                     | JWT minting pauses. **Self-heals**.              |
| Same                                                                                  | Same                                                                                                       | Federated trust bundle delivery (agent via gRPC)           | **Client + Server**                                      | Same as above.                                                                                                                                                     | Stale bundles until sync. **Self-heals**.        |
| **In-cluster broker workload** — 1.2+; not SPIRE-controlled                           | **SPIRE Agent Broker API** — 1.2; **1.3 PQ-only** if `agent.experimental.require_pq_kem` on listener       | Delegated identity / broker SVID subscription              | **Server only** (agent knob on broker listener)          | **Break risk** — inbound broker client (Go or non-Go) may not support TLS 1.3 + PQ hybrid curves.                                                                  | Broker reconnect required. **Self-heals**.       |
| **In-cluster federation consumer** (SPIRE)                                            | **SPIRE Server federation bundle endpoint** — 1.2; **1.3 PQ-only** if `server.experimental.require_pq_kem` | In-cluster bundle fetch                                    | **Server only** (server knob on bundle listener)         | **No break** if consumer is Go 1.26 SPIRE. **Break risk** if consumer is pre–ML-KEM or lacks PQ hybrid curve support.                                              | Cached bundle used. **Self-heals**.              |
| **In-cluster Prometheus scraper** — not SPIRE-controlled                              | **SPIRE Server / Agent Prometheus** — 1.2; **1.3 PQ-only** if respective `require_pq_kem`                  | Metrics scrape                                             | **Server only**                                          | **Break risk** — inbound scraper (Go or non-Go) may not support TLS 1.3 + PQ hybrid curves. Metrics only; no identity impact.                                      | Metrics gap. **Self-heals**.                     |
| **In-cluster workload / OIDC client** (app, sidecar, mesh proxy)                      | **OIDC Discovery Provider** HTTPS listener — 1.2 default                                                   | Workload fetches OIDC discovery & JWKS                     | **N/A** — OIDC has **no** `require_pq_kem` knob          | **No effect** — flag not available on OIDC; SPIRE PQ flags do not affect this path.                                                                                 | Brief unavailability on restart. **Self-heals**. |
| **kube-apiserver** — 1.2 (OCP Intermediate); TLS 1.3 capable                          | **spire-controller-manager validating webhook** — 1.2 default                                              | Admission for ClusterSPIFFEID, ClusterFederatedTrustDomain | **N/A** — controller-manager has **no** `require_pq_kem` | **No effect** — flag not available on controller-manager; SPIRE PQ flags do not affect apiserver→webhook.                                                          | Apiserver retries. **Self-heals**.               |


---

### **Category B — Inter-cluster (SPIRE ↔ SPIRE)**


| Client (min TLS)                                                                                   | Server (min TLS)                                                                                                | Use case                                                  | `require_pq_kem` flag applies to                                        | TLS handshake risk if flag enabled                                                                                                                                          | Operational impact                  |
| -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| **SPIRE Server (Cluster B)** — `https_spiffe` fetch: 1.2 default; **PQ not wired on client today** | **SPIRE Server bundle endpoint (Cluster A)** — 1.2; **1.3 PQ-only** if A's `server.experimental.require_pq_kem` | Outbound federation fetch — `https_spiffe`                | **Server (remote)** only today; client knob **not wired**               | **No break today** — fetch client is not affected. Remote bundle server PQ is OK for Go 1.26 SPIRE client at default settings.                                              | Poll retries. **Self-heals**.       |
| **SPIRE Server (Cluster B)** — `https_web` fetch: 1.2; **`ApplyPolicy` not called**                | **Remote Web PKI bundle endpoint** — 1.2+                                                                       | Outbound federation fetch — `https_web`                   | **Neither side**                                                        | **No effect** — flag not applied on this client path.                                                                                                                       | Poll retries. **Self-heals**.       |
| **Remote cluster SPIRE** (`https_spiffe` client) — Go 1.26                                         | **Local SPIRE Server bundle endpoint** — 1.3 PQ-only if local `server.experimental.require_pq_kem`              | Inbound federation — local `https_spiffe` serve (default) | **Server only** (local server knob)                                     | **No break** if remote SPIRE client is Go 1.26. **Break risk** if remote client is pre–ML-KEM or lacks PQ hybrid curve support.                                             | Cached bundle. **Self-heals**.      |
| **Remote Web PKI / non-SPIRE client**                                                              | **Local SPIRE Server bundle endpoint** — `https_web` serve (ACME / disk cert)                                   | Inbound federation — local `https_web` serve              | **Server only** (local server knob)                                     | **Break risk** — inbound client (Web PKI or non-SPIRE) may not support TLS 1.3 + PQ hybrid curves.                                                                          | Cached bundle. **Self-heals**.      |
| **Downstream SPIRE Server** — 1.2; **1.3 PQ-only** if plugin `experimental.require_pq_kem`         | **Upstream SPIRE Server** — 1.3 PQ-only if upstream `server.experimental.require_pq_kem`                        | Downstream CA signing (nested SPIRE)                      | **Client + Server** (plugin + upstream knobs)                           | **No break** at Go 1.26 SPIRE-to-SPIRE (asymmetric PQ OK). **Break risk** if upstream is pre–ML-KEM while downstream plugin client has flag enabled.                       | CA issuance pauses. **Self-heals**. |
| Same                                                                                               | Same                                                                                                            | Publish JWT authority upstream                            | **Client + Server**                                                     | Same as above.                                                                                                                                                              | Delayed. **Self-heals**.            |
| Same                                                                                               | Same                                                                                                            | Poll upstream bundle                                      | **Client + Server**                                                     | Same as above.                                                                                                                                                              | Stale view. **Self-heals**.         |
| **SPIRE Agent (Cluster B)** — 1.2; **`ApplyPolicy` not used** (trust-bundle URL)                   | **Trust bundle HTTPS URL** (Cluster A endpoint or third party) — 1.2; **1.3 PQ-only** if remote server PQ       | Bootstrap / re-bootstrap                                  | **Neither side** on agent client; **remote server only** if peer has PQ | **No effect** on agent client today. **No break** at Go 1.26 agent default even if remote bundle URL server requires PQ — agent HTTP client is not restricted by the flag. | Retries. **Self-heals**.            |


---

### **Category C — External entities (outside cluster boundary)**


| Client (min TLS)                                           | Server (min TLS)                                   | Use case                                | `require_pq_kem` applies to | TLS handshake risk if flag enabled                                      | Operational impact                                           |
| ---------------------------------------------------------- | -------------------------------------------------- | --------------------------------------- | --------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------ |
| **OIDC Discovery Provider** ACME client — 1.2 (Go default) | **ACME CA** (Let's Encrypt etc.) — 1.2+            | ACME cert obtain/renew for OIDC HTTPS   | **N/A**                     | **No effect** — flag not applied on ACME outbound client.                | Cert renewal failure at expiry. **Self-heals** via autocert. |
| **SPIRE Server** (bundle ACME auth) — 1.2 (Go default)     | **ACME CA** — 1.2+                                 | Federation bundle endpoint cert renewal | **N/A**                     | **No effect** — flag not applied on ACME outbound client.               | Cert expiry risk.                                            |
| **SPIRE Server** — 1.2 (Go default)                        | **HashiCorp Vault** — 1.2+                         | Upstream CA / key manager               | **N/A**                     | **No effect** — flag not applied on Vault outbound client.              | **Self-heals** on Vault recovery.                            |
| **SPIRE Server** — 1.2 (Go default)                        | **EJBCA / AWS PCA / GCP CA / Azure Blob / cloud KMS** — 1.2+ | Upstream CA, bundle publish, keys       | **N/A**                     | **No effect** — flag not applied on plugin outbound clients.            | Plugin-dependent. **Self-heals**.                            |
| **SPIRE Server** (gcp_iit, azureimds) — 1.2 (Go default)   | **Google / Microsoft HTTPS APIs** — 1.2+           | Node attestation validation             | **N/A**                     | **No effect** — flag not applied on cloud API outbound clients.         | **Self-heals**.                                              |
| **SPIRE Agent** (sigstore, optional) — 1.2 (Go default)    | **Registry / Rekor / Fulcio** — 1.2+               | Image signature attestation             | **N/A**                     | **No effect** — flag not applied on sigstore outbound client.           | **Self-heals**.                                              |


---

### **Category D — Kubernetes API interactions**


| Client (min TLS)                                                  | Server (min TLS)                                   | Use case                                           | `require_pq_kem` applies to | TLS handshake risk if flag enabled                                           | Operational impact                 |
| ----------------------------------------------------------------- | -------------------------------------------------- | -------------------------------------------------- | --------------------------- | ---------------------------------------------------------------------------- | ---------------------------------- |
| **SPIRE Agent** (k8s workload attestor) — 1.2 (Go default)        | **Kubelet HTTPS API** — 1.2 (OCP)                  | Pod/node metadata attestation                      | **N/A**                     | **No effect** — flag not applied on kubelet outbound client.                  | **Self-heals**.                    |
| **SPIRE Agent** (k8s workload attestor) — 1.2 (Go default)        | **kube-apiserver** — 1.2 (OCP Intermediate)        | K8s API metadata / informers                       | **N/A**                     | **No effect** — flag not applied on kube-apiserver outbound client.          | **Self-heals**.                    |
| **SPIRE Server** (k8s_psat) — 1.2 (Go default)                    | **kube-apiserver** — 1.2 (OCP Intermediate)        | PSAT node attestation validation                   | **N/A**                     | **No effect** — flag not applied on kube-apiserver outbound client.           | **Self-heals**.                    |
| **SPIRE Server** (bundle publisher / notifier) — 1.2 (Go default) | **kube-apiserver** — 1.2 (OCP Intermediate)        | Trust bundle sync to cluster                       | **N/A**                     | **No effect** — flag not applied on kube-apiserver outbound client.           | **Self-heals**.                    |
| **SPIRE Server** (cert-manager upstream) — 1.2 (Go default)       | **kube-apiserver** — 1.2 (OCP Intermediate)        | Upstream cert via CRs                              | **N/A**                     | **No effect** — flag not applied on kube-apiserver outbound client.           | **Self-heals**.                    |
| **kube-apiserver** — 1.2 (OCP Intermediate); TLS 1.3 capable      | **spire-controller-manager webhook** — 1.2 default | Admission validation (apiserver is TLS **client**) | **N/A**                     | **No effect** — flag not available on webhook; apiserver handshake unaffected. | Apiserver retries. **Self-heals**. |


---

## **Executive summary**

### **Why `require_pq_kem` remains experimental today**

The current `experimental.require_pq_kem` knob applies PQ policy to **both client and server** at each wired call site — e.g. `agent.experimental.require_pq_kem` affects the agent→server **client** and the Prometheus **listeners** together. That coupling is the core problem:


| Drawback                                                | Impact                                                                                                                                                                                                                                                                                                                  |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Agent client inherits PQ policy**                     | An agent with `require_pq_kem` enabled must negotiate TLS 1.3 + PQ hybrid curves when dialing its SPIRE Server. If that server sits in **another cluster** that is not PQ-aware (pre–Go 1.26 or PQ not enabled), the handshake **breaks** — even though the remote server's listener may be fine with classical curves. |
| **Upstream `"spire"` plugin client inherits PQ policy** | Same cross-cluster / cross-version skew: downstream server with plugin PQ enabled cannot reach a non-PQ upstream SPIRE Server.                                                                                                                                                                                          |
| **Non-SPIRE inbound clients on listeners**              | When the flag is on a **listener** (Prometheus, federation bundle endpoint), inbound peers such as **Prometheus scrapers** that do not support PQ hybrid curves **break** — they are not SPIRE-controlled and cannot be upgraded in lockstep.                                                                           |


These paths are **outside a single-cluster, uniformly Go 1.26 deployment**. The flag is therefore experimental: it conflates client capability with server policy.

---

## **Final verdict — do we need TLS profile? Client, server, or both?**

### **1. `require_pq_kem` status**

`require_pq_kem` is an **experimental feature as of today**. It enforces a strict PQ-only policy on **both client and server** wherever wired, which is the wrong split of responsibility: clients should **adapt** to what the remote server offers, not impose local TLS governance on outbound connections. Cross-cluster agent→server and upstream-authority paths, plus non-SPIRE inbound clients, demonstrate why this knob cannot graduate without decoupling client from listener.

### **2. Do we need configurable TLS governance (min TLS version, cipher suites, curve preferences)?**

**Yes — but only on server/listener endpoints**, and only where SPIRE operands expose a terminating TLS surface we control:


| Listener                                                  | Configurable TLS governance today?                           |
| --------------------------------------------------------- | ------------------------------------------------------------ |
| SPIRE Server gRPC, federation bundle endpoint, Prometheus | **Target** — via proposed `tls_profile`                      |
| SPIRE Agent Broker API, Agent Prometheus                  | **Target** — via proposed `tls_profile`                      |
| **OIDC Discovery Provider HTTPS**                         | **No option today**. **Target** — via proposed `tls_profile` |
| **spire-controller-manager validating webhook**           | **No option today**. **Target** — via proposed `tls_profile` |


Rationale: the **server/listener** is where TLS governance belongs — it is the authority that advertises what it accepts. Clients (agent→server, upstream plugin, kube-apiserver, ACME, Vault, etc.) should remain **capable** negotiators: they offer what they support and complete the handshake with whatever the remote peer requires. Applying min TLS, cipher suites, or curve preferences on a **client** would mean the local side dictates policy to a remote peer that has its own listener config — the wrong direction.

### **3. Placement summary**


| Surface                                                                                               | TLS profile (min TLS, ciphers, curves)? | `require_pq_kem`?                                | Rationale                                                           |
| ----------------------------------------------------------------------------------------------------- | --------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------------- |
| **SPIRE server listeners** (Server gRPC, bundle endpoint, Prometheus; Agent Broker, Agent Prometheus) | **Yes — listener only**                 | **Replace** — experimental; decouple from client | Server dictates governance; inbound peer inventory before strict PQ |
| **OIDC Discovery Provider HTTPS; controller-manager webhook**                                         | **No option today**                     | **N/A**                                          | Not in scope for SPIRE operator TLS governance                      |
| **All SPIRE outbound clients** (Agent→Server, upstream `"spire"`, federation fetch, trust-bundle URL) | **No**                                  | **No** — never on client                         | Client must be capable, not prescriptive; remote server owns policy |
| **All outbound clients outside SPIRE perimeter** (kube-apiserver, kubelet, Vault, ACME, cloud APIs)   | **No**                                  | **No**                                           | External peer dictates compatibility                                |


**Bottom line:** `require_pq_kem` stays **experimental** because it binds PQ policy to clients as well as listeners. The path forward is **generalized, configurable TLS governance on server/listener endpoints only** (min TLS version, cipher suites, curve preferences) — the server sets the policy; clients remain capable negotiators. OIDC Discovery Provider and spire-controller-manager webhook have **no operator-managed TLS governance option today**.