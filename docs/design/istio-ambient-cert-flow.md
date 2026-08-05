# Istio Ambient Mode: Certificate Issuance Flow

This document describes how Athenz ZTS issues SPIFFE SVIDs for an Istio ambient mesh
via cert-manager, approver-policy, athenz-issuer, and cert-manager-istio-csr.

> Waypoints and gateways run with **dotted, platform-provisioned ServiceAccounts**
> (`{domain}.waypoint`), so their identities are standard domain-qualified SPIFFE identities like any workload's. The
> required platform setup is documented in
> [istio-ambient-waypoint-setup.md](istio-ambient-waypoint-setup.md).

Example values used below (substitute your own):

| Concept | Example |
|---------|---------|
| SPIFFE trust domain | `athenz.io` |
| Control-plane Athenz domain | `example.k8s` |
| Workload domains | `app.frontend`, `app.backend` |
| cert-manager / istio-csr namespace | `cert-manager` |

---

## Component Map

| Component | Namespace | Role |
|-----------|-----------|------|
| `istio-cni-node` DaemonSet | `istio-system` | Installs iptables rules in pod netns to redirect traffic to ztunnel |
| `ztunnel` DaemonSet | `istio-system` | L4 mTLS proxy; holds workload SVIDs in memory on behalf of pods |
| `istiod` Deployment | `istio-system` | xDS control plane; proxies workload SVID requests from ztunnel to istio-csr |
| `cert-manager-istio-csr` Deployment | `cert-manager` | gRPC CA bridge; turns SVID requests from istiod into cert-manager CertificateRequests |
| **cert-manager controller** | `cert-manager` | Framework that watches CertificateRequest objects and coordinates approval + signing |
| **approver-policy** | `cert-manager` | cert-manager plugin; auto-approves CertificateRequests matching the `allow-athenz-istio-issuer` policy |
| **athenz-issuer** | `cert-manager` | cert-manager external issuer; signs approved CertificateRequests by calling ZTS |
| `AthenzClusterIssuer` `athenz-istio-issuer` | cluster-scoped | Points athenz-issuer at the ZTS endpoint |
| `waypoint` Deployment | application namespace (e.g. `app-backend`) | L7 Envoy proxy per namespace; enforces AuthorizationPolicy for traffic to services in that namespace |
| Athenz ZTS | external | Certificate authority; validates SA token + cloud OIDC issuer; signs and returns cert |

> **Where is cert-manager in `ztunnel → istiod → istio-csr → CertificateRequest → athenz-issuer → ZTS`?**
> cert-manager is the layer *around* `CertificateRequest`. It provides the CRD, watches for
> new requests, routes them to approver-policy (approval) and to athenz-issuer (signing).
> cert-manager does not touch cryptographic content — it orchestrates the lifecycle.
> approver-policy and athenz-issuer are separate pods, both cert-manager plugins.

---

## Certificate Landscape

| Certificate | Mechanism | Secret / location |
|-------------|-----------|-------------------|
| `istiod-tls` | cert-manager `Certificate` → athenz-issuer → ZTS | Secret `istiod-tls`, `istio-system` |
| ztunnel identity | dynamic SVID via istio-csr → CertificateRequest → athenz-issuer → ZTS (not a static Secret) | in-memory in ztunnel |
| istio-csr serving cert | cert-manager `Certificate` → athenz-issuer → ZTS | Secret `cert-manager-istio-csr-athenz-tls`, `cert-manager` |
| Workload SVIDs | ztunnel gRPC → istiod → istio-csr → CertificateRequest → athenz-issuer → ZTS | ztunnel in-memory, one per pod |
| Waypoint SVID | waypoint gRPC → istio-csr → CertificateRequest → athenz-issuer → ZTS | waypoint in-memory |
| Ingress gateway mesh SVID | gateway pilot-agent → istio-csr → CertificateRequest → athenz-issuer → ZTS (Section 6) | gateway in-memory |
| Ingress gateway listener cert | cert-manager `Certificate` → athenz-issuer → ZTS (Section 6b) | Secret referenced by Gateway `certificateRefs` |
| Egress waypoint SVID | waypoint on `ServiceEntry` → istio-csr → athenz-issuer → ZTS (Section 6c) | waypoint in-memory |

---

## Section 1: istiod and ztunnel Certificates

istiod and ztunnel each need their own X.509 certificate before the mesh can function.
These are **not** fetched via gRPC — they are provisioned by cert-manager `Certificate`
objects defined in `istio-infra/`. cert-manager controller reconciles them, athenz-issuer
signs them via ZTS, and the result lands in a Kubernetes Secret that the pod mounts.

### 1a. istiod TLS Serving Certificate

istiod exposes xDS on port 15012. ztunnel and istio-csr connect to this port over TLS;
both verify istiod's certificate against the mesh trust bundle. The cert is defined in
`istio-infra/istiod-cert.yaml`.

```
    cert-manager           approver-policy       athenz-issuer        Kubernetes API       Athenz ZTS          istiod
       (CM)                    (AP)                  (AI)                 (K8S)              (ZTS)              (ISO)
         │                      │                     │                     │                  │                  │
         │  [watches Certificate: istio-infra/istiod-cert.yaml              │                  │                  │
         │   issuerRef=athenz-istio-issuer  secretName=istiod-tls]          │                  │                  │
         │                      │                     │                     │                  │                  │
         │  1. Generate EC key pair and CSR           │                     │                  │                  │
         │     CN:      example.k8s.istiod     │                     │                  │                  │
         │     URI SAN: spiffe://athenz.io/        │                     │                  │                  │
         │              ns/istio-system/sa/           │                     │                  │                  │
         │              example.k8s.istiod     │                     │                  │                  │
         │     DNS SAN: istiod.istio-system.svc       │                     │                  │                  │
         │              istiod.istio-system.svc.cluster.local               │                  │                  │
         │                      │                     │                     │                  │                  │
         │  2. Create CertificateRequest istiod-1     │                     │                  │                  │
         ├──────────────────────────────────────────────────────────────── ►│                  │                  │
         │                      │                     │                     │                  │                  │
         │               3. Watch CertificateRequest istiod-1               │                  │                  │
         │               ◄───────────────────────────────────────────────── │                  │                  │
         │                      │                     │                     │                  │                  │
         │               4. Evaluate policy: issuerRef ok, URIs spiffe/* ok │                  │                  │
         │                      │                     │                     │                  │                  │
         │               5. Patch Approved=True        │                     │                  │                  │
         │               ─────────────────────────────────────────────────► │                  │                  │
         │                      │                     │                     │                  │                  │
         │                      │              6. Watch CertificateRequest istiod-1 (Approved=True)               │
         │                      │              ◄───────────────────────────┤                  │                  │
         │                      │                     │                     │                  │                  │
         │                      │              7. Parse SPIFFE URI from CSR │                  │                  │
         │                      │                     │  ns=istio-system sa=example.k8s.istiod             │
         │                      │                     │  -> domain=example.k8s service=istiod              │
         │                      │                     │                     │                  │                  │
         │                      │              8. TokenRequest for SA example.k8s.istiod│                  │
         │                      │                     ├────────────────────►│                  │                  │
         │                      │                     │                     │                  │                  │
         │                      │                     │◄────────────────────┤                  │                  │
         │                      │                     │  SA token           │                  │                  │
         │                      │                     │  sub: system:serviceaccount:           │                  │
         │                      │                     │       istio-system:example.k8s.istiod              │
         │                      │                     │  iss: cluster OIDC issuer                │                  │
         │                      │                     │  aud: ZTS URL       │                  │                  │
         │                      │                     │                     │                  │                  │
         │                      │              9. POST /zts/v1/instance     │                  │                  │
         │                      │                     │  domain=example.k8s service=istiod                 │
         │                      │                     │  provider=sys.k8s.gcp         │                  │
         │                      │                     │  csr.CN:      example.k8s.istiod│                  │
         │                      │                     │  csr.URI SAN: spiffe://athenz.io/   │                  │
         │                      │                     │               ns/istio-system/sa/      │                  │
         │                      │                     │               example.k8s.istiod│                  │
         │                      │                     │  csr.DNS SAN: istiod.istio-system.svc(.cluster.local)     │
         │                      │                     │  identityToken: SA token above         │                  │
         │                      │                     │  x509CertInstanceId: example.k8s.istiod SA's UID │
         │                      │                     ├─────────────────────────────────────── ►│                  │
         │                      │                     │                     │                  │                  │
         │                      │                     │                     │           10. Validate SA token      │
         │                      │                     │                     │               Validate cloud OIDC issuer
         │                      │                     │                     │               Read instanceId from x509CertInstanceId
         │                      │                     │                     │               Validate CN == domain.service
         │                      │                     │                     │               Validate DNS SANs      │
         │                      │                     │                     │               Sign cert:             │
         │                      │                     │                     │                 Issuer:  Athenz CA
         │                      │                     │                     │                 Subject: CN=example.k8s.istiod
         │                      │                     │                     │                 URI SAN: spiffe://athenz.io/
         │                      │                     │                     │                          ns/istio-system/sa/
         │                      │                     │                     │                          example.k8s.istiod
         │                      │                     │                     │                 DNS SAN: istiod.istio-system.svc(.cluster.local)
         │                      │                     │                     │                  │                  │
         │                      │                     │◄──────────────────────────────────────┤                  │
         │                      │                     │  11. signed cert + chain               │                  │
         │                      │                     │                     │                  │                  │
         │                      │              12. Patch CertificateRequest.status.certificate │                  │
         │                      │                     ├────────────────────►│                  │                  │
         │                      │                     │                     │                  │                  │
         │                      │                     │              13. cert-manager writes Secret istiod-tls    │
         │                      │                     │                     │  tls.crt / tls.key / ca.crt         │
         │                      │                     │                     │                  │                  │
         │                      │                     │                     │          14. istiod mounts Secret istiod-tls
         │                      │                     │                     │◄──────────────────────────────────── │
         │                      │                     │                     │               serves xDS on port 15012
```

### 1b. ztunnel Node Certificate

Unlike istiod, ztunnel does **not** load a pre-provisioned cert-manager `Certificate` Secret.
It talks to istio-csr **directly** via `CA_ADDRESS` (for example
`cert-manager-istio-csr.cert-manager.svc:443`) and has no volume mount for a static TLS
Secret. Upstream ztunnel (`istio/ztunnel`) confirms there is no static-certificate path.

ztunnel's own SPIFFE identity is fetched **dynamically**, on demand, the same way as any
workload SVID — through `CA_ADDRESS` → cert-manager-istio-csr → cert-manager
`CertificateRequest` → `athenz-istio-issuer` → ZTS. No separate `Certificate` resource is
involved. The identity is `spiffe://{TRUST_DOMAIN}/ns/istio-system/sa/{SERVICE_ACCOUNT}`,
built from:
- `TRUST_DOMAIN` env var (example: `athenz.io`; ztunnel defaults to `cluster.local` when
  unset, per `src/config.rs`'s `DEFAULT_TRUST_DOMAIN`)
- the pod's ServiceAccount (example: `example.k8s.ztunnel`; the upstream chart hardcodes
  `serviceAccountName`, so deployments typically patch it)

**What this identity is used for:**
- ztunnel's XDS connection to istiod authenticates via the projected `istio-token` bearer
  JWT (`aud=istio-ca`), **not** an x509 client cert.
- ztunnel-to-ztunnel HBONE tunnels carry the impersonated **workload's** SVID (e.g.
  `app.frontend.curl`), **not** a separate ztunnel node cert — see Section 5.
- Per ztunnel's own source (`proxyfactory.rs`,
  `create_ztunnel_self_proxy_listener`), this identity exists so ztunnel can treat its
  own metrics port (15020) as a workload for policy on inbound scrape traffic. It is
  fetched lazily on first use via the standard on-demand `SecretManager` path
  (`src/cert_fetcher.rs`).

---

## Section 2: istio-csr Serving Certificate

istio-csr is the gRPC CA bridge that istiod forwards workload SVID requests to. It exposes
port 6443 (gRPC TLS). istiod connects to it and verifies its certificate.

### Why this required code changes to istio-csr

istio-csr v0.16 generates its own serving CSR internally using `pkiutil.GenCSR()`, which
produces a **DNS-only CSR** — no SPIFFE URI SAN. athenz-issuer requires a SPIFFE URI to
identify the Athenz domain and service and call ZTS. Without a URI SAN, signing fails with
`"failed to get service account or in namespace : resource name may not be empty"`.

The fix: two new flags that tell istio-csr to **skip generating its own CSR** and instead
load its serving cert from a pre-provisioned cert-manager Certificate Secret.

#### Code changes (`csi-driver-athenz/istio-csr/`)

**`pkg/tls/tls.go`** — core change
```
Added:
  Options.ServingCertificateSecretName   string
  Options.ServingCertificateSecretNamespace string
  Provider.k8sClient                     kubernetes.Interface

New method loadFromSecret():
  reads tls.crt / tls.key / ca.crt from the named Secret
  parses and returns the tls.Certificate directly

Modified fetchCertificate():
  if ServingCertificateSecretName != "":
      return loadFromSecret()   // ← new path
  else:
      // original GenCSR() path (unchanged)
```

**`cmd/app/options/options.go`** — two new CLI flags
```
--serving-certificate-secret-name       string
--serving-certificate-secret-namespace  string

Also: relaxed the DNS-names validation check — previously it rejected
startup if --serving-dns-names was empty, which conflicts with Secret mode
where DNS SANs are embedded in the pre-provisioned cert.
```

**`cmd/app/app.go`** — wire k8s client into tls.Provider
```
Passes the existing k8s client (cl) into tls.NewProvider() so that
loadFromSecret() can call the Secrets API.
```

**`pkg/certmanager/certmanager.go`** — mutex deadlock fix
```
HasIssuerConfig() was acquiring Lock() (write lock) while only reading
activeIssuerRef. Sign() holds RLock() for the full duration of certificate
signing. Under concurrent workload SVID load, HasIssuerConfig() (called
on every readiness probe) blocked on the write lock held by Sign() →
readiness probe timeout → pod NotReady.

Fix: Lock()/Unlock() → RLock()/RUnlock() in HasIssuerConfig().
```

### Sequence Diagram: istio-csr Serving Certificate

```
    cert-manager           approver-policy       athenz-issuer        Kubernetes API       Athenz ZTS          istio-csr
       (CM)                    (AP)                  (AI)                 (K8S)              (ZTS)              (ICSR)
         │                      │                     │                     │                  │                   │
         │  [watches Certificate: istio-infra/istio-csr-cert.yaml           │                  │                   │
         │   issuerRef=athenz-istio-issuer  secretName=cert-manager-istio-csr-athenz-tls]      │                   │
         │                      │                     │                     │                  │                   │
         │  1. Generate EC key pair and CSR           │                     │                  │                   │
         │     CN:      example.k8s.cert-manager-istio-csr           │                  │                   │
         │     URI SAN: spiffe://athenz.io/ns/cert-manager/sa/example.k8s.cert-manager-istio-csr         │
         │     DNS SAN: cert-manager-istio-csr.cert-manager.svc              │                  │                   │
         │              cert-manager-istio-csr.cert-manager.svc.cluster.local│                  │                   │
         │                      │                     │                     │                  │                   │
         │  2. Create CertificateRequest istio-csr-cert-1                   │                  │                   │
         ├──────────────────────────────────────────────────────────────── ►│                  │                   │
         │                      │                     │                     │                  │                   │
         │               3. Watch and approve istio-csr-cert-1              │                  │                   │
         │               ◄───────────────────────────────────────────────── │                  │                   │
         │               ─────────────────────────────────────────────────► │                  │                   │
         │                      │                     │                     │                  │                   │
         │                      │              4. Watch CertificateRequest istio-csr-cert-1 (Approved=True)        │
         │                      │              ◄───────────────────────────┤                  │                   │
         │                      │                     │                     │                  │                   │
         │                      │              5. Parse SPIFFE URI: ns=cert-manager sa=example.k8s.cert-manager-istio-csr
         │                      │                     │  -> domain=example.k8s service=cert-manager-istio-csr
         │                      │                     │                     │                  │                   │
         │                      │              6. TokenRequest for SA example.k8s.cert-manager-istio-csr    │
         │                      │                     ├────────────────────►│                  │                   │
         │                      │                     │◄────────────────────┤                  │                   │
         │                      │                     │  SA token           │                  │                   │
         │                      │                     │                     │                  │                   │
         │                      │              7. POST /zts/v1/instance     │                  │                   │
         │                      │                     │  domain=example.k8s  service=cert-manager-istio-csr │
         │                      │                     │  csr.CN:      example.k8s.cert-manager-istio-csr    │
         │                      │                     │  csr.URI SAN: spiffe://athenz.io/ns/cert-manager/sa/example.k8s.cert-manager-istio-csr
         │                      │                     │  csr.DNS SAN: cert-manager-istio-csr.cert-manager.svc(.cluster.local)
         │                      │                     │  identityToken: SA token               │                   │
         │                      │                     ├─────────────────────────────────────── ►│                   │
         │                      │                     │                     │                  │                   │
         │                      │                     │                     │           8. Validate and sign cert   │
         │                      │                     │                     │               Issuer:  Athenz CA│
         │                      │                     │                     │               Subject: CN=example.k8s.cert-manager-istio-csr
         │                      │                     │                     │               URI SAN: spiffe://athenz.io/ns/cert-manager/sa/example.k8s.cert-manager-istio-csr
         │                      │                     │                     │               DNS SAN: cert-manager-istio-csr.cert-manager.svc(.cluster.local)
         │                      │                     │◄──────────────────────────────────────┤                   │
         │                      │                     │  9. signed cert + chain                │                   │
         │                      │                     │                     │                  │                   │
         │                      │             10. Write Secret cert-manager-istio-csr-athenz-tls                   │
         │                      │                     ├────────────────────►│                  │                   │
         │                      │                     │                     │                  │                   │
         │                      │                     │             11. istio-csr starts with flags:               │
         │                      │                     │                     │  serving-certificate-secret-name=cert-manager-istio-csr-athenz-tls
         │                      │                     │                     │  serving-certificate-secret-namespace=cert-manager
         │                      │                     │                     │  (loadFromSecret() instead of GenCSR())
         │                      │                     │                     │◄──────────────────────────────────── │
         │                      │                     │                     │                  │  tls.crt / tls.key / ca.crt
         │                      │                     │                     │                  │                   │
         │                      │                     │                     │                  │  12. Serve gRPC on port 6443
         │                      │                     │                     │                  │      using Athenz-signed cert
         │                      │                     │                     │                  │      istiod connects and verifies
         │                      │                     │                     │                  │      against Athenz CA trust bundle
```

---

## Section 3: Workload SVIDs

Once the control plane is up (istiod cert + ztunnel node cert + istio-csr serving cert all
ready), ztunnel can request per-pod SVIDs for workloads in the ambient mesh. This path goes
through gRPC, not cert-manager `Certificate` objects — the requests are ephemeral and
generated on demand by ztunnel as pods join the mesh.

### SA Naming: Approach A

Workload SAs use fully-qualified names: `{athenz-domain}.{athenz-service}`.
signer.go splits on the last dot to extract domain and service:
- SA `app.frontend.curl` → domain=`app.frontend`, service=`curl`
- SA `app.backend.httpbin` → domain=`app.backend`, service=`httpbin`

```
  Workload Pod      ztunnel          istiod         istio-csr      cert-manager    athenz-issuer   Kubernetes API    Athenz ZTS
    (POD)            (ZT)            (ISO)           (ICSR)          (CM/AP)           (AI)            (K8S)            (ZTS)
       │               │               │               │               │                 │               │                │
       │  [Pod scheduled on node       │               │               │                 │               │                │
       │   NS label: istio.io/dataplane-mode=ambient   │               │                 │               │                │
       │   SA: app.frontend.curl]   │               │               │                 │               │                │
       │               │               │               │               │                 │               │                │
       │  1. pod joins ambient mesh (istio-cni iptables redirect)       │                 │               │                │
       ├──────────────►│               │               │               │                 │               │                │
       │               │               │               │               │                 │               │                │
       │               │  2. Generate EC P-256 key pair on behalf of pod│                 │               │                │
       │               │     CSR Subject: (empty - SPIFFE spec)         │                 │               │                │
       │               │     CSR URI SAN: spiffe://athenz.io/ns/app-frontend/sa/app.frontend.curl│               │
       │               │     CSR DNS SAN: (none)        │               │                 │               │                │
       │               │               │               │               │                 │               │                │
       │               │  3. gRPC IstioCertificateService.CreateCertificate               │               │                │
       │               │     Bearer: ztunnel SA token (SA=example.k8s.ztunnel, aud=istio-ca)       │                │
       │               │     ImpersonatedIdentity: spiffe://athenz.io/ns/app-frontend/sa/app.frontend.curl
       │               ├──────────────►│               │               │                 │               │                │
       │               │               │               │               │                 │               │                │
       │               │        4. TokenReview: validate ztunnel Bearer token             │               │                │
       │               │               ├───────────────────────────────────────────────── ►│               │                │
       │               │               │◄───────────────────────────────────────────────── │               │                │
       │               │               │  ok: authenticated as example.k8s.ztunnel  │               │                │
       │               │               │               │               │                 │               │                │
       │               │        5. ClusterNodeAuthorizer: ztunnel is trusted node agent, workload pod on same node ok
       │               │               │               │               │                 │               │                │
       │               │        6. gRPC CreateCertificate forwarded (ImpersonatedIdentity preserved, no token)
       │               │               ├──────────────►│               │                 │               │                │
       │               │               │               │               │                 │               │                │
       │               │               │        7. ClusterNodeAuthorizer: node-workload co-location ok   │                │
       │               │               │               │               │                 │               │                │
       │               │               │        8. Create CertificateRequest istio-csr-xxxx               │                │
       │               │               │               │  spec.request: CSR (Subject empty, URI SAN only, no DNS SANs)    │
       │               │               │               │  spec.issuerRef: athenz-istio-issuer              │                │
       │               │               │               │  annotation istio.cert-manager.io/identities:     │                │
       │               │               │               │    spiffe://athenz.io/ns/app-frontend/sa/app.frontend.curl
       │               │               │               │  (no SA token - trust fully consumed above)       │                │
       │               │               │               ├──────────────►│                 │               │                │
       │               │               │               │               │                 │               │                │
       │               │               │               │        9. approver-policy: policy match ok, Approved=True         │
       │               │               │               │               │                 │               │                │
       │               │               │               │               │                 10. Read SPIFFE URI from annotation
       │               │               │               │               │                     ns=app-frontend  sa=app.frontend.curl
       │               │               │               │               │                     SA has dots -> split on last dot
       │               │               │               │               │                     -> domain=app.frontend  service=curl
       │               │               │               │               │                 │               │                │
       │               │               │               │               │                 11. TokenRequest for SA app.frontend.curl
       │               │               │               │               │                 ├──────────────►│                │
       │               │               │               │               │                 │◄──────────────┤                │
       │               │               │               │               │                 │  SA token (GCP OIDC-signed, 1h TTL)
       │               │               │               │               │                 │  sub: system:serviceaccount:app-frontend:app.frontend.curl
       │               │               │               │               │                 │  iss: cluster OIDC issuer         │
       │               │               │               │               │                 │  aud: ZTS URL  │                │
       │               │               │               │               │                 │  (SA-bound, no pod claim)       │
       │               │               │               │               │                 │               │                │
       │               │               │               │               │                 12. POST /zts/v1/instance        │
       │               │               │               │               │                     domain=app.frontend  service=curl
       │               │               │               │               │                     provider=sys.k8s.gcp  namespace=app-frontend
       │               │               │               │               │                     csr: Subject empty, URI SAN only, no DNS SANs
       │               │               │               │               │                     identityToken: SA token      │
       │               │               │               │               │                 ├───────────────────────────────► │
       │               │               │               │               │                 │               │                │
       │               │               │               │               │                 │        13. Validate SA token: sub, aud, iss ok
       │               │               │               │               │                 │            GCP OIDC issuer check ok
       │               │               │               │               │                 │            CSR CN empty - skip (patch 1)
       │               │               │               │               │                 │            DNS SANs none + URI SAN is spiffe - bypass DNS validation (patch 2)
       │               │               │               │               │                 │            Sign cert:
       │               │               │               │               │                 │              Issuer:  Athenz CA
       │               │               │               │               │                 │              Subject: (empty)
       │               │               │               │               │                 │              URI SAN: spiffe://athenz.io/ns/app-frontend/sa/app.frontend.curl
       │               │               │               │               │                 │              Validity: 7 days
       │               │               │               │               │                 │◄─────────────────────────────── │
       │               │               │               │               │                 │  14. signed cert + chain        │
       │               │               │               │               │                 │               │                │
       │               │               │               │              15. Patch CertificateRequest.status.certificate      │
       │               │               │               │               │◄────────────────┤               │                │
       │               │               │               │               │  Ready=True     │               │                │
       │               │               │◄──────────────┤               │                 │               │                │
       │               │◄──────────────┤               │               │                 │               │                │
       │               │  16. gRPC response: signed cert chain          │                 │               │                │
       │               │               │               │               │                 │               │                │
       │               │  17. Store SPIFFE cert in memory keyed by pod identity           │               │                │
       │               │      Used for HBONE mTLS on behalf of the pod  │                 │               │                │
```

---

## Section 4: Waypoint Proxy Certificate

The waypoint is an Envoy-based L7 proxy deployed as a Kubernetes Deployment in the
application namespace. It enforces `AuthorizationPolicy` for all traffic destined to services
in that namespace. Like ztunnel, the waypoint calls istio-csr **directly** (via `CA_ADDRESS`)
for its own SPIFFE SVID — bypassing the ztunnel → istiod hop that workload SVIDs use.

### Waypoint ServiceAccount: dotted, platform-provisioned

The waypoint's SA is `app.backend.waypoint` — the same `{domain}.{service}` (Approach A)
naming as every workload SA in Section 3. athenz-issuer derives the domain and service by
splitting on the last dot, ZTS validates the resulting SPIFFE URI with the
standard `SpiffeUriTrustDomain` validator, and the subject validator cryptographically
binds the domain to the SA name attested in the token. No annotations, no dot-free
SPIFFE machinery, and no waypoint-specific trust model: the waypoint is just another
workload identity that happens to be an L7 proxy.

Getting a dotted SA requires the platform to provision the waypoint itself, because
Istio's **managed** waypoint path cannot produce one: the gateway controller derives the
Kubernetes Service name from the Gateway name, Service names must be DNS-1035 compliant
(no dots), and a dotted Gateway name therefore fails Service creation permanently —
leaving the Gateway `Programmed=False` with no VIP for ztunnel to route to. The
platform-provisioned ("bring your own") pattern — pre-created SA `app.backend.waypoint`,
a hyphenated Service (`app-backend-waypoint`), a rendered proxy Deployment, and a Gateway
with `spec.addresses` preset — is specified and evidenced in
[istio-ambient-waypoint-setup.md](istio-ambient-waypoint-setup.md).

> An earlier revision of this design used a dot-free SA (`waypoint`) with the Athenz
> domain carried out of band via an `athenz.io/domain` annotation and an opt-in dot-free
> SPIFFE validator. It was superseded by the dotted-SA setup, which binds the domain to
> the attested SA name and removes the annotation trust surface and its multi-tenant
> implications entirely.

### Sequence Diagram

```
      waypoint           istio-csr       cert-manager      athenz-issuer     Kubernetes API      Athenz ZTS
       (WP)               (ICSR)           (CM/AP)              (AI)             (K8S)              (ZTS)
         │                  │                 │                   │                 │                  │
         │  [SA=app.backend.waypoint (pre-created by the platform, see waypoint-setup doc)              │
         │   CA_ADDR=cert-manager-istio-csr.cert-manager.svc:443]  │                 │                  │
         │                  │                 │                   │                 │                  │
         │  1. Generate EC P-256 key pair and CSR                  │                 │                  │
         │     Subject: O= (empty string - Istio bug in GenCSRTemplate)             │                  │
         │     URI SAN: spiffe://athenz.io/ns/app-backend/sa/app.backend.waypoint  │                  │
         │     DNS SAN: (none)              │                   │                 │                  │
         │                  │                 │                   │                 │                  │
         │  2. gRPC CreateCertificate       │                   │                 │                  │
         │     csr (Subject O=, URI SAN only)│                   │                 │                  │
         │     identities: spiffe://athenz.io/ns/app-backend/sa/app.backend.waypoint                 │
         ├─────────────────►│                 │                   │                 │                  │
         │                  │                 │                   │                 │                  │
         │           3. Create CertificateRequest istio-csr-xxxx  │                 │                  │
         │                  │  spec.request: CSR (Subject O=, URI SAN only, no DNS SANs)              │
         │                  │  spec.issuerRef: athenz-istio-issuer │                 │                  │
         │                  │  annotation istio.cert-manager.io/identities:         │                  │
         │                  │    spiffe://athenz.io/ns/app-backend/sa/app.backend.waypoint            │
         │                  ├────────────────►│                   │                 │                  │
         │                  │                 │                   │                 │                  │
         │                  │          4. approver-policy: policy match ok, Approved=True              │
         │                  │                 │                   │                 │                  │
         │                  │                 │            5. Read SPIFFE URI from annotation          │
         │                  │                 │               ns=app-backend  sa=app.backend.waypoint    │
         │                  │                 │               SA has dots -> split on last dot         │
         │                  │                 │               -> domain=app.backend  service=waypoint    │
         │                  │                 │                   │                 │                  │
         │                  │                 │            6. TokenRequest for SA app.backend.waypoint   │
         │                  │                 │                   ├────────────────►│                  │
         │                  │                 │                   │◄────────────────┤                  │
         │                  │                 │                   │  SA token       │                  │
         │                  │                 │                   │  sub: system:serviceaccount:app-backend:app.backend.waypoint
         │                  │                 │                   │  iss: cluster OIDC issuer             │
         │                  │                 │                   │  aud: ZTS URL   │                  │
         │                  │                 │                   │                 │                  │
         │                  │                 │            7. POST /zts/v1/instance │                  │
         │                  │                 │               domain=app.backend  service=waypoint       │
         │                  │                 │               provider=sys.k8s.gcp  namespace=app-backend
         │                  │                 │               csr: Subject O= (empty), URI SAN only, no DNS SANs
         │                  │                 │               identityToken: SA token                  │
         │                  │                 │                   ├─────────────────────────────────── ►│
         │                  │                 │                   │                 │                  │
         │                  │                 │                   │                 │          8. Validate SA token ok
         │                  │                 │                   │                 │             GCP OIDC issuer check ok
         │                  │                 │                   │                 │             sub SA name == domain.service ok
         │                  │                 │                   │                 │             CSR CN empty - skip (patch 1)
         │                  │                 │                   │                 │             DNS SANs none + spiffe URI - bypass DNS validation (patch 2)
         │                  │                 │                   │                 │             Subject O= empty string - treat as absent (patch 3)
         │                  │                 │                   │                 │             URI SAN - standard SpiffeUriTrustDomain validation
         │                  │                 │                   │                 │             Sign cert:
         │                  │                 │                   │                 │               Issuer:  Athenz CA
         │                  │                 │                   │                 │               Subject: O= (preserved from CSR)
         │                  │                 │                   │                 │               URI SAN: spiffe://athenz.io/ns/app-backend/sa/app.backend.waypoint
         │                  │                 │                   │                 │               Validity: 7 days
         │                  │                 │                   │◄───────────────────────────────── │
         │                  │                 │                   │  9. signed cert + chain            │
         │                  │                 │                   │                 │                  │
         │                  │                 │            10. Patch CertificateRequest.status.certificate
         │                  │                 │◄──────────────────┤                 │                  │
         │                  │◄────────────────┤  CR Ready=True    │                 │                  │
         │◄─────────────────┤                 │                   │                 │                  │
         │  11. gRPC response: signed cert chain                   │                 │                  │
         │                  │                 │                   │                 │                  │
         │  12. Hold cert in memory           │                   │                 │                  │
         │      Serve HBONE port 15008        │                   │                 │                  │
         │      ztunnel routes L7 traffic here│                   │                 │                  │
```

### How the waypoint differs from the workload SVID path

| Aspect | Workload SVID (Section 3) | Waypoint cert (Section 4) |
|--------|--------------------------|--------------------------|
| CSR generator | ztunnel (on behalf of pod) | waypoint pilot-agent (for itself) |
| First gRPC hop | ztunnel → istiod → istio-csr | waypoint → istio-csr (direct) |
| SA naming | Approach A: `{domain}.{service}` (dots) | Same Approach A: `{domain}.waypoint` (platform pre-created, see waypoint-setup doc) |
| Domain derivation | Split SA on last dot | Split SA on last dot (identical) |
| Namespace naming | Free choice | Free choice |
| Subject DN | Completely empty (SPIFFE spec) | `O=` (empty Organization — Istio bug) |
| DNS SANs | None | None |
| ZTS patches needed | #1 (CN) and #2 (DNS bypass) | #1 (CN) and #2 (DNS bypass) and #3 (empty O=) |
| Cert held by | ztunnel in-memory (per pod) | waypoint in-memory (for itself) |
| Used for | HBONE mTLS between ztunnel nodes | HBONE mTLS to/from ztunnel + L7 policy enforcement |

### L7 Data Plane Flow (with Waypoint)

ztunnel is involved at **both ends**. The waypoint sits between the source and destination
ztunnels — it does not replace them. istiod's xDS pushes waypoint routing rules to ztunnel:
when ztunnel sees traffic destined for the `httpbin` Service it routes to the waypoint first
instead of directly to the destination ztunnel. The waypoint evaluates L7 policy, then
opens a second HBONE hop to the destination ztunnel, which delivers plaintext to the pod.

```
   curl pod          ztunnel           waypoint          ztunnel          httpbin pod
 (app-frontend)  (curl node)    (app-backend/waypoint) (httpbin node)   (app-backend)
       │                │                  │                  │                │
       │  1. plain TCP to httpbin:80 (intercepted by eBPF/iptables)            │
       ├───────────────►│                  │                  │                │
       │                │                  │                  │                │
       │                │  [xDS from istiod: httpbin Service has waypoint annotation
       │                │   route to waypoint instead of direct]               │
       │                │                  │                  │                │
       │                │  2. HBONE CONNECT port 15008         │                │
       │                │     mTLS: src=curl SVID, dst=waypoint SVID           │
       │                │     inner dst: httpbin pod IP:80     │                │
       │                ├─────────────────►│                  │                │
       │                │                  │                  │                │
       │                │                  │  [terminates mTLS                 │
       │                │                  │   source principal:               │
       │                │                  │   spiffe://athenz.io/ns/app-frontend/sa/app.frontend.curl
       │                │                  │   evaluates AuthorizationPolicy httpbin-get-only
       │                │                  │   method GET  -> ALLOW            │
       │                │                  │   method POST -> DENY 403]        │
       │                │                  │                  │                │
       │                │                  │  3. HBONE CONNECT port 15008      │
       │                │                  │     mTLS: src=waypoint SVID, dst=httpbin SVID
       │                │                  │     inner dst: httpbin pod IP:80  │
       │                │                  ├─────────────────►│                │
       │                │                  │                  │                │
       │                │                  │                  │  4. plain TCP to httpbin:80
       │                │                  │                  ├───────────────►│
       │                │                  │                  │◄───────────────┤
       │                │                  │◄─────────────────┤  HTTP response │
       │                │◄─────────────────┤  HBONE response  │                │
       ◄────────────────┤  plain TCP response                  │                │
```

Two HBONE hops are always used when a waypoint is present — one from source ztunnel to
waypoint and one from waypoint to destination ztunnel. L4-only paths (no waypoint) use a
single ztunnel-to-ztunnel hop (see Section 5).

---

## Section 5: mTLS — How the Cert Is Used in Traffic (L4, no waypoint)

```
  curl pod          ztunnel-A          ztunnel-B         httpbin pod
(app-frontend,  (Node A)           (Node B)          (app-backend,
  Node A)                                                 Node B)
     │                 │                  │                  │
     │  1. plaintext TCP (iptables intercept to port 15001)  │
     ├────────────────►│                  │                  │
     │                 │                  │                  │
     │                 │  2. HBONE/mTLS tunnel on port 15008 │
     │                 │     Client cert (ztunnel-A, on behalf of curl):
     │                 │       Subject: (empty)              │
     │                 │       URI SAN: spiffe://athenz.io/ns/app-frontend/sa/app.frontend.curl
     │                 │       Issuer:  Athenz CA      │
     │                 │     Server cert (ztunnel-B, on behalf of httpbin):
     │                 │       Subject: (empty)              │
     │                 │       URI SAN: spiffe://athenz.io/ns/app-backend/sa/app.backend.httpbin
     │                 │       Issuer:  Athenz CA      │
     │                 ├─────────────────►│                  │
     │                 │                  │                  │
     │                 │          3. Verify client cert URI SAN
     │                 │             Evaluate AuthorizationPolicy
     │                 │                  │                  │
     │                 │          4. plaintext TCP into pod netns
     │                 │                  ├─────────────────►│
     │                 │                  │◄─────────────────┤
     │                 │                  │  response        │
     │                 │◄─────────────────┤  HBONE/mTLS      │
     │◄────────────────┤  plaintext response                  │
```

**Application pods send and receive plaintext. mTLS is entirely within ztunnel.**

---

## Section 6: Ingress Gateway and Egress Waypoint

In ambient mode there is no separate "istio egress gateway" component — the egress role is
played by a **waypoint** attached to a `ServiceEntry` (6c). Like the service-side waypoint
(Section 4), both gateway types run with **dotted ServiceAccounts** so their mesh
identities are standard domain-qualified SPIFFE identities.

### 6a. Gateway ServiceAccounts: dotted, not controller-derived

Istio's *managed* gateway path cannot produce dotted SAs: for `gatewayClassName: istio`
the controller generates Deployment/Service/SA named `<Gateway name>-<GatewayClass name>`
(the `istio-waypoint` class keeps the bare Gateway name), and the derived Service name
must be DNS-1035 — a dotted Gateway name fails Service creation permanently. So, as with
waypoints, gateway identities come from platform-managed provisioning:

- **Egress waypoint**: identical to the service-side waypoint — the BYO pattern in
  [istio-ambient-waypoint-setup.md](istio-ambient-waypoint-setup.md), attached to a
  `ServiceEntry` instead of in-cluster Services.
- **Ingress gateway**: a Helm/manually-deployed gateway with a dotted
  `serviceAccountName` (e.g. `example.k8s.ingressgateway`) is the established route; the
  Gateway API BYO analog (mirroring the waypoint-setup pattern) should work identically
  but is untested.

Dot-free SAs are **not supported** by this design — a dot-free identity would have no
derivable Athenz domain and is rejected at issuance.

### 6b. Ingress gateway: two certificates, two roles

| Certificate | Form | Issuance path | Used for |
|-------------|------|---------------|----------|
| Mesh SVID | SPIFFE SVID (dotted SA) | pilot-agent → istio-csr → athenz-issuer → ZTS (Section 4 flow) | HBONE to waypoints and ztunnels — backends see this principal |
| Listener (server) cert | Athenz service cert (CN + DNS SANs) **or** a public-CA cert | cert-manager `Certificate` → Secret, referenced by the Gateway listener `certificateRefs` | TLS / mTLS termination for external clients |

**The listener's server cert and its client-validation bundle are independent
configuration.** The server cert is whatever Secret `certificateRefs` points at, and
cert-manager serves both worlds side by side: `athenz-istio-issuer` for an Athenz-CA cert
(Section 1a pattern), or a public-CA issuer (DigiCert / GlobalSign / ACME) — switching is a
one-line `issuerRef` change in the `Certificate` object. In practice most teams will
present a **public-CA server cert**, since it works with every client's system trust store,
whereas an Athenz-CA server cert requires clients to carry the Athenz trust bundle (fine
for SIA/Athenz-aware clients, a distribution burden otherwise). Either choice composes with
mTLS client validation against the **Athenz CA** (`tls.mode: MUTUAL`): "present DigiCert,
validate clients against Athenz" is a coherent — and likely the majority — listener
configuration. The gateway's mesh-facing identity is unaffected either way: toward
waypoints and backends it always presents its mesh SVID; the listener cert never appears
inside the mesh.

**Exposure note:** the Gateway's generated Service (default `type: LoadBalancer`) may be
internal (RFC1918, corp-network reachable — the common case when the "external" clients
are simply non-mesh internal services) or public. For the mTLS client flow below, the load
balancer must be **L4/passthrough** — an L7 LB or edge proxy that terminates TLS upstream
consumes the client certificate before the gateway can validate it.

External mTLS client flow (e.g. an EC2 service holding an SIA-issued Athenz cert):

1. The listener uses `tls.mode: MUTUAL` with the global Athenz CA as the client-validation
   bundle — the handshake cryptographically verifies the external client's Athenz cert.
2. Fine-grained authorization of external clients happens **at the gateway**: an
   `AuthorizationPolicy` targeting the gateway matches `source.principals` against the
   client cert's SPIFFE URI SAN (the CN is not used for principal matching when SANs are
   present — for Athenz certs the URI and CN both encode `{domain}.{service}`), combined
   with L7 `to.operation` conditions (methods, paths).
3. Envoy forwards the validated client identity upstream in the `X-Forwarded-Client-Cert`
   header (gateway default `SANITIZE_SET`: the header is rebuilt from the validated cert,
   so client-supplied values are discarded). It carries `Subject` (the CN) and `URI`;
   backend applications may parse it for app-level decisions.
4. **Identity terminates at the gateway.** Backends see the gateway's mesh SVID as the
   source principal, so backend policy allows the gateway principal. To have the backend's
   waypoint also process gateway-originated traffic (single L7 enforcement point), label
   the Service or Namespace with `istio.io/ingress-use-waypoint: "true"` — by default,
   ingress-originated traffic bypasses the destination waypoint.
5. Ambient caveat: ztunnel is an L4 proxy and does not sanitize HTTP headers, so XFCC is
   only trustworthy when backend policy restricts ingress to the gateway / waypoint
   principals — otherwise any mesh workload could forge the header on a direct connection.

### 6c. Egress waypoint

The egress waypoint **is a Section 4 waypoint** — same platform-provisioned setup, same
dotted SA, same SVID, same issuance flow. The only differences are its attachment (a
`ServiceEntry` describing the external destination, labeled `istio.io/use-waypoint`,
instead of an in-cluster Service) and its outbound leg: when outbound traffic matches the
`ServiceEntry`, the source ztunnel routes it over HBONE to the egress waypoint carrying the
**originating app's SVID** (the hook for egress `AuthorizationPolicy` — which workloads may
exit, to which hosts and paths), and from the waypoint the connection goes **directly out
to the external load balancer**. There is no second ztunnel hop — that exists only for
in-mesh destinations, where HBONE needs a mesh peer to terminate it.

```
app pod ──plaintext──► ztunnel ──HBONE (app SVID)──► egress waypoint ──TLS/mTLS──► external LB
```

For the outbound leg's identity, the waypoint's mesh SVID is not presented outside the
mesh — the SVID is an HBONE artifact with an empty CN, and the origination cert is
configured separately:

- **Waypoint-originated mTLS:** register a real Athenz service (e.g.
  `example.k8s.egress-gw`), provision a standard Athenz service cert via a cert-manager `Certificate`
  Secret (Section 1a pattern), and reference it from the `DestinationRule`
  (`tls.mode: MUTUAL`, `credentialName`). Requires the app to send plaintext, and coarsens
  identity: the external service sees one identity for every app behind the waypoint.
- **App-level passthrough (recommended for Athenz-protected destinations):** with no
  `ServiceEntry` waypoint attached, ztunnel forwards traffic to unknown destinations
  untouched — the app's own Athenz cert (csi-driver-athenz, the existing in-production
  flow) does end-to-end mTLS, preserving per-app identity and existing Athenz
  authorization. In this default mode nothing egress-shaped is in the path at all.
- Non-Athenz destinations (plain TLS origination) are unaffected by this design.

### 6d. Gateway onboarding checklist

Per gateway service, same as a waypoint:

1. Platform-provisioned resources with the dotted SA — the BYO bundle for waypoints
   ([istio-ambient-waypoint-setup.md](istio-ambient-waypoint-setup.md)), or a
   Helm/manual deployment with a dotted `serviceAccountName` for the ingress gateway.
2. Athenz service registered with its standard launch authorizer role/policy (Terraform
   `k8s-provider` module, 3-segment assertion — same as any workload).
3. Ingress only: the listener `Certificate` + Secret (Athenz or public CA), and the
   gateway-level `AuthorizationPolicy` for external client principals.

Because gateway identities are domain-qualified, the domain is carried inside the identity and
bound to the attested SA name — no gateway-specific trust model or additional isolation
machinery is required.

---

## Certificate Fields by Component

| Certificate | CN | URI SAN | DNS SANs | Subject | Issuer |
|-------------|----|---------|-----------|---------|----|
| istiod-tls | `example.k8s.istiod` | `spiffe://athenz.io/ns/istio-system/sa/example.k8s.istiod` | `istiod.istio-system.svc[.cluster.local]` | = CN | Athenz CA |
| ztunnel node cert | `example.k8s.ztunnel` | `spiffe://athenz.io/ns/istio-system/sa/example.k8s.ztunnel` | `ztunnel.istio-system.svc.cluster.local` | = CN | Athenz CA |
| istio-csr serving cert | `example.k8s.cert-manager-istio-csr` | `spiffe://athenz.io/ns/cert-manager/sa/example.k8s.cert-manager-istio-csr` | `cert-manager-istio-csr.cert-manager.svc[.cluster.local]` | = CN | Athenz CA |
| Workload SVID (curl) | *(empty)* | `spiffe://athenz.io/ns/app-frontend/sa/app.frontend.curl` | *(none)* | *(empty)* | Athenz CA |
| Workload SVID (httpbin) | *(empty)* | `spiffe://athenz.io/ns/app-backend/sa/app.backend.httpbin` | *(none)* | *(empty)* | Athenz CA |
| Waypoint SVID | *(empty)* | `spiffe://athenz.io/ns/app-backend/sa/app.backend.waypoint` | *(none)* | `O=` (empty — Istio bug) | Athenz CA |

> Control-plane certs have a CN and DNS SANs because components connect to them by hostname.
> `athenz-issuer` supplies `instanceId` explicitly via the `x509CertInstanceId` request field
> (set from the SA's UID) when the CSR carries no `{uid}.instanceid.athenz` DNS SAN — no need
> to embed the SA UUID in the Certificate, and ZTS itself never inspects attestation data to
> derive one (see Patch 5). Workload and waypoint SVIDs carry identity purely in the SPIFFE
> URI SAN, and get their `instanceId` the same way. The waypoint's
> `Subject: O=` (empty Organization field present but blank) is an Istio bug in
> `GenCSRTemplate` — it unconditionally writes `Organization: []string{options.Org}` even when
> `Org` is unset (Go zero value `""`), producing an empty field rather than omitting it.
> See `docs/project_istio_csr_empty_org_bug.md`.

---

## SA Token Flow Per Hop (Workload SVID Path)

| Hop | Token | Identity | Purpose |
|-----|-------|----------|---------|
| ztunnel → istiod | ztunnel's own SA token (Bearer) | `example.k8s.ztunnel`, aud: `istio-ca` | Prove ztunnel is a trusted node agent |
| istiod → istio-csr | none | — | Trust consumed; istiod enforces node-workload co-location |
| istio-csr → CertificateRequest | none | — | CertificateRequest carries only CSR + SPIFFE URI annotation |
| athenz-issuer → K8s TokenRequest | fetches fresh token | `app.frontend.curl`, aud: ZTS URL | Obtain proof of workload identity for ZTS |
| athenz-issuer → ZTS | workload SA token | `sub: system:serviceaccount:app-frontend:app.frontend.curl`<br>`iss`: cluster OIDC issuer<br>`aud`: ZTS URL<br>no pod claim — SA-bound | ZTS validates against the cluster OIDC JWKS; confirms sub matches domain.service |

---

## ZTS Patches for Workload SVIDs

Changes span `servers/zts` (WAR) and `libs/java/instance_provider` /
`libs/java/server_common` (often deployed on ZTS's Jetty ext-classpath).

> **Classloading constraint:** when `athenz-instance-provider` (and related) JARs are on
> ZTS's ext-classpath, Jetty parent-first classloading means updates only inside the WAR
> are silently ignored. Deploy matching JARs to the ext-classpath as well.

### Patch 1 — Skip CN validation for empty Subject (`X509ServiceCertRequest.java`)
SPIFFE SVIDs have no Subject DN by spec. ZTS required CN == `domain.service`. The patch
skips the CN check when the CSR CN is empty, relying instead on the URI SAN validation.
Affects: workload SVIDs and waypoint SVID.

### Patch 2 — Skip DNS hostname validation for SPIFFE-only SVIDs, bind the SPIFFE namespace (K8s provider)
Workload SVIDs carry no DNS SANs. The K8s distribution validators previously failed on an
empty DNS SAN list. DNS checks are skipped only when there are no DNS SANs and a SPIFFE URI
SAN is present (`InstanceK8SProvider` / `DefaultGCPGoogleKubernetesEngineValidator`).
`confirmInstance` still always runs so the SA token is verified (signature, issuer,
audience, subject). Affects: workload SVIDs and waypoint SVID.

The same patch also binds the SPIFFE namespace to the attestation. K8s attestation compares
only the ServiceAccount *name* (`domain.service`), and the namespace in a request's SPIFFE
URI was previously matched against the `namespace` request field — a caller-supplied value,
which for athenz-issuer is itself derived from that same URI, making the comparison
tautological. `InstanceK8SProvider` now requires the namespace in the CSR's SPIFFE URI to
match the namespace in the validated id_token subject, so an issued identity can only claim
the namespace its workload verifiably runs in. This applies to **every** request carrying a
SPIFFE URI, including DNS-bearing csi-driver requests; requests without a SPIFFE URI carry no
namespace in their identity and are unaffected.

> Behavior change: a deployment whose SPIFFE URI namespace intentionally differs from the
> pod's real namespace will now be rejected. Note this binds the URI only — the namespace
> component inside K8s DNS SANs (`<svc>.<ns>.svc.cluster.local`) is still validated by suffix
> rules alone, which is pre-existing upstream behavior and out of scope here.

### Patch 3 — Accept empty Subject O field (`X509CertRequest.java`)
The waypoint's Envoy generates a CSR with `Subject: O=` — the Organization field is present
but set to empty string. `Crypto.extractX509CSRSubjectOField()` returns `""` (not `null`).
The old check `if (value == null)` did not treat `""` as absent, causing the empty string to
be validated against the allowed-values set and fail. The patch changes the guard to
`if (StringUtils.isEmpty(value))`, treating an empty O field the same as an absent one.
Affects: waypoint SVID only. Root cause is an Istio bug — see note in Certificate Fields table.

### Patch 5 — Caller-supplied `x509CertInstanceId` when absent from CSR SANs (`Instance.rdli`, `ZTSImpl.java`, `InstanceUtils.java`)
Control-plane certs (istiod, ztunnel, istio-csr) and dynamic workload/waypoint SPIFFE SVIDs
carry no `{sa-uid}.instanceid.athenz...` entry — their CSRs are generated by components
(cert-manager core, ztunnel, waypoint's pilot-agent) that `athenz-issuer` never holds the
private key for, so it cannot inject an instanceid SAN into the CSR after the fact.

Per review feedback on PR #3435 (ZTS must never inspect attestation data — it doesn't know
its format, and the caller is responsible for supplying a valid request id), ZTS no longer
derives `instanceId` from the attestation token itself. Instead, `InstanceRegisterInformation`
gained a new optional field, `x509CertInstanceId` (mirrors the pre-existing `jwtSVIDInstanceId`
field used by the JWT SVID flow). `athenz-issuer`'s `Sign()` populates it directly from the
`ServiceAccount.UID` it already fetches via the Kubernetes API for every flow (control-plane,
workload, and waypoint alike — see `athenz-issuer/controller/signer.go`), so this single change
covers all of them uniformly.

`ZTSImpl.postInstanceX509CertificateRegister` falls back to `info.getX509CertInstanceId()`
only when the CSR itself carries no instanceId (CSR SAN DNS/URI, CSI and legacy flows, still
take precedence, unchanged). If neither is present, `X509ServiceCertRequest.validate()`
rejects the request with "InstanceId cannot be empty" — matching the JWT SVID flow's
existing, always-explicit-instanceId behavior. `InstanceUtils.validateCertRequestSanDnsNames()`'s
`ZTS_INSTANCE_ID`-attribute fallback (used by the K8s DNS-suffix validators) is unchanged; it
now simply reads a caller-supplied value instead of a ZTS-derived one.
Affects: istiod, ztunnel, and istio-csr control-plane certs, plus workload and waypoint SVIDs.

**Open follow-up — validating `x509CertInstanceId` against the attested ServiceAccount UID.**
The caller-supplied instance id is not currently checked against the attestation data. The
K8s ServiceAccount token carries a signed `kubernetes.io/serviceaccount/uid` claim, so the
value *can* be verified for this flow — but only for this flow: `csi-driver-athenz` derives
its instance id from the **Pod** UID and embeds it in the CSR as an `athenz://instanceid/...`
SAN, and the SA-bound token (minted with no `BoundObjectRef`) carries no pod claim to compare
it against. A safe check must therefore be scoped to instance ids that arrived via
`x509CertInstanceId`, leaving CSR-derived ones untouched — the same scoping used for the
namespace check above. The remaining work is plumbing: ZTS would need to tell the provider
which source the instance id came from, and the provider would need the nested UID claim
surfaced as a confirmation attribute (only the token subject is stashed today).

Residual risk while this is open is narrow: the domain and service are bound by the SA name
in the token and the namespace by the check above, so a forged instance id yields no identity
escalation. `InstanceK8SProvider.refreshInstance` rejects all K8s refreshes outright, so it
cannot be leveraged into a refresh either. What remains is certificate-record and audit
attribution, plus the location URI.

> Deploy on ZTS **ext-classpath** (`athenz-instance-provider` JAR), not only inside the WAR.

> All ambient SVIDs — workloads, waypoints, and gateways — carry domain-qualified SPIFFE URIs
> (`spiffe://{trustDomain}/ns/{namespace}/sa/{domain}.{service}`), validated by the
> standard `SpiffeUriTrustDomain` validator. No new SPIFFE validator is required.

---

## Key Source Files

| File | Purpose |
|------|---------|
| `istio-infra/athenz-istio-issuer.yaml` | `AthenzClusterIssuer` pointing at ZTS |
| `istio-infra/crp-athenz-istio-issuer.yaml` | `CertificateRequestPolicy` + RBAC for auto-approval |
| `istio-infra/istiod-cert.yaml` | cert-manager Certificate for istiod TLS cert |
| `istio-infra/ztunnel-cert-unused.yaml` | **Not applied** — documents why (ztunnel has no static-Certificate mechanism) and how its real identity is fetched dynamically |
| `istio-infra/ztunnel-values.yaml` | Helm values for `ztunnel` — sets `TRUST_DOMAIN=athenz.io` |
| `istio-infra/ztunnel-serviceaccount-patch.json` | `kubectl patch` for `ztunnel`'s `serviceAccountName` (chart hardcodes it, no Helm value controls it) |
| `istio-infra/istio-csr-cert.yaml` | cert-manager Certificate for istio-csr serving cert |
| `istio-infra/curl.yaml` | Namespace, SA (`app.frontend.curl`), and Deployment for curl workload |
| `istio-infra/httpbin.yaml` | Namespace, SA (`app.backend.httpbin`), Deployment, Service, and AuthorizationPolicy for httpbin |
| `istio-infra/waypoint.yaml` | Platform-provisioned (BYO) waypoint bundle: SA `app.backend.waypoint`, hyphenated Service, rendered Deployment, Gateway with `spec.addresses` — see [istio-ambient-waypoint-setup.md](istio-ambient-waypoint-setup.md) |
| `istio-infra/terraform/control-plane/main.tf` | Registers control-plane services in `example.k8s` domain |
| `istio-infra/terraform/curl/main.tf` | Registers `curl` service in `app.frontend` domain |
| `istio-infra/terraform/httpbin/main.tf` | Registers `httpbin` and `waypoint` services in `app.backend` domain |
| `istio-csr/pkg/tls/tls.go` | `loadFromSecret()` — load serving cert from pre-provisioned Secret |
| `istio-csr/cmd/app/options/options.go` | `--serving-certificate-secret-name/namespace` flags |
| `istio-csr/cmd/app/app.go` | Wires k8s client into tls.Provider |
| `istio-csr/pkg/certmanager/certmanager.go` | `HasIssuerConfig()` mutex fix (Lock → RLock) |
| `athenz-issuer/controller/signer.go` | Calls `ResolveDomainService`; `getServiceAccountTokenFromAPIServer` returns the fetched `ServiceAccount`; sets `X509CertInstanceId` from `sa.UID` (Patch #5) |
| `athenz-issuer/internal/util.go` | `ResolveDomainService` — derives domain/service by splitting the SA name on the last dot |
| `athenz/core/zts/src/main/rdl/Instance.rdli` | Adds `x509CertInstanceId` field to `InstanceRegisterInformation` (Patch #5) |
| `athenz/servers/zts/.../ZTSImpl.java` | Falls back to caller-supplied `x509CertInstanceId` when the CSR has none (Patch #5) |
| `athenz/servers/zts/.../X509ServiceCertRequest.java` | Skip CN check for empty Subject (Patch #1); delegates SPIFFE URI validation |
| `athenz/libs/java/server_common/.../SpiffeUriTrustDomain.java` | Domain-qualified SPIFFE URI validation — used by all ambient SVIDs, unchanged |
| `athenz/servers/zts/.../X509CertRequest.java` | Accept empty Subject O field (Patch #3) |
| `athenz/libs/java/instance_provider/.../InstanceUtils.java` | `ZTS_INSTANCE_ID` fallback now reads a caller-supplied value (Patch #5) |
| `athenz/libs/java/instance_provider/.../InstanceK8SProvider.java` | SPIFFE-only DNS SAN skip (Patch #2) |
