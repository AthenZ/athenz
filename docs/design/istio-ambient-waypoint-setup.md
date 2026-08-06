# Istio Ambient Mode: Waypoint Setup with Dotted ServiceAccounts

Companion to [istio-ambient-cert-flow.md](istio-ambient-cert-flow.md). This document
describes the platform-provisioned ("bring your own") waypoint deployment pattern that
gives waypoints a **dotted ServiceAccount** (`{athenz-domain}.waypoint`) and therefore a
standard, domain-qualified Athenz identity:

```
SA:   app.backend.waypoint
SVID: spiffe://athenz.io/ns/app-backend/sa/app.backend.waypoint
```

With a dotted SA, the waypoint is identical to any workload (cert-flow doc, Section 3):
athenz-issuer derives domain and service by splitting the SA name on the last dot, ZTS
validates the SPIFFE URI with the standard `SpiffeUriTrustDomain` validator, the subject
validator cryptographically binds the domain to the SA name attested in the token, and the
existing 3-segment launch policy (`{domain}:waypoint:{cluster-project}`) authorizes it. No
`athenz.io/domain` annotation, no dot-free SPIFFE validator, and no
ambient-specific assertions are needed — and the multi-tenant concerns that dot-free
identities carried (annotation-based domain spoofing, cross-division URI ambiguity) do not
arise, because the domain is inside the identity and bound by attestation.

The trade-off: Istio's managed waypoint deployment cannot produce this setup, so the
platform provisions the waypoint resources itself. This document captures why, the exact
resource set, and the verification evidence.

## Why the managed (istioctl) path cannot do this

All findings verified on Istio 1.29.2:

1. **Dotted Gateway names break the managed Service.** The gateway deployment controller
   derives the ServiceAccount, Deployment, *and Service* names from the Gateway name.
   SA and Deployment names are DNS-1123 subdomains (dots allowed), but Service names are
   DNS-1035 (no dots). `istioctl waypoint apply --name app.backend.waypoint` therefore
   creates the SA and Deployment — and the pod even obtains its SVID — but the
   Service fails validation forever:

   ```
   Service "app.backend.waypoint" is invalid: metadata.name: Invalid value:
   "app.backend.waypoint": a DNS-1035 label must consist of lower case alphanumeric
   characters or '-' ...
   ```

   The Gateway stays `Programmed: False` (`AddressNotUsable`), it never gets a VIP, and
   ztunnel can never route traffic to it. (`istioctl waypoint generate` emits the broken
   Gateway without any warning.)
2. **`spec.addresses` disables managed provisioning entirely.** Creating the Gateway with
   `spec.addresses` preset puts it in manual-deployment mode: the controller creates no
   SA, no Deployment, and no Service. Whoever sets the address owns the workload.
3. **The `waypoint` injection template is controller-only.** A hand-written Deployment
   using `inject.istio.io/templates: waypoint` with `image: auto` is rejected by the
   injection webhook (`can't evaluate field ServiceAccount in type
   *inject.SidecarTemplateData`) — the template consumes fields only the deployment
   controller supplies. The BYO Deployment must therefore carry the **fully rendered
   proxy spec**, which is version-pinned to the Istio release.

## Required setup (per tenant namespace)

The platform automation provisions five resources. Example values: Athenz domain
`app.backend`, namespace `app-backend`.

**1. ServiceAccount** — the identity carrier; name encodes the domain:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app.backend.waypoint
  namespace: app-backend
```

**2. Service** — DNS-1035 (hyphenated) name, selecting the waypoint pods:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: app-backend-waypoint
  namespace: app-backend
spec:
  ports:
  - {name: status-port, port: 15021, protocol: TCP, targetPort: 15021, appProtocol: tcp}
  - {name: mesh, port: 15008, protocol: TCP, targetPort: 15008, appProtocol: hbone}
  selector:
    gateway.networking.k8s.io/gateway-name: app.backend.waypoint
```

**3. Deployment** — the rendered waypoint proxy spec. Obtain the template by creating a
throwaway *managed* waypoint on a cluster running the target Istio version
(`istioctl waypoint apply -n <ns> --name tmp`), exporting its Deployment
(`kubectl get deploy tmp -o yaml`), stripping server-side metadata
(`ownerReferences`, `uid`, `resourceVersion`, `status`, ...), and parameterizing:

- `metadata.name`: hyphenated (e.g. `app-backend-waypoint`) — avoids `istioctl` tooling
  issues with dotted names
- `spec.template.spec.serviceAccountName`: `app.backend.waypoint`
- pod label `gateway.networking.k8s.io/gateway-name: app.backend.waypoint` (matches the
  Service selector and binds the proxy to its Gateway)
- pod label `istio.io/dataplane-mode: none` (waypoint pods are not ztunnel-captured)
- container image `docker.io/istio/proxyv2:<istio-version>-distroless` — **version-pinned;
  the platform re-renders this template on every Istio upgrade**

**4. Gateway** — with `spec.addresses` preset, so the controller never attempts (and
never fights over) provisioning:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: app.backend.waypoint
  namespace: app-backend
spec:
  gatewayClassName: istio-waypoint
  addresses:
  - type: Hostname
    value: app-backend-waypoint.app-backend.svc.cluster.local
  listeners:
  - name: mesh
    port: 15008
    protocol: HBONE
```

The Gateway reaches `Programmed: True` once the Service has ready endpoints.

**5. Waypoint binding labels** — on the namespace and/or individual Services:

```
istio.io/use-waypoint: app.backend.waypoint
```

(Label *values* allow dots, so the dotted Gateway name is referenceable.)

### Athenz-side setup

Standard service registration, identical to any workload service — the existing
`k8s-provider` Terraform module with `services = [..., "waypoint"]`:

- Athenz service `waypoint` in the tenant domain (`app.backend.waypoint` principal)
- `k8s-launch-authorizer-waypoint` role/policy: `grant launch ... on
  app.backend:waypoint:{cluster-project}`

### ZTS prerequisites

Patches 1-3 from the cert-flow doc (empty-Subject CN skip, SPIFFE-only DNS SAN bypass,
empty `O=` acceptance) — these address properties of the waypoint's CSR that are
independent of the SA form. **No dot-free SPIFFE validator is required.**

## Verification (validated live on Istio 1.29.2)

```bash
kubectl get gateway -n app-backend            # Programmed=True, ADDRESS = Service ClusterIP
istioctl ztunnel-config service | grep <svc>  # WAYPOINT column shows the hyphenated Service
# traffic + L7 policy (Service-attached AuthorizationPolicy moves with the binding):
curl http://<svc>.<ns>/get                    # 200
curl -X POST http://<svc>.<ns>/post           # 403 when a GET-only policy is attached
# the waypoint's live certificate:
kubectl exec -n app-backend deploy/app-backend-waypoint -- pilot-agent request GET certs
# -> URI SAN: spiffe://athenz.io/ns/app-backend/sa/app.backend.waypoint
```

Observed end-to-end on the validation cluster: `Programmed: True`, ztunnel bound the
service to the BYO waypoint, GET returned 200 and POST 403 through it (L7
`AuthorizationPolicy` enforced at the waypoint), the SVID carried the domain-qualified URI, and ZTS
logged the issuance for principal `{domain}.waypoint` through the standard dotted-SA
validation path.

## Traffic flow

```
app pod ──plaintext──► ztunnel ──HBONE, src workload SVID──► waypoint [L7 policy] ──HBONE, waypoint SVID──► ztunnel (dst node) ──plaintext──► backend pod
```

Egress waypoints use the identical resource pattern — the Gateway/waypoint is attached to
a `ServiceEntry` (labeled `istio.io/use-waypoint`) instead of in-cluster Services, and the
outbound connection goes directly from the waypoint to the external destination.

## Caveats and open items

- **Version coupling:** the rendered Deployment spec is tied to the Istio release. The
  platform must regenerate the template (and roll waypoint Deployments) as part of every
  Istio upgrade — this is the deliberate cost of owning the workload.
- **`istioctl` tooling breaks on dotted names:** commands that address pods/deployments
  (`istioctl proxy-config ...`) mis-parse `name.namespace` at the first dot. Workaround:
  `kubectl exec ... -- pilot-agent request GET <endpoint>` against the Envoy admin API.
  Naming the Deployment/Service with hyphens (only the Gateway and SA are dotted) avoids
  most of it.
- **Upstream durability:** the pattern lives in the gap between Gateway names (DNS-1123)
  and Service names (DNS-1035). An upstream change that validates Gateway names would
  break it; an upstream change that sanitizes the generated Service name would make the
  *managed* path work with dotted names and retire this document. Worth filing the latter
  as a feature request.
- **Ingress gateways:** the same DNS-1035 constraint applies to the managed ingress path
  (`<gateway>-<class>` naming). The BYO analog should work identically but is untested;
  for ingress, a Helm/manually-deployed gateway with a dotted `serviceAccountName` is the
  established alternative (see cert-flow doc, Section 6).
