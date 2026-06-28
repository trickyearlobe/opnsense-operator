# opnsense-operator

A Kubernetes controller that programs an **OPNsense** firewall's **HAProxy** (and,
optionally, **Unbound DNS** and **ACME** certificates) from annotations on
Services — making OPNsense act as the external load balancer / edge for a
cluster, driven from inside the cluster via the OPNsense REST API.

This is the *in-cluster controller → OPNsense API* direction: the cluster holds
an OPNsense API key and pushes config outward. The firewall needs no inbound
access to the Kubernetes API. Config lives in your manifests (GitOps-friendly),
not in `config.xml`.

> **Status: MVP, structured as an operator.** Work is split behind a **provider
> seam** (`internal/provider`) so new OPNsense capabilities plug in without
> touching the reconcile core. Today's providers: **HAProxy** (backend/servers +
> optional host ACL → frontend binding), **DNS** (Unbound host override), and
> **ACME** (issue/renew of a pre-existing cert). A future cluster-level **BGP**
> module (os-frr ↔ Cilium) is the next natural plug-in.
>
> The HAProxy frontend/ACL binding is marked **EXPERIMENTAL** in code: the
> os-haproxy field names can vary by plugin version, so validate against your
> firewall (it's isolated to `pkg/opnsense/haproxy_routing.go`).

## How it works

```
        watch Services (+ Nodes)
                 │
                 ▼                              OPNsense REST API
  ┌──────────────────────────┐   reconcile    ┌────────────────────────┐
  │ Service annotated with    │ ─────────────▶ │ HAProxy servers+backend│
  │ opnsense-operator.k8s.local/* │            │ Unbound host override  │
  │   expose / hostname / ... │                │ ACME issue/renew       │
  └──────────────────────────┘                └──────────┬─────────────┘
                                            debounced reconfigure/reload
```

For each exposed Service the controller:

1. **Resolves stable upstreams.** By default it reads the Service's own
   LoadBalancer VIP from `.status.loadBalancer.ingress` (Cilium LB-IPAM /
   MetalLB / kube-vip). Or every Ready node's internal IP + the Service
   `NodePort`, or a fixed VIP you supply. It never targets churning pod IPs —
   kube-proxy or the in-cluster LB owns the last hop.
2. **Upserts one HAProxy `server` per upstream** and a **`backend`** linking them.
3. **Prunes** servers it previously created for that Service that are no longer
   wanted (node removed, scaled down) — scoped by an ownership marker in each
   object's description, so hand-made GUI objects are never touched.
4. Optionally maintains an **Unbound host override** and triggers **ACME**
   issuance/renewal.
5. **Debounces** the haproxy/unbound reload so a burst of changes reloads once.

A finalizer guarantees firewall objects are removed when the Service is deleted
or opts out. A periodic resync heals out-of-band drift.

## Annotations

| Annotation | Default | Meaning |
|---|---|---|
| `opnsense-operator.k8s.local/expose` | – | `"true"` to manage this Service |
| `opnsense-operator.k8s.local/backend-mode` | `http` | `http` or `tcp` (Kafka etc. want `tcp`) |
| `opnsense-operator.k8s.local/hostname` | – | Host for the ACL / DNS / ACME |
| `opnsense-operator.k8s.local/frontend` | – | Existing public frontend to attach a host ACL to (omit = backend-only) |
| `opnsense-operator.k8s.local/upstream-strategy` | `loadbalancer` | `loadbalancer`, `nodeport`, or `vip` |
| `opnsense-operator.k8s.local/upstream-address` | – | Target address when strategy is `vip` |
| `opnsense-operator.k8s.local/upstream-port` | first Service port | Port for `loadbalancer`/`vip` |
| `opnsense-operator.k8s.local/dns` | `false` | Maintain an Unbound host override |
| `opnsense-operator.k8s.local/acme` | `false` | Issue/renew the cert whose description == hostname |

See [`deploy/example-service.yaml`](deploy/example-service.yaml).

## Prerequisites

- An OPNsense firewall with the **os-haproxy** plugin installed and a public
  frontend already configured (e.g. `https-443`). The controller manages
  backends + servers, and — if you set `opnsense-operator.k8s.local/frontend` — a host ACL +
  action attached to that frontend. Creating the frontend itself is a one-time
  manual step.
- An OPNsense **API key/secret** (System → Access → Users → API keys) for a user
  scoped to the HAProxy (and, if used, Unbound/ACME) endpoints.
- For `dns`/`acme`: the **os-acme-client** plugin and a pre-created certificate
  object whose *description* equals the Service's `hostname`.

## Configuration (env)

| Var | Required | Default | |
|---|---|---|---|
| `OPNSENSE_URL` | ✓ | – | e.g. `https://opnsense.lan` |
| `OPNSENSE_KEY` | ✓ | – | API key |
| `OPNSENSE_SECRET` | ✓ | – | API secret |
| `OPNSENSE_INSECURE` | | `false` | skip TLS verify (self-signed certs) |
| `DNS_DOMAIN` | | `lan` | domain for bare-label hostnames |
| `RECONFIGURE_DEBOUNCE` | | `2s` | reload coalescing window |
| `RESYNC_PERIOD` | | `10m` | periodic drift-healing resync |

## Install

### Helm

```sh
# API credentials live in a Secret (keys: api-key, api-secret).
kubectl create namespace opnsense-system
kubectl -n opnsense-system create secret generic opnsense-api \
  --from-literal=api-key=YOUR_KEY --from-literal=api-secret=YOUR_SECRET

helm upgrade --install opnsense-operator charts/opnsense-operator \
  --namespace opnsense-system \
  --set opnsense.url=https://opnsense.lan \
  --set opnsense.insecure=true \
  --set opnsense.existingSecret=opnsense-api
```

Released charts are also pushed to GHCR as OCI artifacts:

```sh
helm upgrade --install opnsense-operator \
  oci://ghcr.io/trickyearlobe/charts/opnsense-operator --version X.Y.Z ...
```

Key values: `opnsense.url`, `opnsense.insecure`, `opnsense.existingSecret`
(or `opnsense.apiKey`/`apiSecret`), `config.dnsDomain`, `serviceMonitor.enabled`,
`replicaCount`, `resources`. See [`values.yaml`](charts/opnsense-operator/values.yaml).

### Argo CD (GitOps)

Point an Application at the in-repo chart — see
[`deploy/argocd-application.yaml`](deploy/argocd-application.yaml). Pin
`targetRevision` to a released tag and reference an existing credentials Secret
via `opnsense.existingSecret` (don't inline secrets in the Application).

### Run locally

```sh
export OPNSENSE_URL=https://opnsense.lan OPNSENSE_KEY=... OPNSENSE_SECRET=... OPNSENSE_INSECURE=true
make run
```

## Releasing

Releases are tag-driven. Bump a semver tag and push it — that's the only step:

```sh
make bump-patch-push   # vX.Y.Z+1
make bump-minor-push   # vX.Y+1.0
make bump-major-push   # vX+1.0.0
```

Each refuses a dirty tree, computes the next tag from the latest `v*` tag
(`hack/bump-version.sh`), and pushes it to `origin`. Pushing a `v*` tag triggers
[`.github/workflows/release.yaml`](.github/workflows/release.yaml), which:

- builds a **multi-arch** (amd64/arm64) image and pushes it to
  `ghcr.io/trickyearlobe/opnsense-operator` with build **provenance + SBOM**;
- **signs** the image keylessly with **cosign** (OIDC) and attaches an SPDX SBOM
  attestation;
- **scans** the image with Trivy (SARIF → GitHub Security);
- packages the Helm chart (version/appVersion = tag) and **pushes it to GHCR as
  an OCI artifact**;
- cuts a **GitHub Release** with auto notes, cross-compiled binaries, the chart
  `.tgz`, and the SBOM.

## Security / supply chain

CI ([`ci.yaml`](.github/workflows/ci.yaml)) runs on every PR/push:

| Check | Tool |
|---|---|
| SAST | gosec (SARIF) |
| Known vulns in deps | govulncheck |
| Deps / IaC misconfig / secrets | Trivy fs (SARIF) |
| Lint | golangci-lint |
| Dockerfile lint | hadolint |
| Helm | `helm lint` + `template` |
| Dependency diff (PRs) | dependency-review |
| Deep semantic analysis | CodeQL ([`codeql.yaml`](.github/workflows/codeql.yaml)) |

Run the security tools locally with `make vuln`, `make sec`, `make scan`,
`make lint`. Dependencies (gomod, github-actions, docker) are kept current by
[Dependabot](.github/dependabot.yml).

> Hardening note: the workflows pin actions to release tags for readability.
> For maximum supply-chain rigor, pin to commit SHAs (Dependabot's
> `github-actions` updates can manage the bumps).

## Develop

```sh
make test   # unit tests (mock OPNsense API + naming/parsing)
make vet
make build
```

Layout:

```
cmd/manager           main / wiring (builds providers, starts the manager)
internal/annotations  the Service annotation contract
internal/config       env configuration
internal/controller   thin reconcile core: Service → finalizer → fan out to providers
internal/provider     the module seam: Provider interface + Deps + Reconfigurer
                      ├─ haproxy.go / haproxy_targets.go  backend/servers, ACL→frontend, target resolution
                      ├─ dns.go                           Unbound host override
                      └─ acme.go                          certificate issue/renew
pkg/opnsense          OPNsense REST client (client, haproxy, haproxy_routing, acme, ddns)
charts/opnsense-operator  Helm chart (the install path)
deploy                Argo CD Application + example Service/Secret
.github/workflows     ci, release, codeql
```

### Adding a provider

Implement `provider.Provider` (`Name`, `Apply`, `Cleanup`), add any OPNsense API
calls under `pkg/opnsense`, and register it in `provider.Default`. `Apply` runs
in registration order; `Cleanup` runs in reverse. A cluster-level module (e.g.
BGP) would add a sibling interface + its own watch, reusing the same client and
`Reconfigurer`.

## Limitations / roadmap

- **Frontend/ACL binding is EXPERIMENTAL.** It creates a host-matching ACL + a
  `use_backend` action and attaches it to a named existing frontend, but the
  os-haproxy field names vary by version — validate against your firewall. It
  does **not** create the frontend itself (bind point is yours to set up once).
- **ACME/DNS are minimal.** ACME triggers issue/renew of a pre-existing cert; it
  doesn't create the cert object. DNS writes an Unbound host override when a
  hostname and an address (the LB VIP, or `upstream-address`) are available.
- **No CRD yet.** Annotations only. An `OPNsenseRoute` CRD with a status
  subresource would give validation and `kubectl get` visibility.
- **BGP module (planned).** A cluster-level provider pairing OPNsense **os-frr**
  with Cilium's BGP control plane — advertise LB VIPs / pod CIDRs over BGP (L3)
  instead of/alongside HAProxy (L7). The provider seam is in place for it.
- **nginx (deferred).** os-nginx largely duplicates HAProxy here; add only if a
  concrete need (e.g. ModSecurity WAF) appears.
- **Health checks / TLS mode / sticky sessions** aren't exposed as annotations yet.
- Single OPNsense target; no HA-pair fan-out.

Extension points are isolated: add API calls in `pkg/opnsense`, a new `Provider`
in `internal/provider`, new knobs in `internal/annotations`.
