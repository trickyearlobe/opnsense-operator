# Edge provisioner design

Goal: drive the **entire** OPNsense edge path for a Kubernetes Service from
annotations — backend, frontend (port + TLS), routing, certificate, DNS, and the
WAN firewall rule — so exposing a service is a one-annotation operation.

This extends the provider seam (`internal/provider`). Each concern is a module;
the controller fans out to them. All modules follow one rule learned the hard
way: **take human-friendly names in annotations, resolve to OPNsense internal
ids (uuid/refid) under the hood.**

## Annotation schema

| Annotation | Values | Meaning |
|---|---|---|
| `…/expose` | `true` | manage this Service |
| `…/backend-mode` | `http`\|`tcp` | HAProxy backend mode |
| `…/hostname` | FQDN | the public host (ACL / cert / DNS) |
| `…/frontend-mode` | `dedicated`\|`shared` | own frontend per service, or attach to a shared one |
| `…/listen-port` | port | bind port for a `dedicated` frontend |
| `…/frontend` | name | the shared frontend to attach to (`shared` mode) |
| `…/tls-cert` | CN/name | certificate to bind, by name (e.g. `*.trickyearlobe.com`) |
| `…/acme` | `true` | ensure the cert exists; issue/renew via os-acme-client |
| `…/dns` | `true` | publish a DNS record for `hostname` |
| `…/dns-backend` | `ddclient`\|`unbound`\|`dnsmasq` | DNS mechanism |
| `…/expose-wan` | `true` | open the WAN firewall for `listen-port` (within allowed range) |

`dedicated` → operator creates a frontend on `listen-port` with `tls-cert`,
default backend = the service (matches the per-port pattern in this homelab).
`shared` → operator adds a host-matching ACL + `use_backend` action to the named
frontend (SNI/host routing, one port many hosts).

## OPNsense API facts (validated against a live box)

- **Cert name → refid:** HAProxy references certs by **refid**, not the trust
  UUID. Resolve: `POST /api/trust/cert/search` (match `commonname`/`descr`) →
  `GET /api/trust/cert/get/{uuid}` → `.cert.refid`.
- **Frontend create:** `POST /api/haproxy/settings/addFrontend` with a *minimal*
  field set (name, description, bind `0.0.0.0:PORT`, mode `http`,
  defaultBackend, ssl_enabled `1`, ssl_certificates=refid,
  ssl_default_certificate=refid, enabled `1`). Cloning the full object fails on
  empty reference fields; drop the inherited `id`.
- **Apply:** `POST /api/haproxy/service/reconfigure`.
- **ACME:** certs are separate objects under `/api/acmeclient/certificates/*`
  (own UUIDs); issue via `/api/acmeclient/certificates/issue/{uuid}`.
- **Firewall:** `/api/firewall/filter/{searchRule,addRule,delRule,apply}` (the
  Automation > Filter API). Rule fields confirmed via `getRule`.
  - ⚠️ **Two rule APIs to support.** OPNsense is migrating the core ruleset to an
    API-manageable form ("rules(new)"), which is a *different* endpoint from the
    `os-firewall` Automation/Filter API above. The two have different field sets,
    ordering/grouping semantics, and apply calls. The firewall provider must
    therefore put rule CRUD behind a seam (e.g. a `FirewallRules` interface in
    `pkg/opnsense` with `automation` and `core`/`rules-new` implementations),
    selected by config (`FIREWALL_RULE_API=automation|rules-new`) and/or live
    capability detection. **Validate the new endpoint's paths + fields against the
    box before wiring** — don't assume the Automation field names carry over.

## API user privileges

| Module | Privilege | Status |
|---|---|---|
| HAProxy | HAProxy | ✅ granted |
| Cert resolve | System: Certificate Manager | ✅ granted |
| ACME | os-acme-client | ✅ granted |
| WAN rule | Firewall: Automation: Filter | ✅ granted |
| DNS | Unbound / os-ddclient | ⏳ pending |

## Security gating

Auto-opening WAN ports from annotations is powerful. Guards:

- WAN rule only when `expose-wan: true`.
- `listen-port` must fall in an operator-configured **allowed range**
  (`WAN_ALLOWED_PORTS`, e.g. `9000-9099`) — a stray annotation can't open 22/443.
- WAN interface is operator config (`WAN_INTERFACE`), never annotation-driven.

## Credentials

The OPNsense API key/secret are read today from the environment
(`OPNSENSE_KEY` / `OPNSENSE_SECRET`), sourced from a Kubernetes Secret mounted as
env (see `deploy/`). For this homelab the Secret is materialised from Vault at
**`be/dev/opnsense-operator/*`** (e.g. ExternalSecrets / vault-agent → the
`opnsense-api` Secret with keys `api-key`/`api-secret`).

**Future feature — live credential reload (no restart).** Read the creds from the
Secret via the controller-runtime client instead of process env, and watch that
Secret so rotation is picked up without a pod restart. Sketch:

- `opnsense.Client` already holds key/secret at construction. Refactor it to pull
  creds through an indirection — `Options.Credentials func() (key, secret string)`
  reading an `atomic.Pointer` to the current pair — so the value is resolved per
  request, not frozen at startup.
- Feed that holder from a Secret informer (the manager's cached client gives a
  watch-backed local cache): on `Update` to the `opnsense-api` Secret, atomically
  swap in the new pair. A reconcile-time re-read of the cached Secret is the
  simpler first cut; an explicit watch is the zero-latency version.
- Reliability: this is a well-trodden pattern (the cache is authoritative and
  consistent); the only care points are (a) tolerating a transiently-empty/secret
  during rotation by keeping the last-good pair, and (b) not logging the value.
  Gate behind a flag (`CREDS_FROM_SECRET=true` + `OPNSENSE_SECRET_NAME`) and keep
  env as the fallback. Adopt once it proves reliable in dev.

## Build order (each: client capability → validate live → wire provider)

1. ✅ Cert resolver + Frontend CRUD client (`pkg/opnsense`), live read-only test.
2. ✅ HAProxy provider: `dedicated` frontend create/own (`frontend-mode: dedicated`
   → bind `listen-port`, optional `tls-cert` refid offload, default backend = the
   service). Unit-tested; live provider-path validation pending operator approval.
3. Firewall provider: gated WAN rule — behind a `FirewallRules` seam supporting
   BOTH the os-firewall Automation API and the new core "rules(new)" API.
4. ACME provider: ensure/issue cert by name.
5. DNS provider: pluggable backend (ddclient first), once DNS privilege lands.
6. `shared` frontend mode via the host-ACL binding (already prototyped).
