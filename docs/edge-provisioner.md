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

## Build order (each: client capability → validate live → wire provider)

1. ✅ Cert resolver + Frontend CRUD client (`pkg/opnsense`), live read-only test.
2. HAProxy provider: `dedicated` frontend create/own + reuse/own backend.
3. Firewall provider: gated WAN rule.
4. ACME provider: ensure/issue cert by name.
5. DNS provider: pluggable backend (ddclient first), once DNS privilege lands.
6. `shared` frontend mode via the host-ACL binding (already prototyped).
