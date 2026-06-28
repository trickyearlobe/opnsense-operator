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
- **Host routing (shared frontend):** validated live via `getAcl`/`getAction`/
  `getFrontend`. An HTTP Host ACL uses **`expression: "hdr"`** ("HTTP Host Header
  matches") with the value in a field **also named `hdr`** — there is NO
  `host_matches` field (the earlier experimental guess was wrong). The action uses
  `type: "use_backend"` (a valid `type` option), `testType: if`, `operator: and`,
  `linkedAcls` (csv of ACL uuids), `use_backend` (backend uuid). A frontend's
  `linkedActions` is a `uuid -> {value,selected}` map; attach by POSTing the csv
  of selected uuids back to `setFrontend`. (SNI matching, for TCP passthrough, is
  a separate `ssl_sni*` expression — future.)
- **ACME:** certs are separate objects under `/api/acmeclient/certificates/*`
  (own UUIDs); issue via `/api/acmeclient/certificates/issue/{uuid}`. **Validated
  live:** `search` rows key on `name` (the domain/CN, e.g. `zong.trickyearlobe.com`)
  and `altNames` (comma-separated SANs) — NOT `description`, which is often empty
  or a human label. `statusCode` is `"200"` once a sign has succeeded; `certRefId`
  is the HAProxy refid of the issued cert. So resolve a cert by **name (CN), else
  altNames** (`ACME.FindCertByName`), and only force `issue` when not yet signed —
  OPNsense's auto-renewal cron owns ongoing renewal, so re-issuing every resync
  would needlessly hit the ACME provider / its rate limits.
- **Firewall (Automation/Filter):** `/api/firewall/filter/{searchRule,getRule,
  addRule,setRule,delRule,apply}` (os-firewall plugin). **Field set validated
  live via `getRule`** (2026-06-28): `addRule` takes a `{"rule": …}` body where
  select fields are the bare option key as a string and booleans are `"0"`/`"1"`.
  A WAN pass rule = `enabled:1, action:pass, quick:1, interface:wan, direction:in,
  ipprotocol:inet, protocol:TCP, source_net:any, destination_net:(self),
  destination_port:<port>, description:<managed marker>`. The **WAN interface key
  is `wan`** (confirmed against the box's interface list). `searchRule` rows carry
  `uuid` + `description`, so we match our own rules by exact description (the
  managed marker). `apply` returns `{"status":"OK\n…"}` (uppercase, unlike
  haproxy's `ok`). Implemented in `pkg/opnsense/firewall.go` (`automationFilter`).
  - ⚠️ **Two rule APIs — seam in place, only `automation` wired.** OPNsense is
    migrating the core ruleset to an API-manageable form ("rules(new)"), a
    *different* endpoint/field set/apply from the Automation API. Rule CRUD sits
    behind the `FirewallRules` interface (`pkg/opnsense/firewall.go`) with an
    `automation` impl and a `rules-new` placeholder, selected by config
    (`FIREWALL_RULE_API=automation|rules-new`, default `automation`). **The
    `rules-new` endpoints are absent on this box's firmware** (every candidate
    `/api/firewall/*` path 404s as of 2026-06-28), so per the validate-before-wiring
    rule the placeholder fails fast and is NOT implemented on guesswork. Probe the
    real paths + fields live, then fill in `rulesNew`.

## API user privileges

| Module | Privilege | Status |
|---|---|---|
| HAProxy | HAProxy | ✅ granted |
| Cert resolve | System: Certificate Manager | ✅ granted |
| ACME | os-acme-client | ✅ granted |
| WAN rule | Firewall: Automation: Filter | ✅ granted |
| DNS — Unbound | Services: Unbound (host overrides) | ✅ granted |
| DNS — dnsmasq | Services: Dnsmasq DNS | ✅ granted |
| DNS — ddclient | os-ddclient | ✅ granted (API root is **`/api/dyndns/*`**, not `/api/ddclient/*`) |

## Security gating

Auto-opening WAN ports from annotations is powerful. Guards:

- WAN rule only when `expose-wan: true`.
- `listen-port` must fall in an operator-configured **allowed range**
  (`WAN_ALLOWED_PORTS`, e.g. `9000-9099`) — a stray annotation can't open 22/443.
  **Empty range denies every port** (fail-closed): WAN exposure is opt-in at the
  operator level, so the feature is inert until a range is configured.
- WAN interface is operator config (`WAN_INTERFACE`, default `wan`), never
  annotation-driven.
- Rule is destination `(self)` on exactly `listen-port` — opens only the port the
  dedicated frontend listens on, nothing wider.
- Implemented in `internal/provider/firewall.go`; the provider runs **after**
  HAProxy on apply (frontend exists before the port opens) and **before** it on
  cleanup (port closes before the frontend is removed).

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
3. ✅ Firewall provider: gated WAN rule behind the `FirewallRules` seam.
   `automation` impl validated live (field set via `getRule`; read-only client
   test green against the box). `rules-new` is a fail-fast placeholder until its
   endpoints appear on the firmware. Live mutating provider test gated behind
   `LIVE_WAN_RULE=1` (needs per-session box-mutation authorization).
4. ✅ ACME provider: resolve cert by name (CN/altNames, via `tls-cert` else
   `hostname`); issue only when unsigned, else leave renewal to OPNsense.
   Name→cert resolution validated live (read-only); issuance not triggered (would
   hit Let's Encrypt; all live certs already signed).
5. ✅ `shared` frontend mode via the host-ACL binding. Corrected the host-match
   field to `expression: "hdr"` + `hdr` value (was a wrong `host_matches` guess);
   action/frontend-attach fields confirmed live. Unit-tested; live mutating test
   gated behind `LIVE_SHARED_ROUTING=1`.
6. DNS provider: pluggable backend (ddclient first). **Now unblocked** — privileges
   granted; API roots confirmed: ddclient = `/api/dyndns/*`, unbound =
   `/api/unbound/*`, dnsmasq = `/api/dnsmasq/*`.
