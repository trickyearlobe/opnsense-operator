package provider

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/trickyearlobe/opnsense-operator/internal/annotations"
	"github.com/trickyearlobe/opnsense-operator/internal/config"
	"github.com/trickyearlobe/opnsense-operator/pkg/opnsense"
)

// HAProxy programs backend + servers for a Service, and (optionally) a host ACL
// + use_backend action attached to an existing public frontend.
type HAProxy struct {
	k8s          client.Client
	opn          *opnsense.Client
	cfg          *config.Config
	reconfigurer *Reconfigurer
}

// NewHAProxy builds the HAProxy provider.
func NewHAProxy(d Deps) *HAProxy {
	return &HAProxy{k8s: d.K8s, opn: d.OPN, cfg: d.Cfg, reconfigurer: d.Reconfigurer}
}

func (p *HAProxy) Name() string { return "haproxy" }

// target is a single resolved upstream (address + port).
type target struct {
	Address string
	Port    int32
}

func (p *HAProxy) Apply(ctx context.Context, svc *corev1.Service) error {
	l := log.FromContext(ctx)
	hap := p.opn.HAProxy()

	targets, err := p.upstreamTargets(ctx, svc)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		l.Info("no upstream targets resolved yet; requeue", "service", svc.Name)
		return nil
	}

	mode := annotations.Get(svc, annotations.Mode, "http")
	desc := managedDescription(svc)

	// 1. Upsert one server per target.
	desiredServers := map[string]bool{}
	var serverUUIDs []string
	for _, t := range targets {
		name := serverName(svc, t)
		desiredServers[name] = true
		uuid, err := hap.UpsertServer(ctx, opnsense.Server{
			Name:        name,
			Address:     t.Address,
			Port:        strconv.Itoa(int(t.Port)),
			Mode:        "active",
			Type:        "static",
			Enabled:     "1",
			Description: desc,
		})
		if err != nil {
			return fmt.Errorf("upsert server %s: %w", name, err)
		}
		serverUUIDs = append(serverUUIDs, uuid)
	}

	// 2. Prune servers we previously created for THIS service but no longer want.
	if err := p.pruneServers(ctx, svc, desiredServers); err != nil {
		return err
	}

	// 3. Upsert the backend linking those servers.
	sort.Strings(serverUUIDs)
	backendUUID, err := hap.UpsertBackend(ctx, opnsense.Backend{
		Name:          backendName(svc),
		Mode:          mode,
		Enabled:       "1",
		LinkedServers: strings.Join(serverUUIDs, ","),
		Description:   desc,
	})
	if err != nil {
		return fmt.Errorf("upsert backend: %w", err)
	}

	// 4. Optional L7 host routing: ACL + action attached to a public frontend.
	if err := p.applyRouting(ctx, svc, backendUUID); err != nil {
		return fmt.Errorf("apply routing: %w", err)
	}

	p.reconfigurer.TriggerHAProxy()
	l.Info("reconciled haproxy", "service", svc.Name, "targets", len(targets))
	return nil
}

func (p *HAProxy) Cleanup(ctx context.Context, svc *corev1.Service) error {
	hap := p.opn.HAProxy()

	// Detach + delete routing first so nothing references the backend.
	if err := p.cleanupRouting(ctx, svc); err != nil {
		return err
	}

	// Delete the backend, then prune all of this service's servers.
	if uuid, err := hap.FindBackend(ctx, backendName(svc)); err != nil {
		return err
	} else if uuid != "" {
		if err := hap.DeleteBackend(ctx, uuid); err != nil {
			return err
		}
	}
	if err := p.pruneServers(ctx, svc, map[string]bool{}); err != nil {
		return err
	}

	p.reconfigurer.TriggerHAProxy()
	return nil
}

// --- L7 routing ----------------------------------------------------------

// applyRouting attaches the backend to a public frontend, dispatching on
// frontend-mode:
//   - "dedicated": the operator owns a frontend on listen-port (with optional
//     TLS offload) whose default backend is this service.
//   - "shared" (or a bare frontend annotation, for back-compat): attach a
//     host-matching ACL + use_backend action to an existing frontend.
//   - neither: backend-only — the operator binds the backend to a frontend by hand.
func (p *HAProxy) applyRouting(ctx context.Context, svc *corev1.Service, backendUUID string) error {
	switch annotations.Get(svc, annotations.FrontendMode, "") {
	case annotations.FrontendDedicated:
		return p.applyDedicatedFrontend(ctx, svc, backendUUID)
	case annotations.FrontendShared:
		return p.applySharedRouting(ctx, svc, backendUUID)
	default:
		// Back-compat: a frontend named without an explicit mode is shared.
		if annotations.Get(svc, annotations.Frontend, "") != "" {
			return p.applySharedRouting(ctx, svc, backendUUID)
		}
		return nil
	}
}

// applyDedicatedFrontend creates/updates a frontend the operator fully owns,
// bound to listen-port and (if tls-cert is set) offloading TLS for the named
// certificate. Reproduces the manually-built :9001 frontend from annotations.
func (p *HAProxy) applyDedicatedFrontend(ctx context.Context, svc *corev1.Service, backendUUID string) error {
	port := annotations.Get(svc, annotations.ListenPort, "")
	if port == "" {
		return fmt.Errorf("frontend-mode=%s requires annotation %s", annotations.FrontendDedicated, annotations.ListenPort)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid %s %q: must be 1-65535", annotations.ListenPort, port)
	}

	fe := opnsense.Frontend{
		Enabled:        "1",
		Name:           frontendName(svc),
		Description:    managedDescription(svc),
		Bind:           p.cfg.FrontendBindAddress + ":" + port,
		Mode:           "http",
		DefaultBackend: backendUUID,
	}

	// Optional TLS offload: resolve the cert name to a HAProxy refid.
	if cert := annotations.Get(svc, annotations.TLSCert, ""); cert != "" {
		refid, err := p.opn.Trust().FindCertRef(ctx, cert)
		if err != nil {
			return fmt.Errorf("resolve tls-cert %q: %w", cert, err)
		}
		if refid == "" {
			return fmt.Errorf("tls-cert %q not found in certificate store", cert)
		}
		fe.SSLEnabled = "1"
		fe.SSLCertificates = refid
		fe.SSLDefaultCertificate = refid
	}

	if _, err := p.opn.HAProxy().UpsertFrontend(ctx, fe); err != nil {
		return fmt.Errorf("upsert frontend %s: %w", fe.Name, err)
	}
	return nil
}

func (p *HAProxy) applySharedRouting(ctx context.Context, svc *corev1.Service, backendUUID string) error {
	frontend := annotations.Get(svc, annotations.Frontend, "")
	host := annotations.Get(svc, annotations.Hostname, "")
	if frontend == "" || host == "" {
		return fmt.Errorf("frontend-mode=%s requires annotations %s and %s",
			annotations.FrontendShared, annotations.Frontend, annotations.Hostname)
	}
	hap := p.opn.HAProxy()
	desc := managedDescription(svc)

	aclUUID, err := hap.UpsertACL(ctx, opnsense.ACL{
		Name:        aclName(svc),
		Description: desc,
		Expression:  opnsense.ACLExprHostMatch,
		HdrSub:      host,
	})
	if err != nil {
		return fmt.Errorf("upsert acl: %w", err)
	}

	actionUUID, err := hap.UpsertAction(ctx, opnsense.Action{
		Name:        actionName(svc),
		Description: desc,
		TestType:    "if",
		Type:        "use_backend",
		LinkedAcls:  aclUUID,
		Operator:    "and",
		UseBackend:  backendUUID,
	})
	if err != nil {
		return fmt.Errorf("upsert action: %w", err)
	}

	if _, err := hap.AttachActionToFrontend(ctx, frontend, actionUUID); err != nil {
		return fmt.Errorf("attach action to frontend %q: %w", frontend, err)
	}

	// Bind the SNI certificate to the shared frontend so it presents a valid
	// cert for this host. Dedicated mode sets the cert when it creates its own
	// frontend; shared mode attaches to a pre-existing frontend, so it must add
	// the cert to that frontend's list (additive — other hosts' certs are kept,
	// TLS picks per-SNI). Without this, a new host on a shared HTTPS frontend is
	// served the frontend's default cert and fails verification.
	if cert := annotations.Get(svc, annotations.TLSCert, ""); cert != "" {
		refid, err := p.opn.Trust().FindCertRef(ctx, cert)
		if err != nil {
			return fmt.Errorf("resolve tls-cert %q: %w", cert, err)
		}
		if refid == "" {
			return fmt.Errorf("tls-cert %q not found in certificate store", cert)
		}
		if _, err := hap.EnsureFrontendCertificate(ctx, frontend, refid); err != nil {
			return fmt.Errorf("bind tls-cert to shared frontend %q: %w", frontend, err)
		}
	}
	return nil
}

func (p *HAProxy) cleanupRouting(ctx context.Context, svc *corev1.Service) error {
	hap := p.opn.HAProxy()
	frontend := annotations.Get(svc, annotations.Frontend, "")

	// Delete any dedicated frontend we own first — it references the backend as
	// its default. Found by name (managed convention), so cleanup never depends
	// on annotations still being present.
	if feUUID, err := hap.FindFrontend(ctx, frontendName(svc)); err != nil {
		return err
	} else if feUUID != "" {
		if err := hap.DeleteFrontend(ctx, feUUID); err != nil {
			return err
		}
	}

	actionUUID, err := hap.FindAction(ctx, actionName(svc))
	if err != nil {
		return err
	}
	if actionUUID != "" {
		if frontend != "" {
			if _, err := hap.DetachActionFromFrontend(ctx, frontend, actionUUID); err != nil {
				return err
			}
		}
		if err := hap.DeleteAction(ctx, actionUUID); err != nil {
			return err
		}
	}
	if aclUUID, err := hap.FindACL(ctx, aclName(svc)); err != nil {
		return err
	} else if aclUUID != "" {
		if err := hap.DeleteACL(ctx, aclUUID); err != nil {
			return err
		}
	}
	return nil
}

// pruneServers deletes managed servers belonging to svc whose names are not in
// the desired set. This is how scale-down / node-removal / VIP-change converge.
func (p *HAProxy) pruneServers(ctx context.Context, svc *corev1.Service, desired map[string]bool) error {
	hap := p.opn.HAProxy()
	managed, err := hap.ListManagedServers(ctx)
	if err != nil {
		return err
	}
	prefix := serverNamePrefix(svc)
	for _, m := range managed {
		if !strings.HasPrefix(m.Name, prefix) || desired[m.Name] {
			continue
		}
		if err := hap.DeleteServer(ctx, m.UUID); err != nil {
			return fmt.Errorf("prune server %s: %w", m.Name, err)
		}
	}
	return nil
}
