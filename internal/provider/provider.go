// Package provider defines the module seam for the OPNsense operator.
//
// Each Provider maps Kubernetes intent onto one slice of OPNsense
// configuration (HAProxy routing, DNS, ACME, …). The controller stays thin: it
// resolves a Service, manages the finalizer, then fans out to every registered
// Provider. New OPNsense capabilities (e.g. a future cluster-level BGP module)
// plug in here without touching the reconcile core.
package provider

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/trickyearlobe/opnsense-operator/internal/config"
	"github.com/trickyearlobe/opnsense-operator/pkg/opnsense"
)

// Provider reconciles one slice of OPNsense state for a Service.
//
// Apply converges desired state for an exposed Service; it must be idempotent.
// Cleanup removes everything the provider may have created for the Service and
// must also be idempotent — it runs on delete and on opt-out, when the relevant
// annotations may already be gone, so it must not rely on them.
type Provider interface {
	Name() string
	Apply(ctx context.Context, svc *corev1.Service) error
	Cleanup(ctx context.Context, svc *corev1.Service) error
}

// Deps are the shared dependencies handed to every provider.
type Deps struct {
	K8s          client.Client
	OPN          *opnsense.Client
	Cfg          *config.Config
	Reconfigurer *Reconfigurer
}

// Default builds the standard provider set. Order matters: Apply runs in this
// order, Cleanup runs in reverse (so routing is torn down before the backend it
// references).
func Default(d Deps) []Provider {
	return []Provider{
		NewHAProxy(d),  // backend/servers + optional frontend ACL
		NewFirewall(d), // WAN pass rule for the frontend port (gated)
		NewDNS(d),      // Unbound host override
		NewACME(d),     // certificate issue/renew
	}
}
