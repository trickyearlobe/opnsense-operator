package provider

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/trickyearlobe/opnsense-operator/internal/annotations"
	"github.com/trickyearlobe/opnsense-operator/internal/config"
	"github.com/trickyearlobe/opnsense-operator/pkg/opnsense"
)

// ACME ensures the certificate a Service binds is issued. It resolves a
// pre-existing os-acme-client cert by domain name (the tls-cert annotation, else
// hostname) and triggers issuance only when that cert has not yet been signed —
// once issued, OPNsense's own auto-renewal owns it, so we don't force a re-issue
// on every resync. It does not create the certificate object (account +
// validation method are a one-time firewall setup; see README roadmap).
type ACME struct {
	k8s          client.Client
	opn          *opnsense.Client
	cfg          *config.Config
	reconfigurer *Reconfigurer
}

// NewACME builds the ACME provider.
func NewACME(d Deps) *ACME {
	return &ACME{k8s: d.K8s, opn: d.OPN, cfg: d.Cfg, reconfigurer: d.Reconfigurer}
}

func (p *ACME) Name() string { return "acme" }

func (p *ACME) Apply(ctx context.Context, svc *corev1.Service) error {
	if !annotations.Bool(svc, annotations.ACME) {
		return nil
	}
	// Name the cert the same way the frontend binds it: tls-cert first, else the
	// hostname. Resolving by domain name (not description) matches how certs are
	// actually identified on the box.
	name := annotations.Get(svc, annotations.TLSCert, "")
	if name == "" {
		name = annotations.Get(svc, annotations.Hostname, "")
	}
	if name == "" {
		return fmt.Errorf("%s=true requires %s or %s to name the certificate",
			annotations.ACME, annotations.TLSCert, annotations.Hostname)
	}

	cert, err := p.opn.ACME().FindCertByName(ctx, name)
	if err != nil {
		return err
	}
	if cert == nil {
		return fmt.Errorf("no ACME certificate named %q (create the cert object on the firewall first)", name)
	}

	l := log.FromContext(ctx)
	if cert.Issued() {
		// Already signed; OPNsense auto-renewal owns ongoing renewal. Forcing a
		// re-issue every resync would needlessly hit the ACME provider.
		l.V(1).Info("acme cert already issued; leaving renewal to opnsense", "name", cert.Name)
		return nil
	}
	// Not signed yet — trigger issuance now. Failures are retryable and must not
	// block routing; the periodic resync will retry.
	if err := p.opn.ACME().IssueOrRenew(ctx, cert.UUID); err != nil {
		l.Error(err, "acme issue failed (will retry on resync)", "name", cert.Name)
	}
	return nil
}

// Cleanup is a no-op: certificates outlive the Service and are managed on the
// firewall, so we never delete them here.
func (p *ACME) Cleanup(_ context.Context, _ *corev1.Service) error { return nil }
