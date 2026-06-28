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

// ACME triggers issuance/renewal of a pre-existing certificate whose
// description matches the Service hostname. It does not create the certificate
// object (that's a one-time firewall setup; see README roadmap).
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
	host := annotations.Get(svc, annotations.Hostname, "")
	if host == "" {
		return nil
	}
	uuid, err := p.opn.ACME().FindCertificate(ctx, host)
	if err != nil {
		return err
	}
	if uuid == "" {
		return fmt.Errorf("no ACME certificate with description %q (create it on the firewall first)", host)
	}
	// Issuance failures are retryable and must not block routing; log and move
	// on. The periodic resync will retry.
	if err := p.opn.ACME().IssueOrRenew(ctx, uuid); err != nil {
		log.FromContext(ctx).Error(err, "acme issue/renew failed (will retry on resync)", "host", host)
	}
	return nil
}

// Cleanup is a no-op: certificates outlive the Service and are managed on the
// firewall, so we never delete them here.
func (p *ACME) Cleanup(ctx context.Context, svc *corev1.Service) error { return nil }
