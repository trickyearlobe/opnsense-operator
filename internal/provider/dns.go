package provider

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/trickyearlobe/opnsense-operator/internal/annotations"
	"github.com/trickyearlobe/opnsense-operator/internal/config"
	"github.com/trickyearlobe/opnsense-operator/pkg/opnsense"
)

// DNS maintains an Unbound host override mapping the Service hostname to its
// address, so the name resolves on the firewall's resolver.
type DNS struct {
	k8s          client.Client
	opn          *opnsense.Client
	cfg          *config.Config
	reconfigurer *Reconfigurer
}

// NewDNS builds the DNS provider.
func NewDNS(d Deps) *DNS {
	return &DNS{k8s: d.K8s, opn: d.OPN, cfg: d.Cfg, reconfigurer: d.Reconfigurer}
}

func (p *DNS) Name() string { return "dns" }

func (p *DNS) Apply(ctx context.Context, svc *corev1.Service) error {
	if !annotations.Bool(svc, annotations.DNS) {
		return nil
	}
	host := annotations.Get(svc, annotations.Hostname, "")
	addr := dnsAddress(svc)
	if host == "" || addr == "" {
		// Need both a name and a stable address to publish.
		return nil
	}
	hostname, domain := splitHost(host, p.cfg.DNSDomain)
	if _, err := p.opn.Unbound().UpsertHostOverride(ctx, opnsense.HostOverride{
		Enabled:     "1",
		Hostname:    hostname,
		Domain:      domain,
		Server:      addr,
		Description: managedDescription(svc),
	}); err != nil {
		return err
	}
	p.reconfigurer.TriggerUnbound()
	return nil
}

func (p *DNS) Cleanup(ctx context.Context, svc *corev1.Service) error {
	host := annotations.Get(svc, annotations.Hostname, "")
	if host == "" {
		return nil
	}
	hostname, domain := splitHost(host, p.cfg.DNSDomain)
	uuid, err := p.opn.Unbound().FindHostOverride(ctx, hostname, domain)
	if err != nil || uuid == "" {
		return err
	}
	if err := p.opn.Unbound().DeleteHostOverride(ctx, uuid); err != nil {
		return err
	}
	p.reconfigurer.TriggerUnbound()
	return nil
}

// dnsAddress is the address the hostname should resolve to: the explicit VIP if
// given, else the Service's own LoadBalancer IP.
func dnsAddress(svc *corev1.Service) string {
	if addr := annotations.Get(svc, annotations.UpstreamAddress, ""); addr != "" {
		return addr
	}
	return loadBalancerIP(svc)
}

// splitHost splits "host.example.com" into ("host", "example.com"); a bare label
// gets the configured default domain.
func splitHost(host, defaultDomain string) (hostname, domain string) {
	if i := strings.Index(host, "."); i >= 0 {
		return host[:i], host[i+1:]
	}
	return host, defaultDomain
}
