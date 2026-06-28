package provider

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/trickyearlobe/opnsense-operator/internal/annotations"
	"github.com/trickyearlobe/opnsense-operator/internal/config"
	"github.com/trickyearlobe/opnsense-operator/pkg/opnsense"
)

// DNS publishes a DNS record for an exposed Service's hostname, via a pluggable
// backend selected by the dns-backend annotation (or DNS_BACKEND default):
//   - "ddclient": add the hostname to an operator-managed os-ddclient account,
//     which publishes the firewall's WAN IP to an external provider (Route53, …).
//   - "unbound" / "dnsmasq": a host override on the firewall's own resolver,
//     mapping the hostname to the Service's VIP (internal LAN resolution).
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

func (p *DNS) backend(svc *corev1.Service) string {
	return annotations.Get(svc, annotations.DNSBackend, p.cfg.DNSDefaultBackend)
}

func (p *DNS) Apply(ctx context.Context, svc *corev1.Service) error {
	if !annotations.Bool(svc, annotations.DNS) {
		return nil
	}
	host := annotations.Get(svc, annotations.Hostname, "")
	if host == "" {
		return nil
	}

	switch backend := p.backend(svc); backend {
	case annotations.DNSBackendDDClient:
		return p.applyDDClient(ctx, host)
	case annotations.DNSBackendUnbound:
		return p.applyUnbound(ctx, svc, host)
	case annotations.DNSBackendDnsmasq:
		return p.applyDnsmasq(ctx, svc, host)
	default:
		return fmt.Errorf("unknown dns-backend %q (want %s, %s, or %s)", backend,
			annotations.DNSBackendDDClient, annotations.DNSBackendUnbound, annotations.DNSBackendDnsmasq)
	}
}

func (p *DNS) Cleanup(ctx context.Context, svc *corev1.Service) error {
	host := annotations.Get(svc, annotations.Hostname, "")
	if host == "" {
		return nil
	}
	switch backend := p.backend(svc); backend {
	case annotations.DNSBackendDDClient:
		return p.cleanupDDClient(ctx, host)
	case annotations.DNSBackendUnbound:
		return p.cleanupUnbound(ctx, host)
	case annotations.DNSBackendDnsmasq:
		return p.cleanupDnsmasq(ctx, host)
	default:
		// Unknown backend on delete: nothing we can safely remove.
		return nil
	}
}

// --- ddclient (external provider) ----------------------------------------

func (p *DNS) applyDDClient(ctx context.Context, host string) error {
	if p.cfg.DDClientAccount == "" {
		return fmt.Errorf("dns-backend=ddclient requires DDCLIENT_ACCOUNT (the os-ddclient account to manage)")
	}
	changed, err := p.opn.DynDNS().EnsureHostname(ctx, p.cfg.DDClientAccount, host)
	if err != nil {
		return err
	}
	if changed {
		p.reconfigurer.TriggerDynDNS()
	}
	return nil
}

func (p *DNS) cleanupDDClient(ctx context.Context, host string) error {
	if p.cfg.DDClientAccount == "" {
		return nil
	}
	changed, err := p.opn.DynDNS().RemoveHostname(ctx, p.cfg.DDClientAccount, host)
	if err != nil {
		return err
	}
	if changed {
		p.reconfigurer.TriggerDynDNS()
	}
	return nil
}

// --- unbound (internal resolver) -----------------------------------------

func (p *DNS) applyUnbound(ctx context.Context, svc *corev1.Service, host string) error {
	addr := dnsAddress(svc)
	if addr == "" {
		return nil // need a stable address to publish; requeue
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

func (p *DNS) cleanupUnbound(ctx context.Context, host string) error {
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

// --- dnsmasq (internal resolver) -----------------------------------------

func (p *DNS) applyDnsmasq(ctx context.Context, svc *corev1.Service, host string) error {
	addr := dnsAddress(svc)
	if addr == "" {
		return nil
	}
	hostname, domain := splitHost(host, p.cfg.DNSDomain)
	if _, err := p.opn.Dnsmasq().UpsertHost(ctx, opnsense.DnsmasqHost{
		Host:   hostname,
		Domain: domain,
		IP:     addr,
		Descr:  managedDescription(svc),
	}); err != nil {
		return err
	}
	p.reconfigurer.TriggerDnsmasq()
	return nil
}

func (p *DNS) cleanupDnsmasq(ctx context.Context, host string) error {
	hostname, domain := splitHost(host, p.cfg.DNSDomain)
	uuid, err := p.opn.Dnsmasq().FindHost(ctx, hostname, domain)
	if err != nil || uuid == "" {
		return err
	}
	if err := p.opn.Dnsmasq().DeleteHost(ctx, uuid); err != nil {
		return err
	}
	p.reconfigurer.TriggerDnsmasq()
	return nil
}

// --- shared helpers ------------------------------------------------------

// dnsAddress is the address the hostname should resolve to on the firewall's own
// resolver: the explicit VIP if given, else the Service's own LoadBalancer IP.
// (Not used by ddclient, which publishes the WAN IP, not a chosen address.)
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
