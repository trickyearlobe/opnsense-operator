package provider

import (
	"context"
	"sync"
	"time"

	"github.com/trickyearlobe/opnsense-operator/pkg/opnsense"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Reconfigurer coalesces "apply" requests so that a burst of object mutations
// (e.g. a deployment that touches many Services at once) results in a single
// haproxy/unbound reload rather than one per change. Calling Reconfigure on
// the OPNsense API regenerates and reloads the service, which is relatively
// expensive — debouncing keeps that off the hot path.
type Reconfigurer struct {
	client   *opnsense.Client
	debounce time.Duration

	// FirewallAPI selects which firewall-rule API to apply (empty = automation).
	// Set once at startup; read under mu is unnecessary as it never changes.
	FirewallAPI string

	mu              sync.Mutex
	haproxyPending  bool
	unboundPending  bool
	dnsmasqPending  bool
	dyndnsPending   bool
	firewallPending bool
	timer           *time.Timer
}

// NewReconfigurer builds a Reconfigurer with the given debounce window.
func NewReconfigurer(client *opnsense.Client, debounce time.Duration) *Reconfigurer {
	return &Reconfigurer{client: client, debounce: debounce}
}

// TriggerHAProxy schedules a debounced haproxy reload.
func (r *Reconfigurer) TriggerHAProxy() { r.mark(func() { r.haproxyPending = true }) }

// TriggerUnbound schedules a debounced unbound reload.
func (r *Reconfigurer) TriggerUnbound() { r.mark(func() { r.unboundPending = true }) }

// TriggerDnsmasq schedules a debounced dnsmasq reload.
func (r *Reconfigurer) TriggerDnsmasq() { r.mark(func() { r.dnsmasqPending = true }) }

// TriggerDynDNS schedules a debounced ddclient (dyndns) reload.
func (r *Reconfigurer) TriggerDynDNS() { r.mark(func() { r.dyndnsPending = true }) }

// TriggerFirewall schedules a debounced firewall ruleset apply.
func (r *Reconfigurer) TriggerFirewall() { r.mark(func() { r.firewallPending = true }) }

// mark sets a pending flag under the lock and (re)arms the debounce timer.
func (r *Reconfigurer) mark(set func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	set()
	if r.timer == nil {
		r.timer = time.AfterFunc(r.debounce, r.flush)
		return
	}
	r.timer.Reset(r.debounce)
}

func (r *Reconfigurer) flush() {
	r.mu.Lock()
	haproxy := r.haproxyPending
	unbound := r.unboundPending
	dnsmasq := r.dnsmasqPending
	dyndns := r.dyndnsPending
	firewall := r.firewallPending
	r.haproxyPending = false
	r.unboundPending = false
	r.dnsmasqPending = false
	r.dyndnsPending = false
	r.firewallPending = false
	r.mu.Unlock()

	// Use a fresh, bounded context: this fires from a timer, detached from any
	// reconcile's context.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	l := log.FromContext(ctx).WithName("reconfigurer")

	if haproxy {
		if err := r.client.HAProxy().Reconfigure(ctx); err != nil {
			l.Error(err, "haproxy reconfigure failed")
		} else {
			l.Info("haproxy reconfigured")
		}
	}
	if unbound {
		if err := r.client.Unbound().Reconfigure(ctx); err != nil {
			l.Error(err, "unbound reconfigure failed")
		} else {
			l.Info("unbound reconfigured")
		}
	}
	if dnsmasq {
		if err := r.client.Dnsmasq().Reconfigure(ctx); err != nil {
			l.Error(err, "dnsmasq reconfigure failed")
		} else {
			l.Info("dnsmasq reconfigured")
		}
	}
	if dyndns {
		if err := r.client.DynDNS().Reconfigure(ctx); err != nil {
			l.Error(err, "ddclient reconfigure failed")
		} else {
			l.Info("ddclient reconfigured")
		}
	}
	if firewall {
		if rules, err := r.client.FirewallRules(r.FirewallAPI); err != nil {
			l.Error(err, "firewall apply skipped: bad rule API")
		} else if err := rules.Apply(ctx); err != nil {
			l.Error(err, "firewall apply failed")
		} else {
			l.Info("firewall rules applied")
		}
	}
}
