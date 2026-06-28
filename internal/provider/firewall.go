package provider

import (
	"context"
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/trickyearlobe/opnsense-operator/internal/annotations"
	"github.com/trickyearlobe/opnsense-operator/internal/config"
	"github.com/trickyearlobe/opnsense-operator/pkg/opnsense"
)

// Firewall opens (and tears down) a single WAN pass rule for a Service that asks
// to be exposed on the WAN. It is gated hard by operator policy: only when
// expose-wan is true, only for the dedicated frontend's listen-port, and only
// when that port falls inside the operator-configured allowed range. The WAN
// interface is operator config, never annotation-driven.
type Firewall struct {
	opn          *opnsense.Client
	cfg          *config.Config
	reconfigurer *Reconfigurer
}

// NewFirewall builds the Firewall provider.
func NewFirewall(d Deps) *Firewall {
	return &Firewall{opn: d.OPN, cfg: d.Cfg, reconfigurer: d.Reconfigurer}
}

func (p *Firewall) Name() string { return "firewall" }

func (p *Firewall) Apply(ctx context.Context, svc *corev1.Service) error {
	rules, err := p.opn.FirewallRules(p.cfg.FirewallRuleAPI)
	if err != nil {
		return err
	}
	changed, err := p.reconcile(ctx, rules, svc)
	if err != nil {
		return err
	}
	if changed {
		p.reconfigurer.TriggerFirewall()
	}
	return nil
}

func (p *Firewall) Cleanup(ctx context.Context, svc *corev1.Service) error {
	rules, err := p.opn.FirewallRules(p.cfg.FirewallRuleAPI)
	if err != nil {
		return err
	}
	changed, err := p.removeRule(ctx, rules, svc)
	if err != nil {
		return err
	}
	if changed {
		p.reconfigurer.TriggerFirewall()
	}
	return nil
}

// reconcile converges the WAN rule for svc and reports whether it changed the
// firewall (so the caller debounces an apply). Opting out (expose-wan absent)
// removes any rule we previously created.
func (p *Firewall) reconcile(ctx context.Context, rules opnsense.FirewallRules, svc *corev1.Service) (bool, error) {
	l := log.FromContext(ctx)

	if !annotations.Bool(svc, annotations.ExposeWAN) {
		return p.removeRule(ctx, rules, svc)
	}

	// WAN exposure only makes sense for an operator-owned frontend port.
	port := annotations.Get(svc, annotations.ListenPort, "")
	if port == "" {
		return false, fmt.Errorf("%s requires %s (the WAN port to open)", annotations.ExposeWAN, annotations.ListenPort)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false, fmt.Errorf("invalid %s %q: must be 1-65535", annotations.ListenPort, port)
	}
	if !p.cfg.WANPortAllowed(n) {
		return false, fmt.Errorf("refusing to open WAN port %d for %s/%s: outside the operator allowed range (WAN_ALLOWED_PORTS=%q)",
			n, svc.Namespace, svc.Name, p.cfg.WANAllowedPorts)
	}

	// Destination is "(self)" — the dedicated frontend listens on the firewall
	// itself (FrontendBindAddress, default 0.0.0.0), so WAN traffic targets the
	// box's WAN address. This keeps the rule to exactly the port we open.
	if _, err := rules.Upsert(ctx, opnsense.FirewallRule{
		Enabled:         true,
		Action:          "pass",
		Interface:       p.cfg.WANInterface,
		Direction:       "in",
		IPProtocol:      "inet",
		Protocol:        "TCP",
		SourceNet:       "any",
		DestinationNet:  "(self)",
		DestinationPort: port,
		Description:     firewallRuleDescription(svc),
	}); err != nil {
		return false, fmt.Errorf("upsert wan rule: %w", err)
	}

	l.Info("reconciled wan firewall rule", "service", svc.Name, "port", n, "api", rules.API())
	return true, nil
}

// removeRule deletes this service's WAN rule if present. Idempotent and matched
// by the managed description, so it never depends on annotations still being set
// (it runs on delete and on opt-out).
func (p *Firewall) removeRule(ctx context.Context, rules opnsense.FirewallRules, svc *corev1.Service) (bool, error) {
	uuid, err := rules.FindByDescription(ctx, firewallRuleDescription(svc))
	if err != nil {
		return false, err
	}
	if uuid == "" {
		return false, nil
	}
	if err := rules.Delete(ctx, uuid); err != nil {
		return false, fmt.Errorf("delete wan rule: %w", err)
	}
	return true, nil
}

// firewallRuleDescription is the per-service match key: the managed marker (so
// ListManaged sees it) plus a role tag (so it is unique and reads clearly in the
// OPNsense GUI).
func firewallRuleDescription(svc *corev1.Service) string {
	return managedDescription(svc) + " fw=wan-ingress"
}
