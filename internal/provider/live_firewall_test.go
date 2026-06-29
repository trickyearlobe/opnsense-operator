//go:build integration

package provider

import (
	"context"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/trickyearlobe/opnsense-operator/internal/annotations"
	"github.com/trickyearlobe/opnsense-operator/internal/config"
	"github.com/trickyearlobe/opnsense-operator/pkg/opnsense"
)

// TestLive_FirewallProvider exercises the real Firewall provider against the
// live box: open a WAN pass rule on a spare in-range port, apply, confirm it
// exists, then remove it and apply. Reversible and self-cleaning.
//
// This MUTATES the WAN firewall, so it is double-gated: it runs only when
// LIVE_WAN_RULE=1 is set explicitly (alongside per-session authorization to
// mutate the box). Env: OPNSENSE_URL/KEY/SECRET, optional LIVE_WAN_PORT
// (default 9099), LIVE_WAN_INTERFACE (default "wan").
func TestLive_FirewallProvider(t *testing.T) {
	if os.Getenv("LIVE_WAN_RULE") != "1" || os.Getenv("OPNSENSE_URL") == "" {
		t.Skip("set LIVE_WAN_RULE=1 + OPNSENSE_URL (and authorize box mutation) to run")
	}
	port := envOr("LIVE_WAN_PORT", "9099")
	c := opnsense.NewClient(opnsense.Options{
		BaseURL: os.Getenv("OPNSENSE_URL"),
		Key:     os.Getenv("OPNSENSE_KEY"),
		Secret:  os.Getenv("OPNSENSE_SECRET"),
	})
	p := &Firewall{
		opn: c,
		cfg: &config.Config{
			WANInterface:    envOr("LIVE_WAN_INTERFACE", "wan"),
			WANAllowedPorts: port + "-" + port,
			FirewallRuleAPI: "automation",
		},
		reconfigurer: NewReconfigurer(c, 0),
	}
	ctx := context.Background()

	s := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "livetest", Name: "wallet"}}
	s.Annotations = map[string]string{
		annotations.ListenPort: port,
		annotations.ExposeWAN:  "true",
	}

	rules, err := c.FirewallRules("automation")
	if err != nil {
		t.Fatalf("FirewallRules: %v", err)
	}

	// Always remove the rule we own, even on failure.
	t.Cleanup(func() {
		if uuid, err := rules.FindByDescription(ctx, firewallRuleDescription(s)); err == nil && uuid != "" {
			if err := rules.Delete(ctx, uuid); err != nil {
				t.Errorf("cleanup Delete: %v", err)
			}
			if err := rules.Apply(ctx); err != nil {
				t.Errorf("cleanup Apply: %v", err)
			}
			t.Logf("cleaned up wan rule %s", uuid)
		}
	})

	// Open the port.
	changed, err := p.reconcile(ctx, rules, s)
	if err != nil {
		t.Fatalf("reconcile (open): %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true opening the port")
	}
	if err := rules.Apply(ctx); err != nil {
		t.Fatalf("apply (open): %v", err)
	}
	uuid, err := rules.FindByDescription(ctx, firewallRuleDescription(s))
	if err != nil || uuid == "" {
		t.Fatalf("rule not found after open: uuid=%q err=%v", uuid, err)
	}
	t.Logf("opened WAN :%s rule %s", port, uuid)

	// Close it (opt-out path).
	delete(s.Annotations, annotations.ExposeWAN)
	changed, err = p.reconcile(ctx, rules, s)
	if err != nil {
		t.Fatalf("reconcile (close): %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true closing the port")
	}
	if err := rules.Apply(ctx); err != nil {
		t.Fatalf("apply (close): %v", err)
	}
	if uuid, err := rules.FindByDescription(ctx, firewallRuleDescription(s)); err != nil || uuid != "" {
		t.Fatalf("rule should be gone after close: uuid=%q err=%v", uuid, err)
	}
	t.Logf("closed WAN :%s", port)
}
