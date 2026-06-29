package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/trickyearlobe/opnsense-operator/internal/annotations"
	"github.com/trickyearlobe/opnsense-operator/internal/config"
	"github.com/trickyearlobe/opnsense-operator/pkg/opnsense"
)

// newFirewallProvider wires a Firewall provider to an httptest OPNsense, with a
// default allowed WAN range of 9000-9099 and "wan" interface.
func newFirewallProvider(t *testing.T, handler http.HandlerFunc) (*Firewall, opnsense.FirewallRules) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := opnsense.NewClient(opnsense.Options{BaseURL: srv.URL, Key: "k", Secret: "s"})
	p := &Firewall{
		opn:          c,
		cfg:          &config.Config{WANInterface: "wan", WANAllowedPorts: "9000-9099", FirewallRuleAPI: "automation"},
		reconfigurer: NewReconfigurer(c, 0),
	}
	rules, err := c.FirewallRules("automation")
	if err != nil {
		t.Fatal(err)
	}
	return p, rules
}

func exposedWANSvc(port string) *corev1.Service {
	s := svc("aladdin", "demo-wallet")
	s.Annotations = map[string]string{
		annotations.FrontendMode: annotations.FrontendDedicated,
		annotations.ListenPort:   port,
		annotations.ExposeWAN:    "true",
	}
	return s
}

// TestFirewallReconcile_OpensAllowedPort posts a WAN pass rule for an in-range
// port with the expected fields.
func TestFirewallReconcile_OpensAllowedPort(t *testing.T) {
	var addBody map[string]json.RawMessage
	p, rules := newFirewallProvider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/firewall/filter/searchRule":
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": []any{}, "total": 0})
		case "/api/firewall/filter/addRule":
			_ = json.NewDecoder(r.Body).Decode(&addBody)
			_ = json.NewEncoder(w).Encode(map[string]string{"result": "saved", "uuid": "rule-uuid"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})

	changed, err := p.reconcile(context.Background(), rules, exposedWANSvc("9002"))
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true after opening a port")
	}
	rule := map[string]string{}
	_ = json.Unmarshal(addBody["rule"], &rule)
	if rule["interface"] != "wan" || rule["action"] != "pass" || rule["destination_port"] != "9002" {
		t.Errorf("rule fields wrong: %+v", rule)
	}
	if rule["description"] != firewallRuleDescription(exposedWANSvc("9002")) {
		t.Errorf("description = %q", rule["description"])
	}
}

// TestFirewallReconcile_RefusesOutOfRangePort: a port outside the allowed range
// must error and make no API call (nil handler panics if one happens).
func TestFirewallReconcile_RefusesOutOfRangePort(t *testing.T) {
	c := opnsense.NewClient(opnsense.Options{BaseURL: "http://unused", Key: "k", Secret: "s"})
	rules, _ := c.FirewallRules("automation")
	p := &Firewall{cfg: &config.Config{WANInterface: "wan", WANAllowedPorts: "9000-9099"}}

	if _, err := p.reconcile(context.Background(), rules, exposedWANSvc("22")); err == nil {
		t.Error("expected refusal to open port 22 (out of range)")
	}
}

// TestFirewallReconcile_EmptyRangeDeniesAll: with no configured range, even an
// otherwise-sane port is refused — WAN exposure is opt-in at operator level.
func TestFirewallReconcile_EmptyRangeDeniesAll(t *testing.T) {
	c := opnsense.NewClient(opnsense.Options{BaseURL: "http://unused", Key: "k", Secret: "s"})
	rules, _ := c.FirewallRules("automation")
	p := &Firewall{cfg: &config.Config{WANInterface: "wan", WANAllowedPorts: ""}}

	if _, err := p.reconcile(context.Background(), rules, exposedWANSvc("9002")); err == nil {
		t.Error("expected refusal when no allowed range is configured")
	}
}

// TestFirewallReconcile_RequiresListenPort errors when expose-wan is set without
// a listen-port.
func TestFirewallReconcile_RequiresListenPort(t *testing.T) {
	c := opnsense.NewClient(opnsense.Options{BaseURL: "http://unused", Key: "k", Secret: "s"})
	rules, _ := c.FirewallRules("automation")
	p := &Firewall{cfg: &config.Config{WANInterface: "wan", WANAllowedPorts: "9000-9099"}}

	s := svc("aladdin", "demo-wallet")
	s.Annotations = map[string]string{annotations.ExposeWAN: "true"}
	if _, err := p.reconcile(context.Background(), rules, s); err == nil {
		t.Error("expected error when listen-port is missing")
	}
}

// TestFirewallReconcile_OptOutRemovesRule: no expose-wan annotation removes a
// previously-created rule (converging on opt-out), matched by description.
func TestFirewallReconcile_OptOutRemovesRule(t *testing.T) {
	var delHit string
	p, rules := newFirewallProvider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/firewall/filter/searchRule":
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]string{
				{"uuid": "existing", "description": firewallRuleDescription(svc("aladdin", "demo-wallet"))},
			}, "total": 1})
		case "/api/firewall/filter/delRule/existing":
			delHit = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]string{"result": "deleted"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})

	// A service with no expose-wan annotation should have its rule removed.
	changed, err := p.reconcile(context.Background(), rules, svc("aladdin", "demo-wallet"))
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !changed || delHit == "" {
		t.Fatalf("expected the stale rule to be deleted; changed=%v hit=%q", changed, delHit)
	}
}

// TestFirewallReconcile_OptOutNoRuleIsNoop: opt-out with nothing to delete makes
// no change (so no apply is triggered).
func TestFirewallReconcile_OptOutNoRuleIsNoop(t *testing.T) {
	p, rules := newFirewallProvider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/firewall/filter/searchRule" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rows": []any{}, "total": 0})
	})
	changed, err := p.reconcile(context.Background(), rules, svc("aladdin", "demo-wallet"))
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if changed {
		t.Error("expected changed=false when there is no rule to remove")
	}
}
