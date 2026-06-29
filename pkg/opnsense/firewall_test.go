package opnsense

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// TestFirewallUpsert_CreatesWhenAbsent verifies the Automation/Filter create
// path: search finds nothing, so addRule posts the validated minimal field set.
func TestFirewallUpsert_CreatesWhenAbsent(t *testing.T) {
	var addBody map[string]filterRuleWire
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/firewall/filter/searchRule":
			_ = json.NewEncoder(w).Encode(searchResponse{Rows: nil, Total: 0})
		case "/api/firewall/filter/addRule":
			_ = json.NewDecoder(r.Body).Decode(&addBody)
			_ = json.NewEncoder(w).Encode(mutationResponse{Result: "saved", UUID: "rule-uuid"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})

	rules, err := c.FirewallRules("")
	if err != nil {
		t.Fatalf("FirewallRules: %v", err)
	}
	uuid, err := rules.Upsert(context.Background(), FirewallRule{
		Enabled: true, Action: "pass", Interface: "wan", Direction: "in",
		IPProtocol: "inet", Protocol: "TCP", SourceNet: "any",
		DestinationNet: "(self)", DestinationPort: "9002",
		Description: ManagedMarker + " ns=aladdin svc=demo-wallet fw=wan-ingress",
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if uuid != "rule-uuid" {
		t.Fatalf("uuid = %q, want rule-uuid", uuid)
	}
	got := addBody["rule"]
	if got.Enabled != "1" || got.Action != "pass" || got.Quick != "1" {
		t.Errorf("base fields wrong: %+v", got)
	}
	if got.Interface != "wan" || got.Direction != "in" || got.IPProtocol != "inet" {
		t.Errorf("interface/direction/ipproto wrong: %+v", got)
	}
	if got.Protocol != "TCP" || got.DestinationNet != "(self)" || got.DestinationPort != "9002" {
		t.Errorf("dest fields wrong: %+v", got)
	}
}

// TestFirewallUpsert_UpdatesWhenPresent verifies the rule is matched by exact
// description and updated via setRule/{uuid} rather than re-created.
func TestFirewallUpsert_UpdatesWhenPresent(t *testing.T) {
	const desc = ManagedMarker + " ns=aladdin svc=demo-wallet fw=wan-ingress"
	var setPath string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/firewall/filter/searchRule":
			_ = json.NewEncoder(w).Encode(searchResponse{
				Rows:  []Row{{UUID: "existing", Description: desc}},
				Total: 1,
			})
		case "/api/firewall/filter/setRule/existing":
			setPath = r.URL.Path
			_ = json.NewEncoder(w).Encode(mutationResponse{Result: "saved", UUID: "existing"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})

	rules, _ := c.FirewallRules(FirewallAPIAutomation)
	uuid, err := rules.Upsert(context.Background(), FirewallRule{Description: desc})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if uuid != "existing" || setPath != "/api/firewall/filter/setRule/existing" {
		t.Fatalf("expected update of existing; uuid=%q path=%q", uuid, setPath)
	}
}

// TestFirewallDelete uses the delRule endpoint.
func TestFirewallDelete(t *testing.T) {
	var hit string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		hit = r.URL.Path
		_ = json.NewEncoder(w).Encode(mutationResponse{Result: "deleted"})
	})
	rules, _ := c.FirewallRules("")
	if err := rules.Delete(context.Background(), "abc"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if hit != "/api/firewall/filter/delRule/abc" {
		t.Fatalf("delete path = %q", hit)
	}
}

// TestFirewallApply tolerates the os-firewall "OK\n..." status.
func TestFirewallApply(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/firewall/filter/apply" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "OK\n\n"})
	})
	rules, _ := c.FirewallRules("")
	if err := rules.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

// TestFirewallListManaged filters by the managed marker.
func TestFirewallListManaged(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(searchResponse{Rows: []Row{
			{UUID: "1", Description: ManagedMarker + " ns=a svc=b fw=wan-ingress"},
			{UUID: "2", Description: "hand-made WAN rule"},
		}})
	})
	rules, _ := c.FirewallRules("")
	got, err := rules.ListManaged(context.Background())
	if err != nil {
		t.Fatalf("ListManaged: %v", err)
	}
	if len(got) != 1 || got[0].UUID != "1" {
		t.Fatalf("expected only the managed row, got %+v", got)
	}
}

// TestFirewallRulesSelection: unknown API errors; rules-new fails fast.
func TestFirewallRulesSelection(t *testing.T) {
	c := NewClient(Options{BaseURL: "http://x", Key: "k", Secret: "s"})

	if _, err := c.FirewallRules("bogus"); err == nil {
		t.Error("expected error for unknown firewall API")
	}

	rn, err := c.FirewallRules(FirewallAPIRulesNew)
	if err != nil {
		t.Fatalf("rules-new selection should construct: %v", err)
	}
	if _, err := rn.Upsert(context.Background(), FirewallRule{}); err == nil {
		t.Error("expected rules-new Upsert to be unimplemented")
	}
	if err := rn.Apply(context.Background()); err == nil {
		t.Error("expected rules-new Apply to be unimplemented")
	}
}
