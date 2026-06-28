//go:build integration

// Read-only firewall integration tests against a real OPNsense box. They prove
// our request/response shapes for the os-firewall Automation/Filter API match
// the live API, without mutating anything. Run with the same env as the other
// live tests:
//
//	OPNSENSE_URL=... OPNSENSE_KEY=... OPNSENSE_SECRET=... \
//	  go test -tags integration -run TestLive_Firewall ./pkg/opnsense/
package opnsense

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestLive_FirewallSearchRule proves searchRule parses against the real config
// and that ListManaged filters cleanly (it may legitimately find zero rules).
func TestLive_FirewallSearchRule(t *testing.T) {
	c := liveClient(t)
	rules, err := c.FirewallRules(os.Getenv("LIVE_FIREWALL_API"))
	if err != nil {
		t.Fatalf("FirewallRules: %v", err)
	}

	// FindByDescription on a marker that cannot exist must succeed with "".
	uuid, err := rules.FindByDescription(context.Background(), ManagedMarker+" ns=__none__ svc=__none__ fw=wan-ingress")
	if err != nil {
		t.Fatalf("FindByDescription: %v", err)
	}
	if uuid != "" {
		t.Fatalf("unexpected match for a non-existent rule: %q", uuid)
	}

	managed, err := rules.ListManaged(context.Background())
	if err != nil {
		t.Fatalf("ListManaged: %v", err)
	}
	for _, m := range managed {
		if !strings.Contains(m.Description, ManagedMarker) {
			t.Fatalf("ListManaged returned an unmanaged rule: %+v", m)
		}
	}
	t.Logf("api=%s managed firewall rules: %d", rules.API(), len(managed))
}
