//go:build integration

// Read-only DNS-backend integration tests: prove our search/parse shapes match
// the live unbound, dnsmasq, and dyndns (os-ddclient) APIs. No mutation. Run:
//
//	OPNSENSE_URL=... OPNSENSE_KEY=... OPNSENSE_SECRET=... \
//	  go test -tags integration -run TestLive_DNS ./pkg/opnsense/
package opnsense

import (
	"context"
	"os"
	"testing"
)

// TestLive_DNSReadOnly exercises a read-only search on each backend so a parse
// or path mistake surfaces against the real box.
func TestLive_DNSReadOnly(t *testing.T) {
	c := liveClient(t)
	ctx := context.Background()

	// Unbound: a host override that cannot exist resolves to "".
	if uuid, err := c.Unbound().FindHostOverride(ctx, "__none__", "invalid.example"); err != nil {
		t.Fatalf("unbound FindHostOverride: %v", err)
	} else if uuid != "" {
		t.Fatalf("unbound: unexpected match %q", uuid)
	}

	// Dnsmasq: same.
	if uuid, err := c.Dnsmasq().FindHost(ctx, "__none__", "invalid.example"); err != nil {
		t.Fatalf("dnsmasq FindHost: %v", err)
	} else if uuid != "" {
		t.Fatalf("dnsmasq: unexpected match %q", uuid)
	}

	// DynDNS: ensure-hostname against a non-existent account must error (proves
	// the account search parses); never mutates.
	if _, err := c.DynDNS().EnsureHostname(ctx, "__no_such_account__", "x.example.com"); err == nil {
		t.Fatal("dyndns: expected error for a non-existent account")
	}

	// And if the operator points at a real account, resolve it (optional).
	if acct := os.Getenv("LIVE_DDCLIENT_ACCOUNT"); acct != "" {
		row, err := c.DynDNS().findAccount(ctx, acct)
		if err != nil {
			t.Fatalf("dyndns findAccount: %v", err)
		}
		if row == nil {
			t.Fatalf("dyndns: account %q not found", acct)
		}
		t.Logf("dyndns account %q -> uuid=%s hostnames=%q", acct, row.UUID, row.Hostnames)
	}
}
