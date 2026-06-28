//go:build integration

// Read-only ACME integration test: prove name → certificate resolution against
// the real os-acme-client config. Run with:
//
//	OPNSENSE_URL=... OPNSENSE_KEY=... OPNSENSE_SECRET=... \
//	  go test -tags integration -run TestLive_ACME ./pkg/opnsense/
package opnsense

import (
	"context"
	"os"
	"testing"
)

// TestLive_FindCertByName resolves a real cert by name and reports its status.
// LIVE_ACME_NAME defaults to the wildcard used elsewhere in these tests.
func TestLive_FindCertByName(t *testing.T) {
	c := liveClient(t)
	name := os.Getenv("LIVE_ACME_NAME")
	if name == "" {
		name = "*.trickyearlobe.com"
	}
	cert, err := c.ACME().FindCertByName(context.Background(), name)
	if err != nil {
		t.Fatalf("FindCertByName: %v", err)
	}
	if cert == nil {
		t.Fatalf("no ACME certificate resolved for %q", name)
	}
	t.Logf("resolved %q -> uuid=%s issued=%v refid=%s altNames=%q",
		name, cert.UUID, cert.Issued(), cert.CertRefID, cert.AltNames)
	if cert.Name != name {
		t.Logf("note: matched via altNames (cert primary name is %q)", cert.Name)
	}
}
