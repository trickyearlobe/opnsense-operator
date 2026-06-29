//go:build integration

// Read-only integration tests against a real OPNsense box. They validate that
// our request/response shapes match the live API — the thing unit tests with
// mocks can't catch. Run with:
//
//	OPNSENSE_URL=https://opnsense OPNSENSE_KEY=... OPNSENSE_SECRET=... \
//	  go test -tags integration -run TestLive ./pkg/opnsense/
//
// Skipped automatically when OPNSENSE_URL is unset. These tests never mutate.
package opnsense

import (
	"context"
	"os"
	"testing"
	"time"
)

func liveClient(t *testing.T) *Client {
	t.Helper()
	url := os.Getenv("OPNSENSE_URL")
	if url == "" {
		t.Skip("OPNSENSE_URL not set; skipping live integration test")
	}
	return NewClient(Options{
		BaseURL:            url,
		Key:                os.Getenv("OPNSENSE_KEY"),
		Secret:             os.Getenv("OPNSENSE_SECRET"),
		InsecureSkipVerify: os.Getenv("OPNSENSE_INSECURE") == "true",
		Timeout:            20 * time.Second,
	})
}

// TestLive_FindCertRef proves name → refid resolution against real certs.
func TestLive_FindCertRef(t *testing.T) {
	c := liveClient(t)
	ref, err := c.Trust().FindCertRef(context.Background(), os.Getenv("LIVE_CERT_CN"))
	if err != nil {
		t.Fatalf("FindCertRef: %v", err)
	}
	if ref == "" {
		t.Fatalf("no refid resolved for %q", os.Getenv("LIVE_CERT_CN"))
	}
	t.Logf("resolved %q -> refid %s", os.Getenv("LIVE_CERT_CN"), ref)
	if want := os.Getenv("LIVE_CERT_REFID"); want != "" && ref != want {
		t.Fatalf("refid = %q, want %q", ref, want)
	}
}

// TestLive_FindFrontend proves frontend search/parse against the real config.
func TestLive_FindFrontend(t *testing.T) {
	c := liveClient(t)
	name := os.Getenv("LIVE_FRONTEND_NAME")
	if name == "" {
		t.Skip("LIVE_FRONTEND_NAME not set")
	}
	uuid, err := c.HAProxy().FindFrontend(context.Background(), name)
	if err != nil {
		t.Fatalf("FindFrontend: %v", err)
	}
	if uuid == "" {
		t.Fatalf("frontend %q not found", name)
	}
	t.Logf("frontend %q -> %s", name, uuid)
}
