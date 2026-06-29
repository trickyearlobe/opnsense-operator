package opnsense

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func acmeSearchHandler(t *testing.T, rows []map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/acmeclient/certificates/search" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rows": rows, "total": len(rows)})
	}
}

// TestFindCertByName_ExactName matches a cert on its primary name (CN), and
// reports issuance + refid from statusCode/certRefId.
func TestFindCertByName_ExactName(t *testing.T) {
	c := newTestClient(t, acmeSearchHandler(t, []map[string]string{
		{"uuid": "wild", "name": "*.trickyearlobe.com", "description": "trickyearlobe.com", "altNames": "*.trickyearlobe.com", "enabled": "1", "statusCode": "200", "certRefId": "6a3ffc9bd067d"},
		{"uuid": "zong", "name": "zong.trickyearlobe.com", "description": "Zong web application", "altNames": "zong.trickyearlobe.com", "enabled": "1", "statusCode": "200", "certRefId": "6a3f1a0d58b57"},
	}))

	got, err := c.ACME().FindCertByName(context.Background(), "zong.trickyearlobe.com")
	if err != nil {
		t.Fatalf("FindCertByName: %v", err)
	}
	if got == nil || got.UUID != "zong" {
		t.Fatalf("expected zong cert, got %+v", got)
	}
	if !got.Issued() || got.CertRefID != "6a3f1a0d58b57" {
		t.Errorf("issued/refid wrong: %+v", got)
	}
}

// TestFindCertByName_AltNamesFallback matches a host that is a SAN, not the CN.
func TestFindCertByName_AltNamesFallback(t *testing.T) {
	c := newTestClient(t, acmeSearchHandler(t, []map[string]string{
		{"uuid": "multi", "name": "lan.trickyearlobe.com", "altNames": "trickyearlobe.com,www.trickyearlobe.com", "enabled": "1", "statusCode": "200"},
	}))

	got, err := c.ACME().FindCertByName(context.Background(), "www.trickyearlobe.com")
	if err != nil {
		t.Fatalf("FindCertByName: %v", err)
	}
	if got == nil || got.UUID != "multi" {
		t.Fatalf("expected altNames fallback match, got %+v", got)
	}
}

// TestFindCertByName_ExactNameBeatsAltNames: an exact name match wins over a
// cert that merely lists the name as a SAN.
func TestFindCertByName_ExactNameBeatsAltNames(t *testing.T) {
	c := newTestClient(t, acmeSearchHandler(t, []map[string]string{
		{"uuid": "san-holder", "name": "other.example.com", "altNames": "app.example.com", "statusCode": "200"},
		{"uuid": "exact", "name": "app.example.com", "altNames": "app.example.com", "statusCode": "200"},
	}))

	got, err := c.ACME().FindCertByName(context.Background(), "app.example.com")
	if err != nil {
		t.Fatalf("FindCertByName: %v", err)
	}
	if got == nil || got.UUID != "exact" {
		t.Fatalf("expected the exact-name cert to win, got %+v", got)
	}
}

// TestFindCertByName_NotFound returns nil (not an error) when nothing matches.
func TestFindCertByName_NotFound(t *testing.T) {
	c := newTestClient(t, acmeSearchHandler(t, []map[string]string{
		{"uuid": "x", "name": "other.example.com", "altNames": "other.example.com"},
	}))

	got, err := c.ACME().FindCertByName(context.Background(), "missing.example.com")
	if err != nil {
		t.Fatalf("FindCertByName: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for no match, got %+v", got)
	}
}

func TestCertificateIssued(t *testing.T) {
	if (&Certificate{StatusCode: "200"}).Issued() != true {
		t.Error("statusCode 200 should be issued")
	}
	for _, s := range []string{"", "0", "404", "100"} {
		if (&Certificate{StatusCode: s}).Issued() {
			t.Errorf("statusCode %q should not be issued", s)
		}
	}
}
