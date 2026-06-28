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

func newACMEProvider(t *testing.T, handler http.HandlerFunc) *ACME {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := opnsense.NewClient(opnsense.Options{BaseURL: srv.URL, Key: "k", Secret: "s"})
	return &ACME{opn: c, cfg: &config.Config{}, reconfigurer: NewReconfigurer(c, 0)}
}

func acmeSvc(anns map[string]string) *corev1.Service {
	s := svc("aladdin", "demo-wallet")
	s.Annotations = anns
	return s
}

// TestACME_Disabled: without acme=true the provider makes no API calls.
func TestACME_Disabled(t *testing.T) {
	p := &ACME{} // nil client: any call would panic
	if err := p.Apply(context.Background(), acmeSvc(map[string]string{})); err != nil {
		t.Fatalf("disabled ACME should be a no-op, got %v", err)
	}
}

// TestACME_IssuesWhenUnsigned: a resolved-but-never-issued cert triggers issue.
func TestACME_IssuesWhenUnsigned(t *testing.T) {
	var issued string
	p := newACMEProvider(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/acmeclient/certificates/search":
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]string{
				{"uuid": "zong", "name": "zong.trickyearlobe.com", "statusCode": ""},
			}})
		case r.URL.Path == "/api/acmeclient/certificates/issue/zong":
			issued = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})

	err := p.Apply(context.Background(), acmeSvc(map[string]string{
		annotations.ACME:    "true",
		annotations.TLSCert: "zong.trickyearlobe.com",
	}))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if issued != "/api/acmeclient/certificates/issue/zong" {
		t.Fatalf("expected issuance of unsigned cert, hit=%q", issued)
	}
}

// TestACME_SkipsWhenIssued: an already-signed cert (statusCode 200) is left to
// OPNsense auto-renewal — no issue call (issue path would t.Error).
func TestACME_SkipsWhenIssued(t *testing.T) {
	p := newACMEProvider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/acmeclient/certificates/search" {
			t.Errorf("unexpected path %s (should not issue an already-signed cert)", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]string{
			{"uuid": "wild", "name": "*.trickyearlobe.com", "statusCode": "200"},
		}})
	})

	err := p.Apply(context.Background(), acmeSvc(map[string]string{
		annotations.ACME:    "true",
		annotations.TLSCert: "*.trickyearlobe.com",
	}))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

// TestACME_FallsBackToHostname: with no tls-cert, the hostname names the cert.
func TestACME_FallsBackToHostname(t *testing.T) {
	p := newACMEProvider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/acmeclient/certificates/search" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]string{
			{"uuid": "h", "name": "app.trickyearlobe.com", "statusCode": "200"},
		}})
	})

	err := p.Apply(context.Background(), acmeSvc(map[string]string{
		annotations.ACME:     "true",
		annotations.Hostname: "app.trickyearlobe.com",
	}))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

// TestACME_MissingCertErrors: acme=true but no such cert on the box errors.
func TestACME_MissingCertErrors(t *testing.T) {
	p := newACMEProvider(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]string{}})
	})

	err := p.Apply(context.Background(), acmeSvc(map[string]string{
		annotations.ACME:    "true",
		annotations.TLSCert: "nope.trickyearlobe.com",
	}))
	if err == nil {
		t.Fatal("expected error when the named cert does not exist")
	}
}

// TestACME_NoNameErrors: acme=true without tls-cert or hostname errors.
func TestACME_NoNameErrors(t *testing.T) {
	p := &ACME{} // must fail before any client call
	err := p.Apply(context.Background(), acmeSvc(map[string]string{annotations.ACME: "true"}))
	if err == nil {
		t.Fatal("expected error when no cert name can be derived")
	}
}
