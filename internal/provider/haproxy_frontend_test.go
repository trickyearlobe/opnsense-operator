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

// newFrontendProvider wires an HAProxy provider to an httptest server standing
// in for OPNsense, with a zero-debounce reconfigurer.
func newFrontendProvider(t *testing.T, handler http.HandlerFunc) *HAProxy {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := opnsense.NewClient(opnsense.Options{BaseURL: srv.URL, Key: "k", Secret: "s"})
	return &HAProxy{
		opn:          c,
		cfg:          &config.Config{FrontendBindAddress: "0.0.0.0"},
		reconfigurer: NewReconfigurer(c, 0),
	}
}

func dedicatedSvc() *corev1.Service {
	s := svc("aladdin", "demo-wallet")
	s.Annotations = map[string]string{
		annotations.FrontendMode: annotations.FrontendDedicated,
		annotations.ListenPort:   "9001",
		annotations.TLSCert:      "*.trickyearlobe.com",
	}
	return s
}

// TestApplyDedicatedFrontend_CreatesWithTLS reproduces the validated :9001
// frontend: it resolves the cert name to a refid and posts a minimal SSL-offload
// addFrontend with the service's backend as the default.
func TestApplyDedicatedFrontend_CreatesWithTLS(t *testing.T) {
	var addBody map[string]opnsense.Frontend
	p := newFrontendProvider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/haproxy/settings/searchFrontends":
			_ = json.NewEncoder(w).Encode(searchResp(nil))
		case "/api/trust/cert/search":
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]string{
				{"uuid": "cert-uuid", "commonname": "*.trickyearlobe.com", "descr": "wildcard"},
			}})
		case "/api/trust/cert/get/cert-uuid":
			_ = json.NewEncoder(w).Encode(map[string]any{"cert": map[string]string{"refid": "6a3ffc9bd067d"}})
		case "/api/haproxy/settings/addFrontend":
			_ = json.NewDecoder(r.Body).Decode(&addBody)
			_ = json.NewEncoder(w).Encode(map[string]string{"result": "saved", "uuid": "fe-uuid"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})

	if err := p.applyRouting(context.Background(), dedicatedSvc(), "backend-uuid"); err != nil {
		t.Fatalf("applyRouting: %v", err)
	}

	fe := addBody["frontend"]
	if fe.Name != "k8s_aladdin_demo-wallet_fe" {
		t.Errorf("frontend name = %q", fe.Name)
	}
	if fe.Bind != "0.0.0.0:9001" {
		t.Errorf("bind = %q, want 0.0.0.0:9001", fe.Bind)
	}
	if fe.DefaultBackend != "backend-uuid" {
		t.Errorf("defaultBackend = %q", fe.DefaultBackend)
	}
	if fe.Mode != "http" {
		t.Errorf("mode = %q, want http (SSL offload)", fe.Mode)
	}
	if fe.SSLEnabled != "1" || fe.SSLCertificates != "6a3ffc9bd067d" || fe.SSLDefaultCertificate != "6a3ffc9bd067d" {
		t.Errorf("TLS not wired to refid: %+v", fe)
	}
}

// TestApplyDedicatedFrontend_NoTLS omits the cert: a plain HTTP frontend, no
// trust lookup.
func TestApplyDedicatedFrontend_NoTLS(t *testing.T) {
	var addBody map[string]opnsense.Frontend
	p := newFrontendProvider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/haproxy/settings/searchFrontends":
			_ = json.NewEncoder(w).Encode(searchResp(nil))
		case "/api/haproxy/settings/addFrontend":
			_ = json.NewDecoder(r.Body).Decode(&addBody)
			_ = json.NewEncoder(w).Encode(map[string]string{"result": "saved", "uuid": "fe-uuid"})
		default:
			t.Errorf("unexpected path %s (cert lookup should be skipped)", r.URL.Path)
		}
	})

	s := dedicatedSvc()
	delete(s.Annotations, annotations.TLSCert)
	if err := p.applyRouting(context.Background(), s, "backend-uuid"); err != nil {
		t.Fatalf("applyRouting: %v", err)
	}
	if fe := addBody["frontend"]; fe.SSLEnabled != "" {
		t.Errorf("expected no TLS, got ssl_enabled=%q", fe.SSLEnabled)
	}
}

func TestApplyDedicatedFrontend_Validation(t *testing.T) {
	// No client calls should happen on these error paths; a nil handler would
	// panic if one did.
	p := &HAProxy{cfg: &config.Config{FrontendBindAddress: "0.0.0.0"}}

	missing := svc("aladdin", "demo-wallet")
	missing.Annotations = map[string]string{annotations.FrontendMode: annotations.FrontendDedicated}
	if err := p.applyRouting(context.Background(), missing, "b"); err == nil {
		t.Error("expected error when listen-port is missing")
	}

	bad := dedicatedSvc()
	bad.Annotations[annotations.ListenPort] = "70000"
	if err := p.applyRouting(context.Background(), bad, "b"); err == nil {
		t.Error("expected error for out-of-range listen-port")
	}
}

// TestApplyRouting_BackendOnly: no frontend annotations → no routing calls.
func TestApplyRouting_BackendOnly(t *testing.T) {
	p := &HAProxy{}
	if err := p.applyRouting(context.Background(), svc("aladdin", "demo-wallet"), "b"); err != nil {
		t.Fatalf("backend-only should be a no-op, got %v", err)
	}
}

func searchResp(rows []map[string]string) map[string]any {
	return map[string]any{"rows": rows, "total": len(rows)}
}
