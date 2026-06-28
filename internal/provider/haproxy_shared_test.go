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

func newSharedProvider(t *testing.T, handler http.HandlerFunc) *HAProxy {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := opnsense.NewClient(opnsense.Options{BaseURL: srv.URL, Key: "k", Secret: "s"})
	return &HAProxy{opn: c, cfg: &config.Config{}, reconfigurer: NewReconfigurer(c, 0)}
}

func sharedSvc() *corev1.Service {
	s := svc("aladdin", "demo-wallet")
	s.Annotations = map[string]string{
		annotations.FrontendMode: annotations.FrontendShared,
		annotations.Frontend:     "https-443",
		annotations.Hostname:     "wallet.trickyearlobe.com",
	}
	return s
}

// TestApplySharedRouting_CreatesHostACL drives the corrected host-ACL path: the
// ACL must use expression "hdr" with the host in the hdr field (NOT the old
// host_matches), the action must use_backend the service's backend, and the
// action must be linked into the named frontend.
func TestApplySharedRouting_CreatesHostACL(t *testing.T) {
	var aclBody map[string]opnsense.ACL
	var actionBody map[string]opnsense.Action
	var feSetBody map[string]map[string]string
	p := newSharedProvider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/haproxy/settings/searchAcls":
			_ = json.NewEncoder(w).Encode(searchResp(nil))
		case "/api/haproxy/settings/addAcl":
			_ = json.NewDecoder(r.Body).Decode(&aclBody)
			_ = json.NewEncoder(w).Encode(map[string]string{"result": "saved", "uuid": "acl-uuid"})
		case "/api/haproxy/settings/searchActions":
			_ = json.NewEncoder(w).Encode(searchResp(nil))
		case "/api/haproxy/settings/addAction":
			_ = json.NewDecoder(r.Body).Decode(&actionBody)
			_ = json.NewEncoder(w).Encode(map[string]string{"result": "saved", "uuid": "action-uuid"})
		case "/api/haproxy/settings/searchFrontends":
			_ = json.NewEncoder(w).Encode(searchResp([]map[string]string{{"uuid": "fe1", "name": "https-443"}}))
		case "/api/haproxy/settings/getFrontend/fe1":
			_, _ = w.Write([]byte(`{"frontend":{"linkedActions":{}}}`))
		case "/api/haproxy/settings/setFrontend/fe1":
			_ = json.NewDecoder(r.Body).Decode(&feSetBody)
			_ = json.NewEncoder(w).Encode(map[string]string{"result": "saved"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})

	if err := p.applyRouting(context.Background(), sharedSvc(), "backend-uuid"); err != nil {
		t.Fatalf("applyRouting: %v", err)
	}

	if opnsense.ACLExprHostMatch != "hdr" {
		t.Fatalf("ACLExprHostMatch = %q, want hdr", opnsense.ACLExprHostMatch)
	}
	acl := aclBody["acl"]
	if acl.Expression != "hdr" {
		t.Errorf("acl expression = %q, want hdr", acl.Expression)
	}
	if acl.Hdr != "wallet.trickyearlobe.com" {
		t.Errorf("acl hdr = %q, want the hostname", acl.Hdr)
	}
	act := actionBody["action"]
	if act.Type != "use_backend" || act.UseBackend != "backend-uuid" || act.LinkedAcls != "acl-uuid" {
		t.Errorf("action wrong: %+v", act)
	}
	if got := feSetBody["frontend"]["linkedActions"]; got != "action-uuid" {
		t.Errorf("frontend linkedActions = %q, want action-uuid", got)
	}
}

// TestApplySharedRouting_Validation: shared mode needs both frontend + hostname.
func TestApplySharedRouting_Validation(t *testing.T) {
	p := &HAProxy{}
	s := svc("aladdin", "demo-wallet")
	s.Annotations = map[string]string{annotations.FrontendMode: annotations.FrontendShared}
	if err := p.applyRouting(context.Background(), s, "b"); err == nil {
		t.Error("expected error when frontend/hostname are missing in shared mode")
	}
}
