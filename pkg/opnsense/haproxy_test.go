package opnsense

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeOPNsense stands in for the firewall, recording the last request body and
// returning canned responses keyed by path.
func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewClient(Options{BaseURL: srv.URL, Key: "k", Secret: "s"})
}

func TestUpsertServer_CreatesWhenAbsent(t *testing.T) {
	var addBody map[string]Server
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/haproxy/settings/searchServers":
			// No existing servers.
			_ = json.NewEncoder(w).Encode(searchResponse{Rows: nil, Total: 0})
		case "/api/haproxy/settings/addServer":
			if u, p, ok := r.BasicAuth(); !ok || u != "k" || p != "s" {
				t.Errorf("missing/incorrect basic auth: %q/%q ok=%v", u, p, ok)
			}
			_ = json.NewDecoder(r.Body).Decode(&addBody)
			_ = json.NewEncoder(w).Encode(mutationResponse{Result: "saved", UUID: "new-uuid"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})

	uuid, err := c.HAProxy().UpsertServer(context.Background(), Server{
		Name: "k8s_default_app_10-0-0-1_30080", Address: "10.0.0.1", Port: "30080", Enabled: "1",
	})
	if err != nil {
		t.Fatalf("UpsertServer: %v", err)
	}
	if uuid != "new-uuid" {
		t.Fatalf("uuid = %q, want new-uuid", uuid)
	}
	if got := addBody["server"].Address; got != "10.0.0.1" {
		t.Fatalf("posted address = %q, want 10.0.0.1", got)
	}
}

func TestUpsertServer_UpdatesWhenPresent(t *testing.T) {
	var setPath string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/haproxy/settings/searchServers":
			_ = json.NewEncoder(w).Encode(searchResponse{
				Rows:  []row{{UUID: "existing", Name: "k8s_default_app_10-0-0-1_30080"}},
				Total: 1,
			})
		case r.URL.Path == "/api/haproxy/settings/setServer/existing":
			setPath = r.URL.Path
			_ = json.NewEncoder(w).Encode(mutationResponse{Result: "saved", UUID: "existing"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})

	uuid, err := c.HAProxy().UpsertServer(context.Background(), Server{
		Name: "k8s_default_app_10-0-0-1_30080", Address: "10.0.0.1", Port: "30080", Enabled: "1",
	})
	if err != nil {
		t.Fatalf("UpsertServer: %v", err)
	}
	if uuid != "existing" || setPath != "/api/haproxy/settings/setServer/existing" {
		t.Fatalf("expected update of existing; uuid=%q path=%q", uuid, setPath)
	}
}

func TestListManagedServers_FiltersByMarker(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(searchResponse{Rows: []row{
			{UUID: "1", Name: "ours", Description: ManagedMarker + " ns=default svc=app"},
			{UUID: "2", Name: "theirs", Description: "hand-made backend"},
		}})
	})
	got, err := c.HAProxy().ListManagedServers(context.Background())
	if err != nil {
		t.Fatalf("ListManagedServers: %v", err)
	}
	if len(got) != 1 || got[0].UUID != "1" {
		t.Fatalf("expected only the managed row, got %+v", got)
	}
}

func TestValidationErrorSurfaced(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/haproxy/settings/searchServers" {
			_ = json.NewEncoder(w).Encode(searchResponse{})
			return
		}
		_ = json.NewEncoder(w).Encode(mutationResponse{
			Result:      "failed",
			Validations: map[string]any{"server.port": "invalid"},
		})
	})
	_, err := c.HAProxy().UpsertServer(context.Background(), Server{Name: "x"})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}
