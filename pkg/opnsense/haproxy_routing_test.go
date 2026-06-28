package opnsense

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestCSVHelpers(t *testing.T) {
	if got := appendCSV("a,b", "c"); got != "a,b,c" {
		t.Errorf("appendCSV = %q", got)
	}
	if got := appendCSV("a,b", "b"); got != "a,b" {
		t.Errorf("appendCSV dup = %q", got)
	}
	if got := appendCSV("", "a"); got != "a" {
		t.Errorf("appendCSV empty = %q", got)
	}
	if got := removeCSV("a,b,c", "b"); got != "a,c" {
		t.Errorf("removeCSV = %q", got)
	}
	if !csvContains("a,b,c", "b") || csvContains("a,b,c", "z") {
		t.Errorf("csvContains wrong")
	}
}

// AttachActionToFrontend must read the frontend's currently-selected actions and
// POST back the union including the new UUID.
func TestAttachActionToFrontend(t *testing.T) {
	var setBody map[string]map[string]string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/haproxy/settings/searchFrontends":
			_ = json.NewEncoder(w).Encode(searchResponse{
				Rows: []row{{UUID: "fe1", Name: "https-443"}}, Total: 1,
			})
		case "/api/haproxy/settings/getFrontend/fe1":
			// Existing action "old" already selected.
			_, _ = w.Write([]byte(`{"frontend":{"linkedActions":{"old":{"selected":1},"other":{"selected":0}}}}`))
		case "/api/haproxy/settings/setFrontend/fe1":
			_ = json.NewDecoder(r.Body).Decode(&setBody)
			_ = json.NewEncoder(w).Encode(mutationResponse{Result: "saved"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})

	changed, err := c.HAProxy().AttachActionToFrontend(context.Background(), "https-443", "new")
	if err != nil {
		t.Fatalf("AttachActionToFrontend: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}
	got := setBody["frontend"]["linkedActions"]
	if !csvContains(got, "old") || !csvContains(got, "new") {
		t.Fatalf("linkedActions = %q, want old+new", got)
	}
}

func TestAttachActionToFrontend_AlreadyLinked(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/haproxy/settings/searchFrontends":
			_ = json.NewEncoder(w).Encode(searchResponse{Rows: []row{{UUID: "fe1", Name: "f"}}})
		case "/api/haproxy/settings/getFrontend/fe1":
			_, _ = w.Write([]byte(`{"frontend":{"linkedActions":{"act":{"selected":1}}}}`))
		default:
			t.Errorf("must not POST setFrontend when already linked; got %s", r.URL.Path)
		}
	})
	changed, err := c.HAProxy().AttachActionToFrontend(context.Background(), "f", "act")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if changed {
		t.Fatal("expected changed=false when already linked")
	}
}
