package opnsense

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// --- dnsmasq -------------------------------------------------------------

func TestDnsmasqUpsertHost_CreatesWhenAbsent(t *testing.T) {
	var addBody map[string]DnsmasqHost
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/dnsmasq/settings/searchHost":
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": []any{}})
		case "/api/dnsmasq/settings/addHost":
			_ = json.NewDecoder(r.Body).Decode(&addBody)
			_ = json.NewEncoder(w).Encode(mutationResponse{Result: "saved", UUID: "h1"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	uuid, err := c.Dnsmasq().UpsertHost(context.Background(), DnsmasqHost{Host: "app", Domain: "trickyearlobe.com", IP: "172.25.0.155", Descr: "d"})
	if err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}
	if uuid != "h1" {
		t.Fatalf("uuid = %q", uuid)
	}
	if got := addBody["host"]; got.Host != "app" || got.IP != "172.25.0.155" {
		t.Errorf("posted host wrong: %+v", got)
	}
}

func TestDnsmasqFindHost_MatchesHostDomain(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]string{
			{"uuid": "a", "host": "other", "domain": "trickyearlobe.com"},
			{"uuid": "b", "host": "app", "domain": "trickyearlobe.com"},
		}})
	})
	uuid, err := c.Dnsmasq().FindHost(context.Background(), "app", "trickyearlobe.com")
	if err != nil {
		t.Fatalf("FindHost: %v", err)
	}
	if uuid != "b" {
		t.Fatalf("uuid = %q, want b", uuid)
	}
}

// --- ddclient (dyndns) ---------------------------------------------------

func TestDynDNSEnsureHostname_AddsWhenAbsent(t *testing.T) {
	var setBody map[string]map[string]string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/dyndns/accounts/searchItem":
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]string{
				{"uuid": "acct1", "description": "Route53", "hostnames": "a.example.com", "enabled": "1"},
			}})
		case "/api/dyndns/accounts/setItem/acct1":
			_ = json.NewDecoder(r.Body).Decode(&setBody)
			_ = json.NewEncoder(w).Encode(mutationResponse{Result: "saved"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	changed, err := c.DynDNS().EnsureHostname(context.Background(), "Route53", "b.example.com")
	if err != nil {
		t.Fatalf("EnsureHostname: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}
	// Partial update: only hostnames, and it must include both old + new.
	got := setBody["account"]
	if len(got) != 1 || got["hostnames"] != "a.example.com,b.example.com" {
		t.Fatalf("partial setItem wrong: %+v", got)
	}
}

func TestDynDNSEnsureHostname_NoopWhenPresent(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/dyndns/accounts/searchItem" {
			t.Errorf("must not setItem when already present; got %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]string{
			{"uuid": "acct1", "description": "Route53", "hostnames": "a.example.com,b.example.com"},
		}})
	})
	changed, err := c.DynDNS().EnsureHostname(context.Background(), "Route53", "b.example.com")
	if err != nil {
		t.Fatalf("EnsureHostname: %v", err)
	}
	if changed {
		t.Fatal("expected changed=false when hostname already present")
	}
}

func TestDynDNSEnsureHostname_MissingAccountErrors(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]string{
			{"uuid": "acct1", "description": "SomethingElse", "hostnames": ""},
		}})
	})
	if _, err := c.DynDNS().EnsureHostname(context.Background(), "Route53", "b.example.com"); err == nil {
		t.Fatal("expected error for missing account")
	}
}

func TestDynDNSRemoveHostname(t *testing.T) {
	var setBody map[string]map[string]string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/dyndns/accounts/searchItem":
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]string{
				{"uuid": "acct1", "description": "Route53", "hostnames": "a.example.com,b.example.com"},
			}})
		case "/api/dyndns/accounts/setItem/acct1":
			_ = json.NewDecoder(r.Body).Decode(&setBody)
			_ = json.NewEncoder(w).Encode(mutationResponse{Result: "saved"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	changed, err := c.DynDNS().RemoveHostname(context.Background(), "Route53", "a.example.com")
	if err != nil {
		t.Fatalf("RemoveHostname: %v", err)
	}
	if !changed || setBody["account"]["hostnames"] != "b.example.com" {
		t.Fatalf("expected removal leaving b only; changed=%v body=%+v", changed, setBody)
	}
}
