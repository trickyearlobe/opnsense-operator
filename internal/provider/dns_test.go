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

func newDNSProvider(t *testing.T, cfg *config.Config, handler http.HandlerFunc) *DNS {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := opnsense.NewClient(opnsense.Options{BaseURL: srv.URL, Key: "k", Secret: "s"})
	return &DNS{opn: c, cfg: cfg, reconfigurer: NewReconfigurer(c, 0)}
}

// dnsSvc builds a Service with a LoadBalancer VIP so dnsAddress resolves.
func dnsSvc(anns map[string]string) *corev1.Service {
	s := svc("aladdin", "demo-wallet")
	s.Annotations = anns
	s.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "172.25.0.155"}}
	return s
}

func TestDNS_Disabled(t *testing.T) {
	p := &DNS{cfg: &config.Config{}} // nil client: any call panics
	if err := p.Apply(context.Background(), dnsSvc(map[string]string{})); err != nil {
		t.Fatalf("disabled DNS should be a no-op, got %v", err)
	}
}

func TestDNS_UnknownBackendErrors(t *testing.T) {
	p := &DNS{cfg: &config.Config{DNSDefaultBackend: "bogus"}}
	err := p.Apply(context.Background(), dnsSvc(map[string]string{
		annotations.DNS:      "true",
		annotations.Hostname: "app.trickyearlobe.com",
	}))
	if err == nil {
		t.Fatal("expected error for unknown dns-backend")
	}
}

// TestDNS_DDClientRequiresAccount: ddclient without DDCLIENT_ACCOUNT errors.
func TestDNS_DDClientRequiresAccount(t *testing.T) {
	p := &DNS{cfg: &config.Config{DNSDefaultBackend: "ddclient", DDClientAccount: ""}}
	err := p.Apply(context.Background(), dnsSvc(map[string]string{
		annotations.DNS:      "true",
		annotations.Hostname: "app.trickyearlobe.com",
	}))
	if err == nil {
		t.Fatal("expected error when DDCLIENT_ACCOUNT is unset")
	}
}

// TestDNS_DDClient_EnsuresHostname drives the ddclient path: add the FQDN to the
// operator's account.
func TestDNS_DDClient_EnsuresHostname(t *testing.T) {
	var setBody map[string]map[string]string
	p := newDNSProvider(t, &config.Config{DNSDefaultBackend: "ddclient", DDClientAccount: "Route53"},
		func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/dyndns/accounts/searchItem":
				_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]string{
					{"uuid": "acct1", "description": "Route53", "hostnames": ""},
				}})
			case "/api/dyndns/accounts/setItem/acct1":
				_ = json.NewDecoder(r.Body).Decode(&setBody)
				_ = json.NewEncoder(w).Encode(map[string]string{"result": "saved"})
			default:
				t.Errorf("unexpected path %s", r.URL.Path)
			}
		})
	err := p.Apply(context.Background(), dnsSvc(map[string]string{
		annotations.DNS:      "true",
		annotations.Hostname: "app.trickyearlobe.com",
	}))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if setBody["account"]["hostnames"] != "app.trickyearlobe.com" {
		t.Fatalf("ddclient hostnames = %q", setBody["account"]["hostnames"])
	}
}

// TestDNS_Unbound_UpsertsOverride drives the unbound path with the host split.
func TestDNS_Unbound_UpsertsOverride(t *testing.T) {
	var addBody map[string]opnsense.HostOverride
	p := newDNSProvider(t, &config.Config{DNSDomain: "lan"},
		func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/unbound/settings/searchHostOverride":
				_ = json.NewEncoder(w).Encode(map[string]any{"rows": []any{}})
			case "/api/unbound/settings/addHostOverride":
				_ = json.NewDecoder(r.Body).Decode(&addBody)
				_ = json.NewEncoder(w).Encode(map[string]string{"result": "saved", "uuid": "o1"})
			default:
				t.Errorf("unexpected path %s", r.URL.Path)
			}
		})
	err := p.Apply(context.Background(), dnsSvc(map[string]string{
		annotations.DNS:        "true",
		annotations.DNSBackend: annotations.DNSBackendUnbound,
		annotations.Hostname:   "app.trickyearlobe.com",
	}))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	h := addBody["host"]
	if h.Hostname != "app" || h.Domain != "trickyearlobe.com" || h.Server != "172.25.0.155" {
		t.Fatalf("unbound override wrong: %+v", h)
	}
}

// TestDNS_Dnsmasq_UpsertsHost drives the dnsmasq path.
func TestDNS_Dnsmasq_UpsertsHost(t *testing.T) {
	var addBody map[string]opnsense.DnsmasqHost
	p := newDNSProvider(t, &config.Config{DNSDomain: "lan"},
		func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/dnsmasq/settings/searchHost":
				_ = json.NewEncoder(w).Encode(map[string]any{"rows": []any{}})
			case "/api/dnsmasq/settings/addHost":
				_ = json.NewDecoder(r.Body).Decode(&addBody)
				_ = json.NewEncoder(w).Encode(map[string]string{"result": "saved", "uuid": "h1"})
			default:
				t.Errorf("unexpected path %s", r.URL.Path)
			}
		})
	err := p.Apply(context.Background(), dnsSvc(map[string]string{
		annotations.DNS:        "true",
		annotations.DNSBackend: annotations.DNSBackendDnsmasq,
		annotations.Hostname:   "app.trickyearlobe.com",
	}))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	h := addBody["host"]
	if h.Host != "app" || h.Domain != "trickyearlobe.com" || h.IP != "172.25.0.155" {
		t.Fatalf("dnsmasq host wrong: %+v", h)
	}
}
