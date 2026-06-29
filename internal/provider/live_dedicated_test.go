//go:build integration

package provider

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/trickyearlobe/opnsense-operator/internal/annotations"
	"github.com/trickyearlobe/opnsense-operator/internal/config"
	"github.com/trickyearlobe/opnsense-operator/pkg/opnsense"
)

// TestLive_DedicatedFrontendProvider exercises the real provider code path
// against the live OPNsense box: create a dedicated TLS frontend on a spare
// port via applyDedicatedFrontend, reconfigure, verify it serves HTTP 200,
// then delete it and reconfigure. Reversible; uses no WAN rule.
//
// Env: OPNSENSE_URL/KEY/SECRET, LIVE_BACKEND_UUID, LIVE_TLS_CERT,
// LIVE_LISTEN_PORT, LIVE_VERIFY_URL.
func TestLive_DedicatedFrontendProvider(t *testing.T) {
	url := os.Getenv("OPNSENSE_URL")
	backend := os.Getenv("LIVE_BACKEND_UUID")
	if url == "" || backend == "" {
		t.Skip("set OPNSENSE_URL + LIVE_BACKEND_UUID to run")
	}
	c := opnsense.NewClient(opnsense.Options{
		BaseURL: url,
		Key:     os.Getenv("OPNSENSE_KEY"),
		Secret:  os.Getenv("OPNSENSE_SECRET"),
	})
	p := &HAProxy{
		opn:          c,
		cfg:          &config.Config{FrontendBindAddress: "0.0.0.0"},
		reconfigurer: NewReconfigurer(c, 0),
	}
	ctx := context.Background()

	s := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "livetest", Name: "wallet"}}
	s.Annotations = map[string]string{
		annotations.FrontendMode: annotations.FrontendDedicated,
		annotations.ListenPort:   envOr("LIVE_LISTEN_PORT", "9002"),
		annotations.TLSCert:      envOr("LIVE_TLS_CERT", "*.trickyearlobe.com"),
	}

	// Always clean up the frontend we own, even on failure.
	t.Cleanup(func() {
		hap := c.HAProxy()
		if uuid, err := hap.FindFrontend(ctx, frontendName(s)); err == nil && uuid != "" {
			if err := hap.DeleteFrontend(ctx, uuid); err != nil {
				t.Errorf("cleanup DeleteFrontend: %v", err)
			}
			if err := hap.Reconfigure(ctx); err != nil {
				t.Errorf("cleanup Reconfigure: %v", err)
			}
			t.Logf("cleaned up frontend %s (%s)", frontendName(s), uuid)
		}
	})

	if err := p.applyDedicatedFrontend(ctx, s, backend); err != nil {
		t.Fatalf("applyDedicatedFrontend: %v", err)
	}
	if err := c.HAProxy().Reconfigure(ctx); err != nil {
		t.Fatalf("reconfigure: %v", err)
	}
	t.Logf("created frontend %s on :%s -> backend %s", frontendName(s), s.Annotations[annotations.ListenPort], backend)

	verify := os.Getenv("LIVE_VERIFY_URL")
	if verify == "" {
		t.Log("LIVE_VERIFY_URL unset; skipping HTTP probe")
		return
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	// HAProxy may take a moment to bind the new frontend after reconfigure.
	var lastErr error
	for i := 0; i < 10; i++ {
		resp, err := client.Get(verify)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Logf("verified %s -> HTTP 200 (attempt %d)", verify, i+1)
				return
			}
			lastErr = nil
			t.Logf("attempt %d: HTTP %d", i+1, resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("verify %s never returned 200; last error: %v", verify, lastErr)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
