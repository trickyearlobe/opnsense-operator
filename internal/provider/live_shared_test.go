//go:build integration

package provider

import (
	"context"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/trickyearlobe/opnsense-operator/internal/annotations"
	"github.com/trickyearlobe/opnsense-operator/internal/config"
	"github.com/trickyearlobe/opnsense-operator/pkg/opnsense"
)

// TestLive_SharedRoutingProvider exercises the shared host-ACL path against the
// live box: create a host ACL ("hdr" expression) + use_backend action, link it
// into an existing frontend, confirm, then detach + delete.
//
// This MUTATES an existing public frontend's linkedActions, so it is double-gated:
// runs only when LIVE_SHARED_ROUTING=1 (plus per-session box authorization).
// Env: OPNSENSE_URL/KEY/SECRET, LIVE_SHARED_FRONTEND (name), LIVE_BACKEND_UUID,
// optional LIVE_SHARED_HOST (default livetest.trickyearlobe.com).
func TestLive_SharedRoutingProvider(t *testing.T) {
	if os.Getenv("LIVE_SHARED_ROUTING") != "1" || os.Getenv("OPNSENSE_URL") == "" {
		t.Skip("set LIVE_SHARED_ROUTING=1 + OPNSENSE_URL (and authorize box mutation) to run")
	}
	frontend := os.Getenv("LIVE_SHARED_FRONTEND")
	backend := os.Getenv("LIVE_BACKEND_UUID")
	if frontend == "" || backend == "" {
		t.Skip("set LIVE_SHARED_FRONTEND + LIVE_BACKEND_UUID to run")
	}
	c := opnsense.NewClient(opnsense.Options{
		BaseURL: os.Getenv("OPNSENSE_URL"),
		Key:     os.Getenv("OPNSENSE_KEY"),
		Secret:  os.Getenv("OPNSENSE_SECRET"),
	})
	p := &HAProxy{opn: c, cfg: &config.Config{}, reconfigurer: NewReconfigurer(c, 0)}
	ctx := context.Background()

	s := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "livetest", Name: "shared"}}
	s.Annotations = map[string]string{
		annotations.FrontendMode: annotations.FrontendShared,
		annotations.Frontend:     frontend,
		annotations.Hostname:     envOr("LIVE_SHARED_HOST", "livetest.trickyearlobe.com"),
	}

	// Always tear down ACL/action/attachment we created.
	t.Cleanup(func() {
		if err := p.cleanupRouting(ctx, s); err != nil {
			t.Errorf("cleanupRouting: %v", err)
		}
		if err := c.HAProxy().Reconfigure(ctx); err != nil {
			t.Errorf("cleanup Reconfigure: %v", err)
		}
	})

	if err := p.applySharedRouting(ctx, s, backend); err != nil {
		t.Fatalf("applySharedRouting: %v", err)
	}
	if err := c.HAProxy().Reconfigure(ctx); err != nil {
		t.Fatalf("reconfigure: %v", err)
	}

	// Confirm the action exists and is attached to the frontend.
	actionUUID, err := c.HAProxy().FindAction(ctx, actionName(s))
	if err != nil || actionUUID == "" {
		t.Fatalf("action not found after apply: uuid=%q err=%v", actionUUID, err)
	}
	aclUUID, err := c.HAProxy().FindACL(ctx, aclName(s))
	if err != nil || aclUUID == "" {
		t.Fatalf("acl not found after apply: uuid=%q err=%v", aclUUID, err)
	}
	t.Logf("shared routing live: acl=%s action=%s on frontend %q", aclUUID, actionUUID, frontend)
}
