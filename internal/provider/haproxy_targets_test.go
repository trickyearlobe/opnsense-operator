package provider

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/trickyearlobe/opnsense-operator/internal/annotations"
)

func svc(ns, name string) *corev1.Service {
	return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
}

func TestNaming(t *testing.T) {
	s := svc("default", "my-app")
	if got, want := backendName(s), "k8s_default_my-app"; got != want {
		t.Errorf("backendName = %q, want %q", got, want)
	}
	tg := target{Address: "10.0.0.1", Port: 30080}
	if got, want := serverName(s, tg), "k8s_default_my-app_10.0.0.1_30080"; got != want {
		t.Errorf("serverName = %q, want %q", got, want)
	}
	if got := serverName(s, tg); got[:len(serverNamePrefix(s))] != serverNamePrefix(s) {
		t.Errorf("serverName %q missing prefix %q", got, serverNamePrefix(s))
	}
	if aclName(s) == actionName(s) {
		t.Errorf("acl and action names must differ")
	}
}

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"abc":          "abc",
		"a_b/c":        "a-b-c",
		"ns:weird*key": "ns-weird-key",
		"10.0.0.1":     "10.0.0.1",
	}
	for in, want := range cases {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitHost(t *testing.T) {
	if h, d := splitHost("app.example.com", "lan"); h != "app" || d != "example.com" {
		t.Errorf("splitHost full = %q/%q", h, d)
	}
	if h, d := splitHost("app", "lan"); h != "app" || d != "lan" {
		t.Errorf("splitHost bare = %q/%q", h, d)
	}
}

func TestLoadBalancerIP(t *testing.T) {
	s := svc("default", "app")
	if loadBalancerIP(s) != "" {
		t.Error("expected empty when no ingress")
	}
	s.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "192.0.2.45"}}
	if got := loadBalancerIP(s); got != "192.0.2.45" {
		t.Errorf("loadBalancerIP = %q", got)
	}
}

func TestUpstreamPort(t *testing.T) {
	s := svc("default", "app")
	s.Spec.Ports = []corev1.ServicePort{{Port: 8080}}
	if p, _ := upstreamPort(s); p != 8080 {
		t.Errorf("default port = %d, want 8080", p)
	}
	s.Annotations = map[string]string{annotations.UpstreamPort: "443"}
	if p, _ := upstreamPort(s); p != 443 {
		t.Errorf("override port = %d, want 443", p)
	}
}

// TestUpstreamTargets_LoadBalancer covers the default loadbalancer path: read the
// VIP straight from Service status, no annotations beyond expose.
func TestUpstreamTargets_LoadBalancer(t *testing.T) {
	p := &HAProxy{}
	s := svc("default", "web")
	s.Spec.Ports = []corev1.ServicePort{{Port: 8080}}
	s.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "192.0.2.45"}}

	got, err := p.upstreamTargets(nil, s)
	if err != nil {
		t.Fatalf("upstreamTargets: %v", err)
	}
	if len(got) != 1 || got[0].Address != "192.0.2.45" || got[0].Port != 8080 {
		t.Fatalf("targets = %+v", got)
	}
}

func TestUpstreamTargets_LoadBalancer_PendingVIP(t *testing.T) {
	p := &HAProxy{}
	s := svc("default", "web")
	s.Spec.Ports = []corev1.ServicePort{{Port: 8080}}
	// No ingress IP yet → no targets, no error (controller requeues).
	got, err := p.upstreamTargets(nil, s)
	if err != nil || got != nil {
		t.Fatalf("expected (nil,nil) while VIP pending, got (%+v,%v)", got, err)
	}
}

func TestNodeHelpers(t *testing.T) {
	n := &corev1.Node{Status: corev1.NodeStatus{
		Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeHostName, Address: "node1"},
			{Type: corev1.NodeInternalIP, Address: "192.168.1.10"},
		},
	}}
	if !nodeReady(n) {
		t.Error("expected ready")
	}
	if nodeInternalIP(n) != "192.168.1.10" {
		t.Errorf("internalIP = %q", nodeInternalIP(n))
	}
}
