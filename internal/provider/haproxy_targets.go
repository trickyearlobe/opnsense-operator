package provider

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/trickyearlobe/opnsense-operator/internal/annotations"
	"github.com/trickyearlobe/opnsense-operator/pkg/opnsense"
)

// upstreamTargets resolves the stable upstreams for a Service. We never point
// haproxy at churning pod IPs — instead at the Service's LoadBalancer VIP, a
// fixed VIP, or node IPs + NodePort, so the in-cluster LB / kube-proxy owns the
// last hop.
func (p *HAProxy) upstreamTargets(ctx context.Context, svc *corev1.Service) ([]target, error) {
	strategy := annotations.Strategy(annotations.Get(svc, annotations.UpstreamStrategy, string(annotations.StrategyLoadBalancer)))

	switch strategy {
	case annotations.StrategyLoadBalancer:
		ip := loadBalancerIP(svc)
		if ip == "" {
			// VIP not assigned yet (or not a LoadBalancer Service); requeue.
			return nil, nil
		}
		port, err := upstreamPort(svc)
		if err != nil {
			return nil, err
		}
		return []target{{Address: ip, Port: port}}, nil

	case annotations.StrategyVIP:
		addr := annotations.Get(svc, annotations.UpstreamAddress, "")
		if addr == "" {
			return nil, fmt.Errorf("strategy=vip requires annotation %s", annotations.UpstreamAddress)
		}
		port, err := upstreamPort(svc)
		if err != nil {
			return nil, err
		}
		return []target{{Address: addr, Port: port}}, nil

	case annotations.StrategyNodePort:
		return p.nodePortTargets(ctx, svc)

	default:
		return nil, fmt.Errorf("unknown upstream strategy %q", strategy)
	}
}

// loadBalancerIP returns the first ingress IP from the Service status, or "".
func loadBalancerIP(svc *corev1.Service) string {
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ing.IP != "" {
			return ing.IP
		}
	}
	return ""
}

// upstreamPort is the port used by the loadbalancer/vip strategies: the
// annotation override, else the Service's first port.
func upstreamPort(svc *corev1.Service) (int32, error) {
	if p := svc.Annotations[annotations.UpstreamPort]; p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return 0, fmt.Errorf("invalid %s: %w", annotations.UpstreamPort, err)
		}
		return int32(n), nil
	}
	if len(svc.Spec.Ports) == 0 {
		return 0, fmt.Errorf("service has no ports")
	}
	return svc.Spec.Ports[0].Port, nil
}

// nodePortTargets returns (Ready node internal IP, NodePort) for every Ready node.
func (p *HAProxy) nodePortTargets(ctx context.Context, svc *corev1.Service) ([]target, error) {
	if len(svc.Spec.Ports) == 0 {
		return nil, fmt.Errorf("service has no ports")
	}
	nodePort := svc.Spec.Ports[0].NodePort
	if nodePort == 0 {
		return nil, fmt.Errorf("service %s/%s has no NodePort; set type NodePort or LoadBalancer", svc.Namespace, svc.Name)
	}

	var nodes corev1.NodeList
	if err := p.k8s.List(ctx, &nodes); err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}

	var targets []target
	for i := range nodes.Items {
		n := &nodes.Items[i]
		if !nodeReady(n) {
			continue
		}
		if ip := nodeInternalIP(n); ip != "" {
			targets = append(targets, target{Address: ip, Port: nodePort})
		}
	}
	return targets, nil
}

func nodeReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func nodeInternalIP(n *corev1.Node) string {
	for _, a := range n.Status.Addresses {
		if a.Type == corev1.NodeInternalIP {
			return a.Address
		}
	}
	return ""
}

// --- naming --------------------------------------------------------------
//
// Names embed namespace+service so objects are unambiguous and prunable, and
// stay stable across reconciles (a server name keys off address+port, not an
// ordinal, so a node going away removes exactly its server).

func backendName(svc *corev1.Service) string {
	return fmt.Sprintf("k8s_%s_%s", sanitize(svc.Namespace), sanitize(svc.Name))
}

func serverNamePrefix(svc *corev1.Service) string { return backendName(svc) + "_" }

func serverName(svc *corev1.Service, t target) string {
	return serverNamePrefix(svc) + sanitize(t.Address) + "_" + strconv.Itoa(int(t.Port))
}

func aclName(svc *corev1.Service) string      { return backendName(svc) + "_acl" }
func actionName(svc *corev1.Service) string   { return backendName(svc) + "_act" }
func frontendName(svc *corev1.Service) string { return backendName(svc) + "_fe" }

// managedDescription tags an object as owned by this controller for a given
// Service, so ListManaged* can find it and pruning can be scoped safely.
func managedDescription(svc *corev1.Service) string {
	return fmt.Sprintf("%s ns=%s svc=%s", opnsense.ManagedMarker, svc.Namespace, svc.Name)
}

// sanitize maps identifiers to the [A-Za-z0-9._-] set OPNsense accepts for
// object names, replacing everything else with '-'.
func sanitize(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-':
			b.WriteRune(c)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}
