// Package annotations defines the Service annotation contract that drives the
// controller. Keeping the keys and parsing in one place makes the API surface
// explicit and easy to evolve.
package annotations

import (
	corev1 "k8s.io/api/core/v1"
)

// Group is the DNS-style prefix for every annotation and the finalizer this
// operator owns. Defining it once means all keys move together and never clash
// with other operators. It also serves as the API group for a future
// OPNsenseRoute CRD. All keys below are derived from it as compile-time
// constants (untyped string concatenation).
const Group = "opnsense-operator.k8s.local"

const (
	// Expose toggles management of a Service. Must be "true" to opt in.
	Expose = Group + "/expose"

	// Mode is the backend mode: "http" (default) or "tcp".
	Mode = Group + "/backend-mode"

	// Hostname is the HTTP Host the public frontend should route to this
	// backend (used for the ACL and, if set, the Unbound override / ACME SAN).
	Hostname = Group + "/hostname"

	// UpstreamStrategy selects how upstream targets are derived:
	//   "loadbalancer" (default) – read the VIP from .status.loadBalancer.ingress
	//   "nodeport"               – every Ready node IP + the Service NodePort
	//   "vip"                    – a fixed address given by UpstreamAddress
	UpstreamStrategy = Group + "/upstream-strategy"

	// UpstreamAddress is the target when strategy is "vip" (e.g. a fixed address
	// that is not this Service's own LoadBalancer IP).
	UpstreamAddress = Group + "/upstream-address"

	// UpstreamPort overrides the port used for the "vip"/"loadbalancer"
	// strategies. Defaults to the Service's first port.
	UpstreamPort = Group + "/upstream-port"

	// Frontend is the name of an existing HAProxy public frontend to attach a
	// host-matching ACL + use_backend action to. Empty means "manage the
	// backend/servers only" (bind to a frontend yourself in the GUI).
	Frontend = Group + "/frontend"

	// DNS, when "true", maintains an Unbound host override for Hostname.
	DNS = Group + "/dns"

	// ACME, when "true", ensures the cert for Hostname exists and issues/renews
	// it via os-acme-client.
	ACME = Group + "/acme"

	// FrontendMode selects how the public frontend is provided:
	//   "dedicated" – operator creates a frontend on ListenPort with TLSCert
	//   "shared"    – operator attaches a host ACL to the existing Frontend, and
	//                 (if TLSCert is set) additively binds that cert to it so the
	//                 shared frontend presents a valid certificate for this SNI host
	FrontendMode = Group + "/frontend-mode"

	// ListenPort is the bind port for a "dedicated" frontend.
	ListenPort = Group + "/listen-port"

	// TLSCert names the certificate to bind, by CN/description (e.g.
	// "*.trickyearlobe.com"). Resolved to a refid internally.
	TLSCert = Group + "/tls-cert"

	// DNSBackend selects the DNS mechanism when DNS is enabled:
	//   "ddclient" | "unbound" | "dnsmasq"
	DNSBackend = Group + "/dns-backend"

	// ExposeWAN, when "true", opens a WAN firewall rule for ListenPort (subject
	// to the operator's allowed-port range).
	ExposeWAN = Group + "/expose-wan"

	// Finalizer guards a managed Service so firewall objects are cleaned up
	// before it disappears.
	Finalizer = Group + "/cleanup"
)

// Frontend modes.
const (
	FrontendDedicated = "dedicated"
	FrontendShared    = "shared"
)

// DNS backends.
const (
	DNSBackendDDClient = "ddclient"
	DNSBackendUnbound  = "unbound"
	DNSBackendDnsmasq  = "dnsmasq"
)

// Strategy enumerates upstream derivation modes.
type Strategy string

const (
	StrategyLoadBalancer Strategy = "loadbalancer"
	StrategyNodePort     Strategy = "nodeport"
	StrategyVIP          Strategy = "vip"
)

// IsExposed reports whether the Service opts into management.
func IsExposed(svc *corev1.Service) bool {
	return svc.Annotations[Expose] == "true"
}

// Get returns an annotation value or a fallback.
func Get(svc *corev1.Service, key, fallback string) string {
	if v, ok := svc.Annotations[key]; ok && v != "" {
		return v
	}
	return fallback
}

// Bool returns a boolean annotation, defaulting to false.
func Bool(svc *corev1.Service, key string) bool {
	return svc.Annotations[key] == "true"
}
