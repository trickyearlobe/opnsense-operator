// Package config loads controller settings from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds everything the controller needs to start.
type Config struct {
	// OPNsense connection.
	OPNsenseURL      string
	OPNsenseKey      string
	OPNsenseSecret   string
	OPNsenseInsecure bool

	// DNSDomain is the domain used when building Unbound/dnsmasq host overrides.
	DNSDomain string

	// DNSDefaultBackend selects the DNS mechanism when a Service enables DNS but
	// does not pick one via the dns-backend annotation: "ddclient" (default,
	// external provider via os-ddclient), "unbound", or "dnsmasq".
	DNSDefaultBackend string

	// DDClientAccount is the description of the os-ddclient (dyndns) account whose
	// hostnames the operator manages. The account itself (service, credentials,
	// zone) is configured on the firewall; the operator only adds/removes service
	// hostnames to it. Required when the ddclient backend is used.
	DDClientAccount string

	// FrontendBindAddress is the listen address for operator-created "dedicated"
	// frontends. Defaults to "0.0.0.0" (all interfaces); set to a specific
	// address to restrict which interface the frontend binds.
	FrontendBindAddress string

	// FirewallRuleAPI selects which OPNsense firewall-rule API the firewall
	// provider drives: "automation" (default, the validated os-firewall
	// Automation/Filter API) or "rules-new" (the new core API, not yet wired).
	FirewallRuleAPI string

	// WANInterface is the OPNsense interface key for WAN pass rules (e.g. "wan").
	// This is operator policy, never annotation-driven, so a Service can never
	// pick which interface gets opened.
	WANInterface string

	// WANAllowedPorts bounds which ports an expose-wan annotation may open, as an
	// inclusive "min-max" range (e.g. "9000-9099"). Empty denies every port, so a
	// stray annotation cannot open anything unless the operator opts into a range.
	WANAllowedPorts string

	// ReconfigureDebounce coalesces a burst of changes into one haproxy reload.
	ReconfigureDebounce time.Duration

	// ResyncPeriod forces a periodic full reconciliation to heal drift.
	ResyncPeriod time.Duration

	// MetricsAddr / ProbeAddr for controller-runtime servers.
	MetricsAddr string
	ProbeAddr   string
}

// FromEnv builds a Config, returning an error if required values are missing.
func FromEnv() (*Config, error) {
	c := &Config{
		OPNsenseURL:         os.Getenv("OPNSENSE_URL"),
		OPNsenseKey:         os.Getenv("OPNSENSE_KEY"),
		OPNsenseSecret:      os.Getenv("OPNSENSE_SECRET"),
		OPNsenseInsecure:    envBool("OPNSENSE_INSECURE", false),
		DNSDomain:           envStr("DNS_DOMAIN", "lan"),
		DNSDefaultBackend:   envStr("DNS_BACKEND", "ddclient"),
		DDClientAccount:     envStr("DDCLIENT_ACCOUNT", ""),
		FrontendBindAddress: envStr("FRONTEND_BIND_ADDRESS", "0.0.0.0"),
		FirewallRuleAPI:     envStr("FIREWALL_RULE_API", "automation"),
		WANInterface:        envStr("WAN_INTERFACE", "wan"),
		WANAllowedPorts:     envStr("WAN_ALLOWED_PORTS", ""),
		ReconfigureDebounce: envDuration("RECONFIGURE_DEBOUNCE", 2*time.Second),
		ResyncPeriod:        envDuration("RESYNC_PERIOD", 10*time.Minute),
		MetricsAddr:         envStr("METRICS_ADDR", ":8080"),
		ProbeAddr:           envStr("PROBE_ADDR", ":8081"),
	}

	var missing []string
	if c.OPNsenseURL == "" {
		missing = append(missing, "OPNSENSE_URL")
	}
	if c.OPNsenseKey == "" {
		missing = append(missing, "OPNSENSE_KEY")
	}
	if c.OPNsenseSecret == "" {
		missing = append(missing, "OPNSENSE_SECRET")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %v", missing)
	}
	return c, nil
}

// WANPortAllowed reports whether port may be opened on the WAN by an expose-wan
// annotation. The empty/invalid range denies everything: WAN exposure is opt-in
// at the operator level, so a stray annotation cannot open a port unless a valid
// range is configured.
func (c *Config) WANPortAllowed(port int) bool {
	lo, hi, ok := c.wanPortRange()
	return ok && port >= lo && port <= hi
}

// wanPortRange parses WANAllowedPorts ("min-max", or a single "port") into an
// inclusive range. ok is false when unset or malformed.
func (c *Config) wanPortRange() (lo, hi int, ok bool) {
	s := strings.TrimSpace(c.WANAllowedPorts)
	if s == "" {
		return 0, 0, false
	}
	loStr, hiStr, found := strings.Cut(s, "-")
	lo, err := strconv.Atoi(strings.TrimSpace(loStr))
	if err != nil {
		return 0, 0, false
	}
	hi = lo
	if found {
		hi, err = strconv.Atoi(strings.TrimSpace(hiStr))
		if err != nil {
			return 0, 0, false
		}
	}
	if lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, false
	}
	return lo, hi, true
}

func envStr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
