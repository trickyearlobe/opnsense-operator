// Package config loads controller settings from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds everything the controller needs to start.
type Config struct {
	// OPNsense connection.
	OPNsenseURL      string
	OPNsenseKey      string
	OPNsenseSecret   string
	OPNsenseInsecure bool

	// DNSDomain is the domain used when building Unbound host overrides.
	DNSDomain string

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
