package opnsense

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// FirewallRule is a minimal, API-agnostic firewall rule. Providers build these
// in friendly terms; each FirewallRules implementation maps them onto its
// concrete OPNsense endpoint and field names. Rules are keyed by Description,
// which embeds the managed marker so we only ever touch our own objects.
type FirewallRule struct {
	UUID            string
	Enabled         bool
	Action          string // "pass" | "block" | "reject"
	Interface       string // OPNsense interface key, e.g. "wan"
	Direction       string // "in" | "out"
	IPProtocol      string // "inet" | "inet6" | "inet46"
	Protocol        string // "TCP" | "UDP" | "TCP/UDP" | "any" | ...
	SourceNet       string // "any" | CIDR | alias
	DestinationNet  string // "any" | "(self)" | CIDR | alias
	DestinationPort string // single port, range, or alias; "" = any
	Description     string // match key; must contain ManagedMarker
}

// FirewallRules is the seam over OPNsense's two firewall-rule APIs.
//
// OPNsense is migrating its core ruleset from the os-firewall plugin's
// Automation/Filter API (/api/firewall/filter/*) to a new core ("rules(new)")
// API with a different endpoint, field set, and apply semantics. Callers select
// an implementation by name so the operator can follow that migration without a
// code change. Every method is idempotent and matches rules by exact Description.
type FirewallRules interface {
	// API names the concrete implementation (FirewallAPIAutomation | …RulesNew).
	API() string
	// FindByDescription returns the UUID of the rule whose description matches
	// exactly, or "" if none does.
	FindByDescription(ctx context.Context, description string) (string, error)
	// ListManaged returns every rule this controller owns (marker in description).
	ListManaged(ctx context.Context) ([]Row, error)
	// Upsert creates or updates the rule keyed by its Description; returns UUID.
	Upsert(ctx context.Context, r FirewallRule) (string, error)
	// Delete removes a rule by UUID.
	Delete(ctx context.Context, uuid string) error
	// Apply commits staged rule changes (regenerate ruleset + reload pf).
	Apply(ctx context.Context) error
}

// Firewall-rule API identifiers (the FIREWALL_RULE_API config values).
const (
	FirewallAPIAutomation = "automation"
	FirewallAPIRulesNew   = "rules-new"
)

// FirewallRules selects a firewall-rule implementation by API name. The empty
// string and "automation" both yield the validated Automation/Filter API.
func (c *Client) FirewallRules(api string) (FirewallRules, error) {
	switch api {
	case "", FirewallAPIAutomation:
		return &automationFilter{c: c}, nil
	case FirewallAPIRulesNew:
		return &rulesNew{c: c}, nil
	default:
		return nil, fmt.Errorf("unknown firewall rule API %q (want %q or %q)",
			api, FirewallAPIAutomation, FirewallAPIRulesNew)
	}
}

// --- Automation/Filter implementation ------------------------------------
//
// automationFilter drives the os-firewall plugin (Firewall > Automation >
// Filter) at /api/firewall/filter/*. The field set was validated live via
// getRule against the target box: select fields take the bare option key as a
// string, booleans are "0"/"1", and create is a minimal addRule (OPNsense fills
// every field we omit with its documented default).
type automationFilter struct{ c *Client }

func (a *automationFilter) API() string { return FirewallAPIAutomation }

// filterRuleWire is the addRule/setRule payload — only the fields a WAN pass
// rule needs. quick=1 makes the rule terminating, matching a normal pass rule.
type filterRuleWire struct {
	Enabled         string `json:"enabled"`
	Action          string `json:"action"`
	Quick           string `json:"quick"`
	Interface       string `json:"interface"`
	Direction       string `json:"direction"`
	IPProtocol      string `json:"ipprotocol"`
	Protocol        string `json:"protocol"`
	SourceNet       string `json:"source_net"`
	DestinationNet  string `json:"destination_net"`
	DestinationPort string `json:"destination_port"`
	Description     string `json:"description"`
}

func (a *automationFilter) wire(r FirewallRule) filterRuleWire {
	return filterRuleWire{
		Enabled:         boolField(r.Enabled),
		Action:          r.Action,
		Quick:           "1",
		Interface:       r.Interface,
		Direction:       r.Direction,
		IPProtocol:      r.IPProtocol,
		Protocol:        r.Protocol,
		SourceNet:       r.SourceNet,
		DestinationNet:  r.DestinationNet,
		DestinationPort: r.DestinationPort,
		Description:     r.Description,
	}
}

func (a *automationFilter) search(ctx context.Context) ([]Row, error) {
	var resp searchResponse
	if err := a.c.post(ctx, "/api/firewall/filter/searchRule", map[string]any{"current": 1, "rowCount": -1}, &resp); err != nil {
		return nil, err
	}
	return resp.Rows, nil
}

func (a *automationFilter) FindByDescription(ctx context.Context, description string) (string, error) {
	rows, err := a.search(ctx)
	if err != nil {
		return "", err
	}
	for _, r := range rows {
		if r.Description == description {
			return r.UUID, nil
		}
	}
	return "", nil
}

func (a *automationFilter) ListManaged(ctx context.Context) ([]Row, error) {
	rows, err := a.search(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Row, 0, len(rows))
	for _, r := range rows {
		if strings.Contains(r.Description, ManagedMarker) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (a *automationFilter) Upsert(ctx context.Context, r FirewallRule) (string, error) {
	uuid, err := a.FindByDescription(ctx, r.Description)
	if err != nil {
		return "", err
	}
	body := map[string]filterRuleWire{"rule": a.wire(r)}
	var resp mutationResponse
	if uuid == "" {
		if err := a.c.post(ctx, "/api/firewall/filter/addRule", body, &resp); err != nil {
			return "", err
		}
		return resp.UUID, resp.err("addRule")
	}
	if err := a.c.post(ctx, "/api/firewall/filter/setRule/"+uuid, body, &resp); err != nil {
		return "", err
	}
	return uuid, resp.err("setRule")
}

func (a *automationFilter) Delete(ctx context.Context, uuid string) error {
	var resp mutationResponse
	if err := a.c.post(ctx, "/api/firewall/filter/delRule/"+uuid, map[string]any{}, &resp); err != nil {
		return err
	}
	return resp.err("delRule")
}

// Apply commits the ruleset. The filter apply returns {"status":"OK\n..."} on
// success (note the os-firewall plugin uses "OK", not haproxy's "ok").
func (a *automationFilter) Apply(ctx context.Context) error {
	var resp struct {
		Status string `json:"status"`
	}
	if err := a.c.post(ctx, "/api/firewall/filter/apply", map[string]any{}, &resp); err != nil {
		return err
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(resp.Status)), "ok") {
		return fmt.Errorf("firewall apply status=%q", resp.Status)
	}
	return nil
}

// --- rules(new) placeholder ----------------------------------------------
//
// rulesNew is reserved for OPNsense's new core ("rules(new)") firewall API.
// That endpoint is NOT present on the validated target firmware (every
// candidate /api/firewall/* path 404s as of 2026-06-28) and its field set
// differs from the Automation API. Per the project rule — validate live before
// wiring, never assume field names carry over — we do not implement it on
// guesswork. Selecting FIREWALL_RULE_API=rules-new fails fast with a clear
// message until the endpoints are confirmed live and this is filled in.
type rulesNew struct{ c *Client }

func (r *rulesNew) API() string { return FirewallAPIRulesNew }

var errRulesNewUnimplemented = errors.New(
	"firewall rules-new API not implemented: endpoints absent on the validated firmware; " +
		"confirm /api/firewall/* paths and field set live before enabling FIREWALL_RULE_API=rules-new")

func (r *rulesNew) FindByDescription(context.Context, string) (string, error) {
	return "", errRulesNewUnimplemented
}
func (r *rulesNew) ListManaged(context.Context) ([]Row, error) { return nil, errRulesNewUnimplemented }
func (r *rulesNew) Upsert(context.Context, FirewallRule) (string, error) {
	return "", errRulesNewUnimplemented
}
func (r *rulesNew) Delete(context.Context, string) error { return errRulesNewUnimplemented }
func (r *rulesNew) Apply(context.Context) error          { return errRulesNewUnimplemented }

func boolField(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
