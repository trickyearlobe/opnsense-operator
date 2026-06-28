package opnsense

import "context"

// Unbound wraps the OPNsense core DNS resolver (Unbound) host-override API.
//
// For "dynamic DNS" in the sense of giving an exposed Service a stable internal
// name, the simplest robust mechanism is an Unbound host override mapping a
// hostname to the frontend/VIP address. (The os-ddclient plugin is the right
// tool when you need to push records to an *external* DDNS provider; this MVP
// targets the firewall's own resolver, which covers the LAN-facing case.)
func (c *Client) Unbound() *Unbound { return &Unbound{c: c} }

// Unbound is the core Unbound host-override API surface.
type Unbound struct{ c *Client }

// HostOverride maps a hostname to an address in the firewall's resolver.
type HostOverride struct {
	UUID        string `json:"-"`
	Enabled     string `json:"enabled"`
	Hostname    string `json:"hostname"`
	Domain      string `json:"domain"`
	Server      string `json:"server"` // the IP the name resolves to
	Description string `json:"description"`
}

// FindHostOverride returns the UUID of a host override by hostname.domain, or "".
func (u *Unbound) FindHostOverride(ctx context.Context, hostname, domain string) (string, error) {
	var resp searchResponse
	if err := u.c.post(ctx, "/api/unbound/settings/searchHostOverride", map[string]any{"current": 1, "rowCount": -1}, &resp); err != nil {
		return "", err
	}
	want := hostname + "." + domain
	for _, r := range resp.Rows {
		// Unbound's search rows expose the joined name in Name for overrides.
		if r.Name == want {
			return r.UUID, nil
		}
	}
	return "", nil
}

// UpsertHostOverride creates or updates a host override and returns its UUID.
func (u *Unbound) UpsertHostOverride(ctx context.Context, h HostOverride) (string, error) {
	uuid, err := u.FindHostOverride(ctx, h.Hostname, h.Domain)
	if err != nil {
		return "", err
	}
	body := map[string]HostOverride{"host": h}
	var resp mutationResponse
	if uuid == "" {
		if err := u.c.post(ctx, "/api/unbound/settings/addHostOverride", body, &resp); err != nil {
			return "", err
		}
		return resp.UUID, resp.err("addHostOverride")
	}
	if err := u.c.post(ctx, "/api/unbound/settings/setHostOverride/"+uuid, body, &resp); err != nil {
		return "", err
	}
	return uuid, resp.err("setHostOverride")
}

// DeleteHostOverride removes a host override by UUID.
func (u *Unbound) DeleteHostOverride(ctx context.Context, uuid string) error {
	var resp mutationResponse
	if err := u.c.post(ctx, "/api/unbound/settings/delHostOverride/"+uuid, map[string]any{}, &resp); err != nil {
		return err
	}
	return resp.err("delHostOverride")
}

// Reconfigure applies pending Unbound changes.
func (u *Unbound) Reconfigure(ctx context.Context) error {
	return u.c.post(ctx, "/api/unbound/service/reconfigure", map[string]any{}, nil)
}
