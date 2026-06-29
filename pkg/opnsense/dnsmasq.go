package opnsense

import "context"

// Dnsmasq wraps the os-dnsmasq host-entry API (an alternative local resolver to
// Unbound). A host entry maps host.domain to an address on the firewall's
// dnsmasq, the same internal-resolution role as an Unbound host override.
func (c *Client) Dnsmasq() *Dnsmasq { return &Dnsmasq{c: c} }

// Dnsmasq is the os-dnsmasq settings API surface.
type Dnsmasq struct{ c *Client }

// DnsmasqHost is an A-record host entry. Field names validated live via getHost
// (note: the description field is "descr", not "description").
type DnsmasqHost struct {
	UUID   string `json:"-"`
	Host   string `json:"host"`
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Descr  string `json:"descr"`
}

type dnsmasqHostRow struct {
	UUID   string `json:"uuid"`
	Host   string `json:"host"`
	Domain string `json:"domain"`
	Descr  string `json:"descr"`
}

func (d *Dnsmasq) searchHosts(ctx context.Context) ([]dnsmasqHostRow, error) {
	var resp struct {
		Rows []dnsmasqHostRow `json:"rows"`
	}
	if err := d.c.post(ctx, "/api/dnsmasq/settings/searchHost", map[string]any{"current": 1, "rowCount": -1}, &resp); err != nil {
		return nil, err
	}
	return resp.Rows, nil
}

// FindHost returns the UUID of a host entry by host+domain, or "".
func (d *Dnsmasq) FindHost(ctx context.Context, host, domain string) (string, error) {
	rows, err := d.searchHosts(ctx)
	if err != nil {
		return "", err
	}
	for _, r := range rows {
		if r.Host == host && r.Domain == domain {
			return r.UUID, nil
		}
	}
	return "", nil
}

// UpsertHost creates or updates a host entry and returns its UUID.
func (d *Dnsmasq) UpsertHost(ctx context.Context, h DnsmasqHost) (string, error) {
	uuid, err := d.FindHost(ctx, h.Host, h.Domain)
	if err != nil {
		return "", err
	}
	body := map[string]DnsmasqHost{"host": h}
	var resp mutationResponse
	if uuid == "" {
		if err := d.c.post(ctx, "/api/dnsmasq/settings/addHost", body, &resp); err != nil {
			return "", err
		}
		return resp.UUID, resp.err("addHost")
	}
	if err := d.c.post(ctx, "/api/dnsmasq/settings/setHost/"+uuid, body, &resp); err != nil {
		return "", err
	}
	return uuid, resp.err("setHost")
}

// DeleteHost removes a host entry by UUID.
func (d *Dnsmasq) DeleteHost(ctx context.Context, uuid string) error {
	var resp mutationResponse
	if err := d.c.post(ctx, "/api/dnsmasq/settings/delHost/"+uuid, map[string]any{}, &resp); err != nil {
		return err
	}
	return resp.err("delHost")
}

// Reconfigure applies pending dnsmasq changes.
func (d *Dnsmasq) Reconfigure(ctx context.Context) error {
	return d.c.post(ctx, "/api/dnsmasq/service/reconfigure", map[string]any{}, nil)
}
