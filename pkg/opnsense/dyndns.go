package opnsense

import (
	"context"
	"fmt"
)

// DynDNS wraps the os-ddclient plugin API. NOTE the API root is /api/dyndns/*
// (not /api/ddclient/*).
//
// Unlike Unbound/dnsmasq (which map a name to an address on the firewall's own
// resolver), ddclient pushes the firewall's WAN IP to an *external* DNS provider
// (Route53, Cloudflare, …) for a set of hostnames. The provider account — its
// service, credentials, and zone — is operator-level configuration that already
// exists on the box; this operator only manages which hostnames that account
// publishes. We therefore never create or fully rewrite an account (which would
// risk clobbering its stored credentials); we read-modify-write only the
// account's hostnames list, which OPNsense's additive setNodes leaves the other
// fields untouched.
func (c *Client) DynDNS() *DynDNS { return &DynDNS{c: c} }

// DynDNS is the os-ddclient (/api/dyndns) API surface.
type DynDNS struct{ c *Client }

type dynAccountRow struct {
	UUID        string `json:"uuid"`
	Description string `json:"description"`
	Hostnames   string `json:"hostnames"` // comma-separated FQDNs
	Enabled     string `json:"enabled"`
}

func (d *DynDNS) searchAccounts(ctx context.Context) ([]dynAccountRow, error) {
	var resp struct {
		Rows []dynAccountRow `json:"rows"`
	}
	if err := d.c.post(ctx, "/api/dyndns/accounts/searchItem", map[string]any{"current": 1, "rowCount": -1}, &resp); err != nil {
		return nil, err
	}
	return resp.Rows, nil
}

// findAccount resolves the operator-managed account by its description, or nil.
func (d *DynDNS) findAccount(ctx context.Context, description string) (*dynAccountRow, error) {
	rows, err := d.searchAccounts(ctx)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].Description == description {
			return &rows[i], nil
		}
	}
	return nil, nil
}

// setHostnames updates only the hostnames field of an account (partial update,
// preserving credentials/zone/etc.).
func (d *DynDNS) setHostnames(ctx context.Context, uuid, hostnames string) error {
	body := map[string]map[string]string{"account": {"hostnames": hostnames}}
	var resp mutationResponse
	if err := d.c.post(ctx, "/api/dyndns/accounts/setItem/"+uuid, body, &resp); err != nil {
		return err
	}
	return resp.err("setItem")
}

// EnsureHostname makes sure host is in the named account's hostnames list.
// Returns whether it changed anything. Errors if the account does not exist.
func (d *DynDNS) EnsureHostname(ctx context.Context, accountDescription, host string) (bool, error) {
	acct, err := d.findAccount(ctx, accountDescription)
	if err != nil {
		return false, err
	}
	if acct == nil {
		return false, fmt.Errorf("no ddclient account with description %q", accountDescription)
	}
	if csvContains(acct.Hostnames, host) {
		return false, nil
	}
	return true, d.setHostnames(ctx, acct.UUID, appendCSV(acct.Hostnames, host))
}

// RemoveHostname removes host from the named account's hostnames list. Returns
// whether it changed anything; a missing account is treated as nothing to do.
func (d *DynDNS) RemoveHostname(ctx context.Context, accountDescription, host string) (bool, error) {
	acct, err := d.findAccount(ctx, accountDescription)
	if err != nil || acct == nil {
		return false, err
	}
	if !csvContains(acct.Hostnames, host) {
		return false, nil
	}
	return true, d.setHostnames(ctx, acct.UUID, removeCSV(acct.Hostnames, host))
}

// Reconfigure applies pending ddclient changes.
func (d *DynDNS) Reconfigure(ctx context.Context) error {
	return d.c.post(ctx, "/api/dyndns/service/reconfigure", map[string]any{}, nil)
}
