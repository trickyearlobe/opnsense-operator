package opnsense

import "context"

// ACME wraps the os-acme-client plugin (Let's Encrypt / ACME certificates).
//
// Scope for the MVP: trigger issuance/renewal of a certificate that already
// exists as a configuration object on the firewall, looked up by its
// description. Full lifecycle management (creating the cert object, account,
// and validation method via the API) is a follow-up — those objects carry a
// lot of fields and are usually set up once by hand, whereas issue/renew is
// the part a controller wants to drive on demand.
func (c *Client) ACME() *ACME { return &ACME{c: c} }

// ACME is the os-acme-client API surface.
type ACME struct{ c *Client }

// FindCertificate returns the UUID of an ACME certificate whose description
// contains the given marker, or "" if none match.
func (a *ACME) FindCertificate(ctx context.Context, descriptionMarker string) (string, error) {
	var resp searchResponse
	if err := a.c.post(ctx, "/api/acmeclient/certificates/search", map[string]any{"current": 1, "rowCount": -1}, &resp); err != nil {
		return "", err
	}
	for _, r := range resp.Rows {
		if r.Description == descriptionMarker {
			return r.UUID, nil
		}
	}
	return "", nil
}

// IssueOrRenew forces issuance/renewal of the certificate identified by UUID.
func (a *ACME) IssueOrRenew(ctx context.Context, uuid string) error {
	var resp mutationResponse
	if err := a.c.post(ctx, "/api/acmeclient/certificates/issue/"+uuid, map[string]any{}, &resp); err != nil {
		return err
	}
	return resp.err("acme issue")
}
