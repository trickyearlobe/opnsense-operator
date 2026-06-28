package opnsense

import "context"

// ACME wraps the os-acme-client plugin (Let's Encrypt / ACME certificates).
//
// Scope for the MVP: resolve a certificate that already exists as a
// configuration object on the firewall (by its domain name) and trigger
// issuance/renewal of it. Full lifecycle management (creating the cert object,
// account, and validation method via the API) is a follow-up — those objects
// carry a lot of fields and are usually set up once by hand, whereas resolving
// and issuing is the part a controller wants to drive on demand.
func (c *Client) ACME() *ACME { return &ACME{c: c} }

// ACME is the os-acme-client API surface.
type ACME struct{ c *Client }

// Certificate is the subset of an os-acme-client certificate we care about.
type Certificate struct {
	UUID       string
	Name       string // primary domain / CN, e.g. "*.trickyearlobe.com"
	AltNames   string // comma-separated SANs
	Enabled    bool
	StatusCode string // "200" once a sign has succeeded; "" / other otherwise
	CertRefID  string // HAProxy refid for the issued cert (links to the trust store)
}

// Issued reports whether the certificate's last issuance succeeded. OPNsense's
// own auto-renewal cron then owns ongoing renewal, so callers should avoid
// forcing re-issuance of an already-issued cert.
func (c *Certificate) Issued() bool { return c.StatusCode == "200" }

// acmeCertRow is the search-row shape. The os-acme-client search returns more
// fields than the generic row type, so we parse our own.
type acmeCertRow struct {
	UUID       string `json:"uuid"`
	Name       string `json:"name"`
	AltNames   string `json:"altNames"`
	Enabled    string `json:"enabled"`
	StatusCode string `json:"statusCode"`
	CertRefID  string `json:"certRefId"`
}

func (a *ACME) listCerts(ctx context.Context) ([]acmeCertRow, error) {
	var resp struct {
		Rows []acmeCertRow `json:"rows"`
	}
	if err := a.c.post(ctx, "/api/acmeclient/certificates/search", map[string]any{"current": 1, "rowCount": -1}, &resp); err != nil {
		return nil, err
	}
	return resp.Rows, nil
}

// FindCertByName resolves a certificate by its primary name (CN), falling back
// to any cert whose altNames list contains the name. Returns nil if none match.
// We match on the domain name — not the free-text description — because real
// cert descriptions are often empty or a human label ("Zong web application").
func (a *ACME) FindCertByName(ctx context.Context, name string) (*Certificate, error) {
	rows, err := a.listCerts(ctx)
	if err != nil {
		return nil, err
	}
	var fallback *acmeCertRow
	for i := range rows {
		r := &rows[i]
		if r.Name == name {
			return toCertificate(r), nil
		}
		if fallback == nil && csvContains(r.AltNames, name) {
			fallback = r
		}
	}
	if fallback != nil {
		return toCertificate(fallback), nil
	}
	return nil, nil
}

func toCertificate(r *acmeCertRow) *Certificate {
	return &Certificate{
		UUID:       r.UUID,
		Name:       r.Name,
		AltNames:   r.AltNames,
		Enabled:    r.Enabled == "1",
		StatusCode: r.StatusCode,
		CertRefID:  r.CertRefID,
	}
}

// IssueOrRenew forces issuance/renewal of the certificate identified by UUID.
// OPNsense runs acme.sh, which itself skips a still-valid cert unless it is
// within its renewal window, so this is safe to call but should be reserved for
// certs that have not yet been issued (see Certificate.Issued).
func (a *ACME) IssueOrRenew(ctx context.Context, uuid string) error {
	var resp mutationResponse
	if err := a.c.post(ctx, "/api/acmeclient/certificates/issue/"+uuid, map[string]any{}, &resp); err != nil {
		return err
	}
	return resp.err("acme issue")
}
