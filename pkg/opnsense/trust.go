package opnsense

import (
	"context"
	"fmt"
	"strings"
)

// Trust wraps the System ▸ Trust (certificate) API.
//
// Its job here is one thing the rest of the operator needs everywhere: turn a
// human cert name (a CN like "*.trickyearlobe.com", or a description) into the
// internal **refid** that HAProxy frontends reference. The refid is NOT the
// trust-store UUID — it's a separate field on the certificate object — which is
// exactly the kind of detail we never want devops to hand-enter.
func (c *Client) Trust() *Trust { return &Trust{c: c} }

// Trust is the trust/cert API surface.
type Trust struct{ c *Client }

type certSearchRow struct {
	UUID       string `json:"uuid"`
	Descr      string `json:"descr"`
	CommonName string `json:"commonname"`
}

// FindCertRef resolves a certificate by common name (preferred) or description
// substring, returning its HAProxy refid. Returns "" if no certificate matches.
func (t *Trust) FindCertRef(ctx context.Context, nameOrCN string) (string, error) {
	var resp struct {
		Rows []certSearchRow `json:"rows"`
	}
	if err := t.c.post(ctx, "/api/trust/cert/search", map[string]any{"current": 1, "rowCount": -1}, &resp); err != nil {
		return "", err
	}

	uuid := matchCert(resp.Rows, nameOrCN)
	if uuid == "" {
		return "", nil
	}

	var cg struct {
		Cert struct {
			Refid string `json:"refid"`
		} `json:"cert"`
	}
	if err := t.c.get(ctx, "/api/trust/cert/get/"+uuid, &cg); err != nil {
		return "", err
	}
	if cg.Cert.Refid == "" {
		return "", fmt.Errorf("certificate %q (%s) has no refid", nameOrCN, uuid)
	}
	return cg.Cert.Refid, nil
}

// matchCert prefers an exact common-name match, then a description-substring
// match, so both "*.trickyearlobe.com" and "*.trickyearlobe.com (ACME Client)"
// resolve the same certificate.
func matchCert(rows []certSearchRow, nameOrCN string) string {
	for _, r := range rows {
		if r.CommonName == nameOrCN {
			return r.UUID
		}
	}
	for _, r := range rows {
		if strings.Contains(r.Descr, nameOrCN) {
			return r.UUID
		}
	}
	return ""
}
