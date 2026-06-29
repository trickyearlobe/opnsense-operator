package opnsense

import "context"

// Frontend is an HAProxy public service. This is the field set validated to
// create a working SSL-offloading HTTP frontend via addFrontend; OPNsense fills
// defaults for everything else. (Cloning the full object instead fails on its
// many empty reference fields, so we send only what we set.)
//
// Cert fields take a **refid** (see Trust.FindCertRef), not a trust UUID.
type Frontend struct {
	UUID                  string `json:"-"`
	Enabled               string `json:"enabled"`
	Name                  string `json:"name"`
	Description           string `json:"description"`
	Bind                  string `json:"bind"` // e.g. "0.0.0.0:9001"
	Mode                  string `json:"mode"` // "http" (SSL offload) | "ssl" | "tcp"
	DefaultBackend        string `json:"defaultBackend"`
	SSLEnabled            string `json:"ssl_enabled"`
	SSLCertificates       string `json:"ssl_certificates"`        // comma-separated refids
	SSLDefaultCertificate string `json:"ssl_default_certificate"` // refid
}

// UpsertFrontend creates or updates a frontend by name, returning its UUID.
func (h *HAProxy) UpsertFrontend(ctx context.Context, fe Frontend) (string, error) {
	uuid, err := h.FindFrontend(ctx, fe.Name)
	if err != nil {
		return "", err
	}
	body := map[string]Frontend{"frontend": fe}
	var resp mutationResponse
	if uuid == "" {
		if err := h.c.post(ctx, "/api/haproxy/settings/addFrontend", body, &resp); err != nil {
			return "", err
		}
		return resp.UUID, resp.err("addFrontend")
	}
	if err := h.c.post(ctx, "/api/haproxy/settings/setFrontend/"+uuid, body, &resp); err != nil {
		return "", err
	}
	return uuid, resp.err("setFrontend")
}

// DeleteFrontend removes a frontend by UUID.
func (h *HAProxy) DeleteFrontend(ctx context.Context, uuid string) error {
	var resp mutationResponse
	if err := h.c.post(ctx, "/api/haproxy/settings/delFrontend/"+uuid, map[string]any{}, &resp); err != nil {
		return err
	}
	return resp.err("delFrontend")
}

// ListManagedFrontends returns frontends this controller owns (by description marker).
func (h *HAProxy) ListManagedFrontends(ctx context.Context) ([]Row, error) {
	return h.listManaged(ctx, "/api/haproxy/settings/searchFrontends")
}
