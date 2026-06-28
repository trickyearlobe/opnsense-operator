package opnsense

import (
	"context"
	"fmt"
	"strings"
)

// HAProxy groups the os-haproxy plugin endpoints.
//
// The plugin models configuration as a set of independent objects referenced by
// UUID: real servers, backend pools (which link a list of server UUIDs), and
// public services / frontends (which link a backend). After mutating any of
// them you must call Reconfigure to regenerate and reload haproxy.cfg.
func (c *Client) HAProxy() *HAProxy { return &HAProxy{c: c} }

// HAProxy is the os-haproxy API surface.
type HAProxy struct{ c *Client }

// ManagedMarker is embedded in the description of every object this controller
// owns, so we can safely list and prune only our own objects and never touch
// anything an operator configured by hand in the GUI.
const ManagedMarker = "managed-by=opnsense-operator.k8s.local"

// Server is a single real server in a backend pool.
type Server struct {
	UUID        string `json:"-"`
	Name        string `json:"name"`
	Address     string `json:"address"`
	Port        string `json:"port"`
	Mode        string `json:"mode,omitempty"` // "active" | "backup" | "disabled"
	Type        string `json:"type,omitempty"` // "static" | "template"
	Enabled     string `json:"enabled"`        // "0" | "1"
	SSL         string `json:"ssl,omitempty"`
	Description string `json:"description"`
}

// Backend is a pool that links a set of servers.
type Backend struct {
	UUID          string `json:"-"`
	Name          string `json:"name"`
	Mode          string `json:"mode"` // "http" | "tcp"
	Enabled       string `json:"enabled"`
	LinkedServers string `json:"linkedServers"` // comma-separated server UUIDs
	Description   string `json:"description"`
}

// row is the shape of a single search result; OPNsense returns enough fields
// for us to match by name and identify ownership by description.
type row struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type searchResponse struct {
	Rows  []row `json:"rows"`
	Total int   `json:"total"`
}

type mutationResponse struct {
	Result      string         `json:"result"`
	UUID        string         `json:"uuid"`
	Validations map[string]any `json:"validations"`
}

func (m *mutationResponse) err(action string) error {
	if m.Result == "saved" || m.Result == "deleted" || m.Result == "ok" {
		return nil
	}
	if len(m.Validations) > 0 {
		return fmt.Errorf("haproxy %s rejected: %v", action, m.Validations)
	}
	return fmt.Errorf("haproxy %s returned result=%q", action, m.Result)
}

// --- Servers -------------------------------------------------------------

// FindServer returns the UUID of a server by exact name, or "" if absent.
func (h *HAProxy) FindServer(ctx context.Context, name string) (string, error) {
	return h.findByName(ctx, "/api/haproxy/settings/searchServers", name)
}

// ListManagedServers returns every server this controller owns.
func (h *HAProxy) ListManagedServers(ctx context.Context) ([]row, error) {
	return h.listManaged(ctx, "/api/haproxy/settings/searchServers")
}

// UpsertServer creates or updates a server by name and returns its UUID.
func (h *HAProxy) UpsertServer(ctx context.Context, s Server) (string, error) {
	uuid, err := h.FindServer(ctx, s.Name)
	if err != nil {
		return "", err
	}
	body := map[string]Server{"server": s}
	var resp mutationResponse
	if uuid == "" {
		if err := h.c.post(ctx, "/api/haproxy/settings/addServer", body, &resp); err != nil {
			return "", err
		}
		return resp.UUID, resp.err("addServer")
	}
	path := "/api/haproxy/settings/setServer/" + uuid
	if err := h.c.post(ctx, path, body, &resp); err != nil {
		return "", err
	}
	return uuid, resp.err("setServer")
}

// DeleteServer removes a server by UUID.
func (h *HAProxy) DeleteServer(ctx context.Context, uuid string) error {
	var resp mutationResponse
	if err := h.c.post(ctx, "/api/haproxy/settings/delServer/"+uuid, map[string]any{}, &resp); err != nil {
		return err
	}
	return resp.err("delServer")
}

// --- Backends ------------------------------------------------------------

// FindBackend returns the UUID of a backend by exact name, or "" if absent.
func (h *HAProxy) FindBackend(ctx context.Context, name string) (string, error) {
	return h.findByName(ctx, "/api/haproxy/settings/searchBackends", name)
}

// ListManagedBackends returns every backend this controller owns.
func (h *HAProxy) ListManagedBackends(ctx context.Context) ([]row, error) {
	return h.listManaged(ctx, "/api/haproxy/settings/searchBackends")
}

// UpsertBackend creates or updates a backend by name and returns its UUID.
func (h *HAProxy) UpsertBackend(ctx context.Context, b Backend) (string, error) {
	uuid, err := h.FindBackend(ctx, b.Name)
	if err != nil {
		return "", err
	}
	body := map[string]Backend{"backend": b}
	var resp mutationResponse
	if uuid == "" {
		if err := h.c.post(ctx, "/api/haproxy/settings/addBackend", body, &resp); err != nil {
			return "", err
		}
		return resp.UUID, resp.err("addBackend")
	}
	path := "/api/haproxy/settings/setBackend/" + uuid
	if err := h.c.post(ctx, path, body, &resp); err != nil {
		return "", err
	}
	return uuid, resp.err("setBackend")
}

// DeleteBackend removes a backend by UUID.
func (h *HAProxy) DeleteBackend(ctx context.Context, uuid string) error {
	var resp mutationResponse
	if err := h.c.post(ctx, "/api/haproxy/settings/delBackend/"+uuid, map[string]any{}, &resp); err != nil {
		return err
	}
	return resp.err("delBackend")
}

// --- Apply ---------------------------------------------------------------

// Reconfigure regenerates haproxy.cfg and reloads the service. Callers should
// debounce this: a burst of object mutations needs only one reconfigure.
func (h *HAProxy) Reconfigure(ctx context.Context) error {
	var resp struct {
		Status string `json:"status"`
	}
	if err := h.c.post(ctx, "/api/haproxy/service/reconfigure", map[string]any{}, &resp); err != nil {
		return err
	}
	if resp.Status != "ok" {
		return fmt.Errorf("haproxy reconfigure status=%q", resp.Status)
	}
	return nil
}

// --- shared search helpers ----------------------------------------------

func (h *HAProxy) search(ctx context.Context, path string) ([]row, error) {
	// searchPhrase is empty: we pull the full set and filter client-side. The
	// object counts on a firewall are small, so this stays cheap and keeps the
	// matching logic in one place.
	var resp searchResponse
	if err := h.c.post(ctx, path, map[string]any{"current": 1, "rowCount": -1}, &resp); err != nil {
		return nil, err
	}
	return resp.Rows, nil
}

func (h *HAProxy) findByName(ctx context.Context, path, name string) (string, error) {
	rows, err := h.search(ctx, path)
	if err != nil {
		return "", err
	}
	for _, r := range rows {
		if r.Name == name {
			return r.UUID, nil
		}
	}
	return "", nil
}

func (h *HAProxy) listManaged(ctx context.Context, path string) ([]row, error) {
	rows, err := h.search(ctx, path)
	if err != nil {
		return nil, err
	}
	out := make([]row, 0, len(rows))
	for _, r := range rows {
		if strings.Contains(r.Description, ManagedMarker) {
			out = append(out, r)
		}
	}
	return out, nil
}

// --- comma-separated UUID-list helpers (os-haproxy link fields) ----------

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func joinCSV(items []string) string { return strings.Join(items, ",") }

func csvContains(csv, item string) bool {
	for _, p := range splitCSV(csv) {
		if p == item {
			return true
		}
	}
	return false
}

func appendCSV(csv, item string) string {
	if csvContains(csv, item) {
		return csv
	}
	return joinCSV(append(splitCSV(csv), item))
}

func removeCSV(csv, item string) string {
	var kept []string
	for _, p := range splitCSV(csv) {
		if p != item {
			kept = append(kept, p)
		}
	}
	return joinCSV(kept)
}
