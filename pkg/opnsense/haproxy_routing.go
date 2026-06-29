package opnsense

import (
	"context"
	"fmt"
)

// L7 host routing: ACL + Action + attachment to a public frontend.
//
// To route an HTTP Host to a backend, os-haproxy needs three things:
//   1. an ACL that matches the host (expression "hdr" — HTTP Host header matches)
//   2. an action of type "use_backend" that fires when the ACL matches
//   3. that action linked into a public frontend's `linkedActions`
//
// Field names below were validated live against the os-haproxy model (getAcl /
// getAction / getFrontend templates): the host-match expression is "hdr" with
// the value in a field of the same name (NOT "host_matches"); the action uses
// type/testType/operator/use_backend; a frontend's linkedActions is a
// uuid -> {value,selected} map. Everything is isolated here so a future plugin
// rename is a one-line fix. Steps 1–2 are fully managed (create/update/delete,
// ownership-tagged); step 3 mutates only the frontend's linkedActions list.

// ACLExprHostMatch is the os-haproxy expression for an exact HTTP Host match.
// The matched value is carried in the field of the same name (ACL.Hdr).
const ACLExprHostMatch = "hdr"

// ACL matches a request attribute (here, the HTTP Host header).
type ACL struct {
	UUID        string `json:"-"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Expression  string `json:"expression"`    // e.g. ACLExprHostMatch ("hdr")
	Hdr         string `json:"hdr,omitempty"` // host value when Expression=="hdr"
}

// Action ties an ACL to a backend (use_backend if <acl>).
type Action struct {
	UUID        string `json:"-"`
	Name        string `json:"name"`
	Description string `json:"description"`
	TestType    string `json:"testType,omitempty"` // "if" | "unless"
	Type        string `json:"type"`               // "use_backend"
	LinkedAcls  string `json:"linkedAcls"`         // comma-separated ACL UUIDs
	Operator    string `json:"operator,omitempty"` // "and" | "or"
	UseBackend  string `json:"use_backend,omitempty"`
}

// --- ACLs ----------------------------------------------------------------

func (h *HAProxy) FindACL(ctx context.Context, name string) (string, error) {
	return h.findByName(ctx, "/api/haproxy/settings/searchAcls", name)
}

func (h *HAProxy) ListManagedACLs(ctx context.Context) ([]Row, error) {
	return h.listManaged(ctx, "/api/haproxy/settings/searchAcls")
}

func (h *HAProxy) UpsertACL(ctx context.Context, a ACL) (string, error) {
	uuid, err := h.FindACL(ctx, a.Name)
	if err != nil {
		return "", err
	}
	body := map[string]ACL{"acl": a}
	var resp mutationResponse
	if uuid == "" {
		if err := h.c.post(ctx, "/api/haproxy/settings/addAcl", body, &resp); err != nil {
			return "", err
		}
		return resp.UUID, resp.err("addAcl")
	}
	if err := h.c.post(ctx, "/api/haproxy/settings/setAcl/"+uuid, body, &resp); err != nil {
		return "", err
	}
	return uuid, resp.err("setAcl")
}

func (h *HAProxy) DeleteACL(ctx context.Context, uuid string) error {
	var resp mutationResponse
	if err := h.c.post(ctx, "/api/haproxy/settings/delAcl/"+uuid, map[string]any{}, &resp); err != nil {
		return err
	}
	return resp.err("delAcl")
}

// --- Actions -------------------------------------------------------------

func (h *HAProxy) FindAction(ctx context.Context, name string) (string, error) {
	return h.findByName(ctx, "/api/haproxy/settings/searchActions", name)
}

func (h *HAProxy) ListManagedActions(ctx context.Context) ([]Row, error) {
	return h.listManaged(ctx, "/api/haproxy/settings/searchActions")
}

func (h *HAProxy) UpsertAction(ctx context.Context, a Action) (string, error) {
	uuid, err := h.FindAction(ctx, a.Name)
	if err != nil {
		return "", err
	}
	body := map[string]Action{"action": a}
	var resp mutationResponse
	if uuid == "" {
		if err := h.c.post(ctx, "/api/haproxy/settings/addAction", body, &resp); err != nil {
			return "", err
		}
		return resp.UUID, resp.err("addAction")
	}
	if err := h.c.post(ctx, "/api/haproxy/settings/setAction/"+uuid, body, &resp); err != nil {
		return "", err
	}
	return uuid, resp.err("setAction")
}

func (h *HAProxy) DeleteAction(ctx context.Context, uuid string) error {
	var resp mutationResponse
	if err := h.c.post(ctx, "/api/haproxy/settings/delAction/"+uuid, map[string]any{}, &resp); err != nil {
		return err
	}
	return resp.err("delAction")
}

// --- Frontend attachment -------------------------------------------------

// FindFrontend returns the UUID of a public frontend by name, or "".
func (h *HAProxy) FindFrontend(ctx context.Context, name string) (string, error) {
	return h.findByName(ctx, "/api/haproxy/settings/searchFrontends", name)
}

// frontendActions reads the current comma-separated linkedActions of a frontend.
func (h *HAProxy) frontendActions(ctx context.Context, uuid string) (string, error) {
	var resp struct {
		Frontend struct {
			// OPNsense returns selectable references as a map of
			// uuid -> {value, selected}. We only need the selected UUIDs.
			LinkedActions map[string]struct {
				Selected int `json:"selected"`
			} `json:"linkedActions"`
		} `json:"frontend"`
	}
	if err := h.c.get(ctx, "/api/haproxy/settings/getFrontend/"+uuid, &resp); err != nil {
		return "", err
	}
	var selected []string
	for id, v := range resp.Frontend.LinkedActions {
		if v.Selected == 1 {
			selected = append(selected, id)
		}
	}
	return joinCSV(selected), nil
}

// AttachActionToFrontend ensures actionUUID is present in the named frontend's
// linkedActions. It is a no-op if already linked. Returns true if it changed
// anything (so the caller knows whether a reconfigure is needed).
func (h *HAProxy) AttachActionToFrontend(ctx context.Context, frontendName, actionUUID string) (bool, error) {
	feUUID, err := h.FindFrontend(ctx, frontendName)
	if err != nil {
		return false, err
	}
	if feUUID == "" {
		return false, fmt.Errorf("frontend %q not found", frontendName)
	}
	current, err := h.frontendActions(ctx, feUUID)
	if err != nil {
		return false, err
	}
	if csvContains(current, actionUUID) {
		return false, nil
	}
	updated := appendCSV(current, actionUUID)
	body := map[string]map[string]string{"frontend": {"linkedActions": updated}}
	var resp mutationResponse
	if err := h.c.post(ctx, "/api/haproxy/settings/setFrontend/"+feUUID, body, &resp); err != nil {
		return false, err
	}
	return true, resp.err("setFrontend")
}

// DetachActionFromFrontend removes actionUUID from the frontend's linkedActions.
func (h *HAProxy) DetachActionFromFrontend(ctx context.Context, frontendName, actionUUID string) (bool, error) {
	feUUID, err := h.FindFrontend(ctx, frontendName)
	if err != nil || feUUID == "" {
		return false, err // frontend gone: nothing to detach
	}
	current, err := h.frontendActions(ctx, feUUID)
	if err != nil {
		return false, err
	}
	if !csvContains(current, actionUUID) {
		return false, nil
	}
	updated := removeCSV(current, actionUUID)
	body := map[string]map[string]string{"frontend": {"linkedActions": updated}}
	var resp mutationResponse
	if err := h.c.post(ctx, "/api/haproxy/settings/setFrontend/"+feUUID, body, &resp); err != nil {
		return false, err
	}
	return true, resp.err("setFrontend")
}
