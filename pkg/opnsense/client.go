// Package opnsense is a thin client for the OPNsense REST API.
//
// OPNsense exposes its configuration over a JSON/REST API. Authentication is
// HTTP Basic, where the username is an API key and the password is the matching
// API secret (Settings > Administration > API on the firewall). Every plugin
// namespaces its endpoints, e.g. the os-haproxy plugin lives under
// /api/haproxy/... and the os-acme-client plugin under /api/acmeclient/...
//
// This package keeps a single low-level Client that knows how to authenticate
// and (de)serialise JSON. Feature-specific helpers (HAProxy, ACME, DDNS) hang
// off it in their own files.
package opnsense

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to a single OPNsense instance.
type Client struct {
	baseURL string
	key     string
	secret  string
	http    *http.Client
}

// Options configures a Client.
type Options struct {
	// BaseURL is the firewall root, e.g. https://opnsense.lan (no trailing /api).
	BaseURL string
	// Key and Secret are the API credentials.
	Key    string
	Secret string
	// InsecureSkipVerify disables TLS verification. Handy for the common case of
	// a firewall using a self-signed cert, but prefer pinning a CA in prod.
	InsecureSkipVerify bool
	// Timeout bounds each request. Zero means a sane default.
	Timeout time.Duration
}

// NewClient builds a Client from Options.
func NewClient(opts Options) *Client {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		baseURL: strings.TrimRight(opts.BaseURL, "/"),
		key:     opts.Key,
		secret:  opts.Secret,
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.InsecureSkipVerify}, //nolint:gosec // opt-in
			},
		},
	}
}

// APIError is returned for non-2xx responses, carrying the body for diagnosis.
type APIError struct {
	Status int
	Path   string
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("opnsense: %s returned %d: %s", e.Path, e.Status, e.Body)
}

// get issues a GET and decodes the JSON response into out (may be nil).
func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// post issues a POST with a JSON body and decodes the response into out.
func (c *Client) post(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reader = bytes.NewReader(buf)
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.SetBasicAuth(c.key, c.secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, Path: path, Body: string(raw)}
	}

	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode response from %s: %w (body: %s)", path, err, truncate(raw, 512))
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
