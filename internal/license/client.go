package license

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client is the agent-side client that talks to the control plane.
type Client struct {
	base string
	key  string
	hc   *http.Client
}

// NewClient builds a client for the given control-server base URL and key.
func NewClient(serverURL, key string) *Client {
	return &Client{
		base: strings.TrimRight(serverURL, "/"),
		key:  key,
		hc:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Validate checks the key with the control plane.
func (c *Client) Validate(ctx context.Context) (*ValidateResp, error) {
	var out ValidateResp
	if err := c.do(ctx, "/api/v1/validate", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Heartbeat reports status and returns whether the agent is still licensed.
func (c *Client) Heartbeat(ctx context.Context, req HeartbeatReq) (*HeartbeatResp, error) {
	var out HeartbeatResp
	if err := c.do(ctx, "/api/v1/heartbeat", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) do(ctx context.Context, path string, body, out any) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set(HeaderKey, c.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		// Unknown/invalid key — decode the body for the reason if present.
		_ = json.NewDecoder(resp.Body).Decode(out)
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control plane returned %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
