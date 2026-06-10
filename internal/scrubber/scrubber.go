// Package scrubber integrates AggerShield with upstream/edge DDoS mitigation —
// the layer a host-based proxy cannot provide itself.
//
// AggerShield owns L7 + connection-level defence, but a volumetric L3/L4 flood
// saturates the uplink before any host software sees it. The fix lives at the
// network edge (Cloudflare, OVH VAC, a BGP blackhole). This package lets
// AggerShield *drive* that edge: when the agent (or the ML control plane)
// concludes it's under a volumetric attack it calls Engage, and Disengage when
// the attack clears.
//
// Adapters:
//   - webhook: POST a JSON event to any URL (wire it to your own automation,
//     a Cloudflare Worker, an OVH API script, PagerDuty, etc.).
//   - cloudflare: flip a zone's Security Level to "under_attack" via the
//     Cloudflare API, and back to normal on disengage.
package scrubber

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"aggershield/internal/config"
)

// Scrubber engages and disengages upstream volumetric mitigation.
type Scrubber interface {
	Engage(ctx context.Context, reason string) error
	Disengage(ctx context.Context) error
	Name() string
}

// New builds a Scrubber from config, or nil when scrubbing is disabled.
func New(c config.Scrubber, log *slog.Logger) Scrubber {
	if !c.Enabled {
		return nil
	}
	hc := &http.Client{Timeout: 15 * time.Second}
	switch strings.ToLower(c.Provider) {
	case "cloudflare":
		base := c.Cloudflare.APIBase
		if base == "" {
			base = "https://api.cloudflare.com/client/v4"
		}
		normal := c.Cloudflare.NormalLevel
		if normal == "" {
			normal = "medium"
		}
		return &cloudflare{base: strings.TrimRight(base, "/"), token: c.Cloudflare.APIToken, zone: c.Cloudflare.ZoneID, normal: normal, hc: hc, log: log}
	default:
		return &webhook{url: c.WebhookURL, hc: hc, log: log}
	}
}

// ---- webhook adapter ----

type webhook struct {
	url string
	hc  *http.Client
	log *slog.Logger
}

func (w *webhook) Name() string { return "webhook" }

func (w *webhook) Engage(ctx context.Context, reason string) error {
	return w.post(ctx, map[string]any{"action": "engage", "reason": reason, "time": time.Now().UTC()})
}

func (w *webhook) Disengage(ctx context.Context) error {
	return w.post(ctx, map[string]any{"action": "disengage", "time": time.Now().UTC()})
}

func (w *webhook) post(ctx context.Context, body map[string]any) error {
	if w.url == "" {
		return fmt.Errorf("scrubber: webhook_url not set")
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return do(w.hc, req)
}

// ---- cloudflare adapter ----

type cloudflare struct {
	base   string
	token  string
	zone   string
	normal string
	hc     *http.Client
	log    *slog.Logger
}

func (c *cloudflare) Name() string { return "cloudflare" }

func (c *cloudflare) Engage(ctx context.Context, _ string) error {
	return c.setSecurityLevel(ctx, "under_attack")
}

func (c *cloudflare) Disengage(ctx context.Context) error {
	return c.setSecurityLevel(ctx, c.normal)
}

func (c *cloudflare) setSecurityLevel(ctx context.Context, level string) error {
	if c.token == "" || c.zone == "" {
		return fmt.Errorf("scrubber: cloudflare api_token and zone_id are required")
	}
	url := fmt.Sprintf("%s/zones/%s/settings/security_level", c.base, c.zone)
	buf, _ := json.Marshal(map[string]string{"value": level})
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	return do(c.hc, req)
}

func do(hc *http.Client, req *http.Request) error {
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("scrubber: upstream returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
