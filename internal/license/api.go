// Package license implements AggerShield's licensing: a central control plane
// issues API keys and tracks the agents using them, while each agent (the
// AggerShield proxy) validates its key and heartbeats telemetry. This keeps
// the protection logic on the operator's side — customers run only a thin,
// key-gated agent — and lets the operator see where the tool runs and revoke
// access centrally.
package license

const (
	// HeaderKey carries an agent's license key.
	HeaderKey = "X-AggerShield-Key"
	// HeaderAdmin carries the control-plane admin token (JSON admin API).
	HeaderAdmin = "X-AggerShield-Admin"
	// KeyPrefix is the human-recognisable prefix of issued keys.
	KeyPrefix = "agsk_"
)

// ValidateResp is returned from POST /api/v1/validate.
type ValidateResp struct {
	Valid  bool   `json:"valid"`
	KeyID  string `json:"key_id,omitempty"`
	Name   string `json:"name,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// HeartbeatReq is the periodic status an agent reports.
type HeartbeatReq struct {
	Hostname   string           `json:"hostname"`
	Version    string           `json:"version"`
	Protecting string           `json:"protecting"` // what the agent guards (site/upstream)
	ReportedIP string           `json:"reported_ip,omitempty"`
	Stats      map[string]int64 `json:"stats,omitempty"`
}

// HeartbeatResp tells the agent whether it is still licensed. A revoked key
// returns Licensed=false, which (fail-closed) makes the agent stop serving.
type HeartbeatResp struct {
	Licensed bool   `json:"licensed"`
	Reason   string `json:"reason,omitempty"`
}
