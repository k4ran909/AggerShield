package license

import "aggershield/internal/config"

// PolicyDoc is the subset of protection settings an operator can push to an
// agent from the control plane. Every field is a pointer so a policy can be
// partial — only the set fields override the agent's local config; nil fields
// are left untouched. Deployment/wiring (listen, upstream, tls, license,
// challenge.secret) is NOT pushable and stays local to the agent.
type PolicyDoc struct {
	RateLimit     *config.RateLimit  `json:"rate_limit,omitempty"`
	Ban           *config.Ban        `json:"ban,omitempty"`
	Challenge     *config.Challenge  `json:"challenge,omitempty"`
	Connection    *config.Connection `json:"connection,omitempty"`
	Allowlist     *[]string          `json:"allowlist,omitempty"`
	Denylist      *[]string          `json:"denylist,omitempty"`
	BadUserAgents *[]string          `json:"bad_user_agents,omitempty"`
	Block         *config.Block      `json:"block,omitempty"`
	Rules         *[]config.Rule     `json:"rules,omitempty"`
	DryRun        *bool              `json:"dry_run,omitempty"`
}

// ApplyTo overlays the policy's set fields onto a base config (typically the
// agent's local config). The agent then Normalize()s and hot-reloads it.
func (p *PolicyDoc) ApplyTo(c *config.Config) {
	if p == nil {
		return
	}
	if p.RateLimit != nil {
		c.RateLimit = *p.RateLimit
	}
	if p.Ban != nil {
		c.Ban = *p.Ban
	}
	if p.Challenge != nil {
		secret := c.Challenge.Secret // the signing secret is never pushed
		c.Challenge = *p.Challenge
		if c.Challenge.Secret == "" {
			c.Challenge.Secret = secret
		}
	}
	if p.Connection != nil {
		c.Connection = *p.Connection
	}
	if p.Allowlist != nil {
		c.Allowlist = *p.Allowlist
	}
	if p.Denylist != nil {
		c.Denylist = *p.Denylist
	}
	if p.BadUserAgents != nil {
		c.BadUserAgents = *p.BadUserAgents
	}
	if p.Block != nil {
		c.Block = *p.Block
	}
	if p.Rules != nil {
		c.Rules = *p.Rules
	}
	if p.DryRun != nil {
		c.DryRun = *p.DryRun
	}
}

// PolicyRecord is the stored policy for a key plus a monotonically increasing
// version (so agents apply changes only when the version moves).
type PolicyRecord struct {
	Doc     *PolicyDoc `json:"doc"`
	Version int        `json:"version"`
}

// SetPolicy stores (or replaces) the policy for a key and bumps its version.
func (s *Store) SetPolicy(keyID string, doc *PolicyDoc) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.d.Policies[keyID]
	if rec == nil {
		rec = &PolicyRecord{}
		s.d.Policies[keyID] = rec
	}
	rec.Doc = doc
	rec.Version++
	return rec.Version, s.save()
}

// Policy returns the policy doc and version for a key (nil, 0 if none).
func (s *Store) Policy(keyID string) (*PolicyDoc, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec := s.d.Policies[keyID]
	if rec == nil {
		return nil, 0
	}
	return rec.Doc, rec.Version
}
