// Package rules implements per-route protection overrides.
//
// Real attacks rarely hit your whole site uniformly — they hammer the
// expensive endpoints (login, search, checkout, password reset). A single
// global rate limit is therefore either too loose for those routes or too
// tight for everything else. Rules let each route carry its own policy:
// force a challenge on /login, hard-block /wp-admin, or give /api/checkout a
// much stricter per-IP budget than static assets.
//
// Rules are evaluated in order; the first match wins. A rule matches when the
// request path satisfies its prefix/regex (if set) and its method is in the
// allowed set (if set).
package rules

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"aggershield/internal/config"
	"aggershield/internal/ratelimit"
)

// Action is what to do with a matched request.
type Action int

const (
	ActionDefault   Action = iota // apply the normal pipeline
	ActionAllow                   // skip all checks
	ActionBlock                   // block outright
	ActionChallenge               // force a PoW challenge
)

func parseAction(s string) Action {
	switch s {
	case "allow":
		return ActionAllow
	case "block":
		return ActionBlock
	case "challenge":
		return ActionChallenge
	default:
		return ActionDefault
	}
}

type compiled struct {
	name    string
	prefix  string
	re      *regexp.Regexp
	methods map[string]bool
	action  Action
	// limiter is a per-route per-IP limiter, non-nil only when the rule sets
	// a rate override.
	limiter *ratelimit.PerIP
}

// Decision is the outcome of matching a request against the rule set.
type Decision struct {
	Name    string
	Action  Action
	Limiter *ratelimit.PerIP // route-specific limiter, or nil to use the default
}

// Set is a compiled, immutable collection of rules.
type Set struct {
	rules []*compiled
}

// Compile turns config rules into an evaluable Set. Each rule with a rate
// override gets its own limiter (bounded and GC'd like the default one).
func Compile(in []config.Rule, maxKeys int) (*Set, error) {
	s := &Set{}
	for i, r := range in {
		c := &compiled{
			name:   r.Name,
			prefix: r.PathPrefix,
			action: parseAction(r.Action),
		}
		if r.PathRegex != "" {
			re, err := regexp.Compile(r.PathRegex)
			if err != nil {
				return nil, fmt.Errorf("rule %d (%q): bad path_regex: %w", i, r.Name, err)
			}
			c.re = re
		}
		if len(r.Methods) > 0 {
			c.methods = make(map[string]bool, len(r.Methods))
			for _, m := range r.Methods {
				c.methods[strings.ToUpper(m)] = true
			}
		}
		if r.PerIPRPS > 0 {
			burst := r.PerIPBurst
			if burst <= 0 {
				burst = r.PerIPRPS * 2
			}
			c.limiter = ratelimit.NewPerIP(r.PerIPRPS, burst, maxKeys, 30*time.Second, 5*time.Minute)
		}
		s.rules = append(s.rules, c)
	}
	return s, nil
}

// Match returns the decision for a request, or ActionDefault if nothing matches.
func (s *Set) Match(r *http.Request) Decision {
	if s == nil {
		return Decision{Action: ActionDefault}
	}
	path := r.URL.Path
	for _, c := range s.rules {
		if c.prefix != "" && !strings.HasPrefix(path, c.prefix) {
			continue
		}
		if c.re != nil && !c.re.MatchString(path) {
			continue
		}
		if c.methods != nil && !c.methods[strings.ToUpper(r.Method)] {
			continue
		}
		return Decision{Name: c.name, Action: c.action, Limiter: c.limiter}
	}
	return Decision{Action: ActionDefault}
}

// Close stops the GC goroutines of any per-route limiters.
func (s *Set) Close() {
	if s == nil {
		return
	}
	for _, c := range s.rules {
		if c.limiter != nil {
			c.limiter.Close()
		}
	}
}
