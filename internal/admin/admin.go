// Package admin exposes a token-protected runtime control API so operators
// can retune and respond to an attack live, without restarting:
//
//	GET  /aggershield/admin/bans          list active bans
//	GET  /aggershield/admin/config        current effective config (redacted)
//	POST /aggershield/admin/ban?ip=&for=  manually ban an IP (default 10m)
//	POST /aggershield/admin/unban?ip=     lift a ban
//	POST /aggershield/admin/reload        re-read the config file and hot-swap
//
// Auth: every request must carry  X-AggerShield-Token: <admin.token>.
// Comparison is constant-time. If admin is disabled the routes are not
// mounted at all.
package admin

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"time"

	"aggershield/internal/banlist"
	"aggershield/internal/config"
)

const tokenHeader = "X-AggerShield-Token"

// Reloader re-reads config from disk and applies it. Returns the freshly
// loaded config (for the response) or an error.
type Reloader func() (*config.Config, error)

// API holds the dependencies the admin endpoints act on.
type API struct {
	token       string
	bans        *banlist.Store
	reload      Reloader
	cfgPath     string
	snapshot    func() *config.Config // returns current effective config
	setChalMode func(always bool)     // runtime challenge-mode lever
}

func New(token, cfgPath string, bans *banlist.Store, reload Reloader, snapshot func() *config.Config, setChalMode func(bool)) *API {
	return &API{token: token, bans: bans, reload: reload, cfgPath: cfgPath, snapshot: snapshot, setChalMode: setChalMode}
}

// Register mounts the admin routes on mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("/aggershield/admin/bans", a.auth(a.handleBans))
	mux.HandleFunc("/aggershield/admin/config", a.auth(a.handleConfig))
	mux.HandleFunc("/aggershield/admin/ban", a.auth(a.requirePost(a.handleBan)))
	mux.HandleFunc("/aggershield/admin/unban", a.auth(a.requirePost(a.handleUnban)))
	mux.HandleFunc("/aggershield/admin/reload", a.auth(a.requirePost(a.handleReload)))
	mux.HandleFunc("/aggershield/admin/mode", a.auth(a.requirePost(a.handleMode)))
}

// auth wraps a handler with constant-time token verification.
func (a *API) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get(tokenHeader)
		if a.token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (a *API) requirePost(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

func (a *API) handleBans(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.bans.List())
}

func (a *API) handleConfig(w http.ResponseWriter, _ *http.Request) {
	cfg := *a.snapshot() // copy so we can redact without mutating the live one
	cfg.Admin.Token = "***redacted***"
	if cfg.Challenge.Secret != "" {
		cfg.Challenge.Secret = "***redacted***"
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (a *API) handleBan(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "missing ?ip=", http.StatusBadRequest)
		return
	}
	dur := 10 * time.Minute
	if f := r.URL.Query().Get("for"); f != "" {
		d, err := time.ParseDuration(f)
		if err != nil {
			http.Error(w, "bad ?for= duration", http.StatusBadRequest)
			return
		}
		dur = d
	}
	ok := a.bans.BanFor(ip, dur)
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "banned": ok, "duration": dur.String()})
}

func (a *API) handleUnban(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "missing ?ip=", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "removed": a.bans.Unban(ip)})
}

func (a *API) handleMode(w http.ResponseWriter, r *http.Request) {
	if a.setChalMode == nil {
		http.Error(w, "challenge mode control unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.URL.Query().Get("challenge") {
	case "always":
		a.setChalMode(true)
		writeJSON(w, http.StatusOK, map[string]any{"challenge_mode": "always"})
	case "adaptive":
		a.setChalMode(false)
		writeJSON(w, http.StatusOK, map[string]any{"challenge_mode": "adaptive"})
	default:
		http.Error(w, "use ?challenge=always|adaptive", http.StatusBadRequest)
	}
}

func (a *API) handleReload(w http.ResponseWriter, _ *http.Request) {
	cfg, err := a.reload()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"reloaded": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reloaded": true, "rules": len(cfg.Rules)})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
