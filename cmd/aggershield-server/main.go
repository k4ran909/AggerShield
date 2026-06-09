// Command aggershield-server is AggerShield's central control plane. The
// operator runs it; it issues license keys, validates agents, records where
// each agent runs and what it protects, and serves an admin dashboard to
// generate/revoke keys and watch usage live.
//
//	go run ./cmd/aggershield-server -admin-token "$(openssl rand -hex 16)"
//
// Agents (the AggerShield proxy) authenticate with their key on
// /api/v1/validate and /api/v1/heartbeat. The dashboard lives at /admin and is
// protected by HTTP Basic auth (any username, password = the admin token).
package main

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"aggershield/internal/license"
	"aggershield/internal/ratelimit"
)

const version = "0.1.0"

type server struct {
	store      *license.Store
	adminToken string
	log        *slog.Logger
	tmpl       *template.Template
	// limiter throttles agent endpoints per source IP so a flood of bad keys
	// can't abuse the control plane.
	limiter *ratelimit.PerIP
}

func main() {
	listen := flag.String("listen", ":9000", "listen address")
	dataPath := flag.String("data", "aggershield-license.json", "license data file")
	adminToken := flag.String("admin-token", os.Getenv("AGGERSHIELD_ADMIN_TOKEN"), "admin dashboard token (or AGGERSHIELD_ADMIN_TOKEN)")
	certFile := flag.String("cert", "", "TLS cert (optional)")
	keyFile := flag.String("key", "", "TLS key (optional)")
	agentRPS := flag.Float64("agent-rps", 10, "per-IP request/sec limit on agent endpoints")
	agentBurst := flag.Float64("agent-burst", 20, "per-IP burst on agent endpoints")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if *adminToken == "" {
		log.Error("an -admin-token (or AGGERSHIELD_ADMIN_TOKEN) is required")
		os.Exit(1)
	}

	store, err := license.Open(*dataPath)
	if err != nil {
		log.Error("open license store", "err", err)
		os.Exit(1)
	}

	s := &server{
		store:      store,
		adminToken: *adminToken,
		log:        log,
		tmpl:       template.Must(template.New("dash").Funcs(tmplFuncs).Parse(dashboardHTML)),
		limiter:    ratelimit.NewPerIP(*agentRPS, *agentBurst, 100000, 30*time.Second, 5*time.Minute),
	}

	if *certFile == "" {
		log.Warn("running WITHOUT TLS — keys and the admin token travel in cleartext. " +
			"Use -cert/-key (or put it behind an HTTPS reverse proxy) in production.")
	}

	mux := http.NewServeMux()
	// Agent API (key-authenticated + per-IP rate limited).
	mux.HandleFunc("POST /api/v1/validate", s.rateLimited(s.handleValidate))
	mux.HandleFunc("POST /api/v1/heartbeat", s.rateLimited(s.handleHeartbeat))
	// Admin JSON API (admin-token header).
	mux.HandleFunc("GET /api/v1/admin/keys", s.adminJSON(s.handleKeysJSON))
	mux.HandleFunc("GET /api/v1/admin/agents", s.adminJSON(s.handleAgentsJSON))
	// Admin dashboard (basic auth).
	mux.HandleFunc("GET /admin", s.adminHTML(s.handleDashboard))
	mux.HandleFunc("POST /admin/keys", s.adminHTML(s.handleGenerate))
	mux.HandleFunc("POST /admin/keys/revoke", s.adminHTML(s.handleRevoke))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Info("AggerShield control plane listening", "listen", *listen, "data", *dataPath, "tls", *certFile != "")
	if *certFile != "" {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		err = srv.ListenAndServeTLS(*certFile, *keyFile)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil {
		log.Error("server", "err", err)
		os.Exit(1)
	}
}

// ---- Agent API ----

func (s *server) handleValidate(w http.ResponseWriter, r *http.Request) {
	key, ok := s.store.Validate(r.Header.Get(license.HeaderKey))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, license.ValidateResp{Valid: false, Reason: "invalid or revoked key"})
		return
	}
	writeJSON(w, http.StatusOK, license.ValidateResp{Valid: true, KeyID: key.ID, Name: key.Name})
}

func (s *server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	key, ok := s.store.Validate(r.Header.Get(license.HeaderKey))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, license.HeartbeatResp{Licensed: false, Reason: "invalid or revoked key"})
		return
	}
	var req license.HeartbeatReq
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req)
	_ = s.store.RecordHeartbeat(key.ID, license.AgentStatus{
		Hostname:   req.Hostname,
		Version:    req.Version,
		Protecting: req.Protecting,
		ReportedIP: req.ReportedIP,
		SourceIP:   hostOf(r.RemoteAddr),
		Stats:      req.Stats,
	})
	writeJSON(w, http.StatusOK, license.HeartbeatResp{Licensed: true})
}

// ---- Admin JSON ----

func (s *server) handleKeysJSON(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.store.Keys())
}

func (s *server) handleAgentsJSON(w http.ResponseWriter, _ *http.Request) {
	keys := s.store.Keys()
	agents := make([]*license.AgentStatus, 0, len(keys))
	for _, k := range keys {
		if a := s.store.Agent(k.ID); a != nil {
			agents = append(agents, a)
		}
	}
	writeJSON(w, http.StatusOK, agents)
}

// ---- Admin dashboard ----

type rowView struct {
	Key   *license.Key
	Agent *license.AgentStatus
	Stale bool
}

func (s *server) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	s.render(w, "", "")
}

func (s *server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	plaintext, _, err := s.store.Generate(name, r.FormValue("note"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, plaintext, name)
}

func (s *server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if _, err := s.store.Revoke(r.FormValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *server) render(w http.ResponseWriter, newKey, newKeyName string) {
	rows := make([]rowView, 0)
	for _, k := range s.store.Keys() {
		a := s.store.Agent(k.ID)
		rows = append(rows, rowView{Key: k, Agent: a, Stale: a != nil && time.Since(a.LastSeen) > 2*time.Minute})
	}
	data := map[string]any{
		"Rows":       rows,
		"NewKey":     newKey,
		"NewKeyName": newKeyName,
		"Now":        time.Now().UTC().Format(time.RFC1123),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.Execute(w, data); err != nil {
		s.log.Error("render dashboard", "err", err)
	}
}

// ---- auth middleware ----

func (s *server) adminHTML(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(pass), []byte(s.adminToken)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="AggerShield admin"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// rateLimited throttles a handler per source IP (agent-endpoint abuse guard).
func (s *server) rateLimited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.Allow(hostOf(r.RemoteAddr)) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func (s *server) adminJSON(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get(license.HeaderAdmin)
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.adminToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// handleMetrics serves control-plane counts in Prometheus text format.
func (s *server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	keys := s.store.Keys()
	var revoked, agents int
	for _, k := range keys {
		if k.Revoked {
			revoked++
		}
		if s.store.Agent(k.ID) != nil {
			agents++
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# TYPE aggershield_license_keys_total gauge\naggershield_license_keys_total %d\n", len(keys))
	fmt.Fprintf(w, "# TYPE aggershield_license_keys_revoked gauge\naggershield_license_keys_revoked %d\n", revoked)
	fmt.Fprintf(w, "# TYPE aggershield_license_agents_total gauge\naggershield_license_agents_total %d\n", agents)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

var tmplFuncs = template.FuncMap{
	"stat": func(a *license.AgentStatus, k string) int64 {
		if a == nil || a.Stats == nil {
			return 0
		}
		return a.Stats[k]
	},
	"since": func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		return time.Since(t).Round(time.Second).String() + " ago"
	},
}
