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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
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
	// loginLimiter throttles admin login attempts per IP (anti brute-force).
	loginLimiter *ratelimit.PerIP
	// sessionSecret signs admin session cookies (random per process start).
	sessionSecret []byte
	sessionTTL    time.Duration
	// Fleet blocklist tuning.
	fleetTTL time.Duration
	fleetMax int
}

func main() {
	listen := flag.String("listen", ":9000", "listen address")
	dataPath := flag.String("data", "aggershield-license.json", "license data file")
	adminToken := flag.String("admin-token", os.Getenv("AGGERSHIELD_ADMIN_TOKEN"), "admin dashboard token (or AGGERSHIELD_ADMIN_TOKEN)")
	certFile := flag.String("cert", "", "TLS cert (optional)")
	keyFile := flag.String("key", "", "TLS key (optional)")
	agentRPS := flag.Float64("agent-rps", 10, "per-IP request/sec limit on agent endpoints")
	agentBurst := flag.Float64("agent-burst", 20, "per-IP burst on agent endpoints")
	fleetTTL := flag.Duration("fleet-ban-ttl", time.Hour, "how long a fleet-shared ban lives")
	fleetMax := flag.Int("fleet-max", 10000, "max IPs in the fleet blocklist")
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

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Error("session secret", "err", err)
		os.Exit(1)
	}
	s := &server{
		store:         store,
		adminToken:    *adminToken,
		log:           log,
		tmpl:          template.Must(template.New("dash").Funcs(tmplFuncs).Parse(dashboardHTML)),
		limiter:       ratelimit.NewPerIP(*agentRPS, *agentBurst, 100000, 30*time.Second, 5*time.Minute),
		loginLimiter:  ratelimit.NewPerIP(0.5, 5, 100000, time.Minute, 10*time.Minute), // ~5 tries then 1 / 2s
		sessionSecret: secret,
		sessionTTL:    12 * time.Hour,
		fleetTTL:      *fleetTTL,
		fleetMax:      *fleetMax,
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
	mux.HandleFunc("GET /api/v1/admin/audit", s.adminJSON(s.handleAuditJSON))
	// Admin login (session-cookie). The login POST is rate-limited per IP.
	mux.HandleFunc("GET /admin/login", s.handleLoginGet)
	mux.HandleFunc("POST /admin/login", s.handleLoginPost)
	mux.HandleFunc("POST /admin/logout", s.handleLogout)
	// Admin dashboard (session-authenticated).
	mux.HandleFunc("GET /admin", s.adminHTML(s.handleDashboard))
	mux.HandleFunc("POST /admin/keys", s.adminHTML(s.handleGenerate))
	mux.HandleFunc("POST /admin/keys/revoke", s.adminHTML(s.handleRevoke))
	mux.HandleFunc("POST /admin/keys/policy", s.adminHTML(s.handleSetPolicy))
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
	doc, ver := s.store.Policy(key.ID)
	writeJSON(w, http.StatusOK, license.ValidateResp{
		Valid: true, KeyID: key.ID, Name: key.Name,
		PolicyVersion: ver, Policy: doc,
	})
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
	// Ingest any IPs this agent banned into the shared fleet blocklist.
	if len(req.RecentBans) > 0 {
		_ = s.store.AddFleetBans(req.RecentBans, s.fleetTTL, s.fleetMax)
	}

	resp := license.HeartbeatResp{Licensed: true}
	// Push the policy back only when it's newer than what the agent has.
	if doc, ver := s.store.Policy(key.ID); ver != req.PolicyVersion {
		resp.PolicyVersion = ver
		resp.Policy = doc
	}
	// Push the fleet blocklist back only when its version moved.
	if ips, ver := s.store.FleetBlocklist(); ver != req.BlocklistVersion {
		resp.BlocklistVersion = ver
		resp.Blocklist = ips
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- Admin JSON ----

func (s *server) handleKeysJSON(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.store.Keys())
}

func (s *server) handleAuditJSON(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.store.AuditLog())
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
	Key           *license.Key
	Agent         *license.AgentStatus
	Stale         bool
	PolicyVersion int
	PolicyJSON    string
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
	plaintext, key, err := s.store.Generate(name, r.FormValue("note"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.Audit("key.generate", key.ID+" ("+name+")", hostOf(r.RemoteAddr))
	s.render(w, plaintext, name)
}

func (s *server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	if _, err := s.store.Revoke(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.Audit("key.revoke", id, hostOf(r.RemoteAddr))
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// handleSetPolicy stores a per-key protection policy (pushed to the agent on
// its next heartbeat). An empty body clears the policy to an empty doc.
func (s *server) handleSetPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	if id == "" {
		http.Error(w, "missing key id", http.StatusBadRequest)
		return
	}
	var doc license.PolicyDoc
	if raw := strings.TrimSpace(r.FormValue("policy")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			http.Error(w, "invalid policy JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if _, err := s.store.SetPolicy(id, &doc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.Audit("policy.set", id, hostOf(r.RemoteAddr))
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *server) render(w http.ResponseWriter, newKey, newKeyName string) {
	rows := make([]rowView, 0)
	for _, k := range s.store.Keys() {
		a := s.store.Agent(k.ID)
		doc, ver := s.store.Policy(k.ID)
		pj := ""
		if doc != nil {
			if b, err := json.MarshalIndent(doc, "", "  "); err == nil {
				pj = string(b)
			}
		}
		rows = append(rows, rowView{
			Key: k, Agent: a, Stale: a != nil && time.Since(a.LastSeen) > 2*time.Minute,
			PolicyVersion: ver, PolicyJSON: pj,
		})
	}
	audit := s.store.AuditLog()
	if len(audit) > 20 {
		audit = audit[:20] // show the 20 most recent on the dashboard
	}
	data := map[string]any{
		"Rows":       rows,
		"NewKey":     newKey,
		"NewKeyName": newKeyName,
		"Now":        time.Now().UTC().Format(time.RFC1123),
		"Audit":      audit,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.Execute(w, data); err != nil {
		s.log.Error("render dashboard", "err", err)
	}
}

// ---- session login ----

const sessionCookie = "ags_session"

// issueSession returns a signed session value "exp.hexsig" valid for sessionTTL.
func (s *server) issueSession() string {
	exp := strconv.FormatInt(time.Now().Add(s.sessionTTL).Unix(), 10)
	mac := hmac.New(sha256.New, s.sessionSecret)
	mac.Write([]byte(exp))
	return exp + "." + hex.EncodeToString(mac.Sum(nil))
}

func (s *server) validSession(r *http.Request) bool {
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	exp, sig, ok := strings.Cut(ck.Value, ".")
	if !ok {
		return false
	}
	mac := hmac.New(sha256.New, s.sessionSecret)
	mac.Write([]byte(exp))
	want := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return false
	}
	ts, err := strconv.ParseInt(exp, 10, 64)
	return err == nil && time.Now().Unix() < ts
}

func (s *server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	if s.validSession(r) {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	s.securityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(loginHTML))
}

func (s *server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	ip := hostOf(r.RemoteAddr)
	if !s.loginLimiter.Allow(ip) {
		w.Header().Set("Retry-After", "2")
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.FormValue("token")), []byte(s.adminToken)) != 1 {
		s.store.Audit("login.fail", "", ip)
		s.log.Warn("admin login failed", "ip", ip)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: s.issueSession(), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil,
		MaxAge: int(s.sessionTTL.Seconds()),
	})
	s.store.Audit("login.ok", "", ip)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// ---- auth middleware ----

func (s *server) adminHTML(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.validSession(r) {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		s.securityHeaders(w)
		next(w, r)
	}
}

// securityHeaders sets conservative headers on admin HTML responses.
func (s *server) securityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// The dashboard is a single self-contained page with inline styles + a small
	// inline confirm handler, so inline is allowed; everything else is 'self'.
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
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
