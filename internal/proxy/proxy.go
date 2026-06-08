// Package proxy builds the reverse proxy / router that forwards guarded
// traffic to one or more origins (Vercel, Dokploy, a local app, ...).
//
// Host-based routing lets a single AggerShield protect several sites: the
// inbound Host header selects the origin. A default upstream catches any
// unmatched host. WebSockets and streaming responses pass through natively.
//
// Forwarded headers: every proxied request carries X-Forwarded-For,
// X-Forwarded-Proto, X-Forwarded-Host and X-Real-IP set to the client IP the
// guard resolved — so the origin sees the true visitor even when AggerShield
// sits behind a CDN.
package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"aggershield/internal/config"
	"aggershield/internal/netutil"
)

// Router forwards requests to origins selected by Host.
type Router struct {
	sites   map[string]http.Handler // host (lower, no port) -> origin proxy
	def     http.Handler            // fallback for unmatched hosts
	log     *slog.Logger
}

// New builds a Router from config: one entry per Sites[], plus the default
// Upstream (if set) as the catch-all.
func New(cfg *config.Config, log *slog.Logger) (*Router, error) {
	rt := &Router{sites: make(map[string]http.Handler), log: log}

	for _, s := range cfg.Sites {
		p, err := newReverseProxy(s.Upstream, s.PreserveHost, log)
		if err != nil {
			return nil, err
		}
		rt.sites[strings.ToLower(s.Host)] = p
	}
	if cfg.Upstream != "" {
		// The default origin keeps the visitor's Host by default (suits a
		// single self-hosted app); platform origins should use Sites with
		// preserve_host:false.
		p, err := newReverseProxy(cfg.Upstream, true, log)
		if err != nil {
			return nil, err
		}
		rt.def = p
	}
	return rt, nil
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := stripPort(r.Host)
	h := rt.sites[strings.ToLower(host)]
	if h == nil {
		h = rt.def
	}
	if h == nil {
		http.Error(w, "No origin configured for this host", http.StatusNotFound)
		return
	}
	h.ServeHTTP(w, r)
}

func newReverseProxy(upstream string, preserveHost bool, log *slog.Logger) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)      // scheme + host + base path
			pr.SetXForwarded()     // X-Forwarded-For/Host/Proto from the inbound request
			if preserveHost {
				pr.Out.Host = pr.In.Host
			} else {
				// Platforms like Vercel route by Host and only know their own
				// *.vercel.app name; send that, not the visitor's domain.
				pr.Out.Host = target.Host
			}
			// Prefer the guard-resolved client IP (correct behind a CDN).
			if ip, ok := netutil.ClientIPFromContext(pr.In.Context()); ok {
				pr.Out.Header.Set("X-Forwarded-For", ip)
				pr.Out.Header.Set("X-Real-IP", ip)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Error("upstream error", "err", err, "host", r.Host, "path", r.URL.Path)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
	return rp, nil
}

func stripPort(host string) string {
	if i := strings.LastIndexByte(host, ':'); i != -1 {
		// Guard against IPv6 literals like [::1]:443.
		if !strings.Contains(host, "]") || strings.HasSuffix(host[:i], "]") {
			return host[:i]
		}
	}
	return host
}
