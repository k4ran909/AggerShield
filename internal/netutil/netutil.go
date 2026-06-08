// Package netutil contains shared IP/CIDR helpers.
package netutil

import (
	"context"
	"net"
	"net/http"
	"strings"
)

type ctxKey int

const clientIPKey ctxKey = 0

// WithClientIP stores the resolved client IP in the request context so
// downstream handlers (the proxy) can forward the true client to the origin,
// even when AggerShield itself sits behind a CDN/load balancer.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey, ip)
}

// ClientIPFromContext returns the IP stored by WithClientIP, if any.
func ClientIPFromContext(ctx context.Context) (string, bool) {
	ip, ok := ctx.Value(clientIPKey).(string)
	return ip, ok
}

// ParseCIDRs turns a mix of bare IPs and CIDRs into *net.IPNet entries.
// A bare IP "1.2.3.4" becomes a /32 (or /128 for IPv6).
func ParseCIDRs(entries []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			if ip := net.ParseIP(e); ip != nil {
				if ip.To4() != nil {
					e += "/32"
				} else {
					e += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

// Contains reports whether ip falls inside any of the given networks.
func Contains(nets []*net.IPNet, ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// ClientIP resolves the real client IP for a request.
//
// We only honour X-Forwarded-For when the immediate TCP peer is a trusted
// proxy; otherwise we use the raw peer address. XFF is trivially spoofable,
// so trusting it unconditionally would let an attacker forge any source IP
// and either dodge bans or frame an innocent IP to get it banned.
func ClientIP(r *http.Request, trusted []*net.IPNet) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	if len(trusted) == 0 || !Contains(trusted, peer) {
		return peer
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer
	}
	// Take the left-most entry (original client) from the chain.
	first := strings.TrimSpace(strings.Split(xff, ",")[0])
	if net.ParseIP(first) != nil {
		return first
	}
	return peer
}
