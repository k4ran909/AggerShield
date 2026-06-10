// Package fingerprint computes TLS client fingerprints (JA3 + JA4) from the
// ClientHello, so AggerShield can tell *what TLS stack* a client uses — Chrome,
// Safari, curl, python-requests, Go, a bot framework — regardless of the
// User-Agent it claims. This catches automated clients that spoof a browser UA
// but have a non-browser TLS handshake, which rate limits and PoW can miss.
//
// Fingerprints are computed from Go's parsed ClientHelloInfo (Go 1.24+ exposes
// the extension list), with GREASE values filtered out so they stay stable.
// They are only available when AggerShield terminates TLS directly facing the
// client — behind a CDN you'd see the CDN's fingerprint, not the visitor's.
package fingerprint

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// isGREASE reports whether a TLS value is a GREASE placeholder (RFC 8701).
// Browsers insert random GREASE values to prevent protocol ossification; they
// must be excluded or the fingerprint changes every connection.
func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a }

func filterGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func maxVersion(vers []uint16) uint16 {
	var max uint16
	for _, v := range vers {
		if !isGREASE(v) && v > max {
			max = v
		}
	}
	return max
}

// JA3 returns the MD5 JA3 hash, computed from the parsed ClientHello (decimal
// fields joined per the JA3 spec, GREASE removed).
func JA3(chi *tls.ClientHelloInfo) string {
	curves := make([]uint16, len(chi.SupportedCurves))
	for i, c := range chi.SupportedCurves {
		curves[i] = uint16(c)
	}
	parts := []string{
		strconv.Itoa(int(maxVersion(chi.SupportedVersions))),
		joinDec(filterGREASE(chi.CipherSuites)),
		joinDec(filterGREASE(chi.Extensions)),
		joinDec(filterGREASE(curves)),
		joinDecU8(chi.SupportedPoints),
	}
	sum := md5.Sum([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(sum[:])
}

// JA4 returns a JA4-style fingerprint (FoxIO JA4 over TCP/TLS), e.g.
// "t13d1516h2_8daaf6152771_b186095e22b6".
func JA4(chi *tls.ClientHelloInfo) string {
	ciphers := filterGREASE(chi.CipherSuites)
	exts := filterGREASE(chi.Extensions)

	sni := "i"
	if chi.ServerName != "" {
		sni = "d"
	}
	a := "t" + ja4Version(maxVersion(chi.SupportedVersions)) + sni +
		count2(len(ciphers)) + count2(len(exts)) + ja4ALPN(chi.SupportedProtos)

	b := hash12(sortedHex(ciphers))

	// JA4_c hashes the extensions (sorted) EXCLUDING SNI (0x0000) and ALPN
	// (0x0010), then "_" then the signature algorithms IN ORDER.
	extForHash := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if e != 0x0000 && e != 0x0010 {
			extForHash = append(extForHash, e)
		}
	}
	sigs := make([]uint16, len(chi.SignatureSchemes))
	for i, s := range chi.SignatureSchemes {
		sigs[i] = uint16(s)
	}
	c := hash12(sortedHex(extForHash) + "_" + orderedHex(filterGREASE(sigs)))

	return a + "_" + b + "_" + c
}

func ja4Version(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "13"
	case tls.VersionTLS12:
		return "12"
	case tls.VersionTLS11:
		return "11"
	case tls.VersionTLS10:
		return "10"
	}
	return "00"
}

func ja4ALPN(protos []string) string {
	if len(protos) == 0 || protos[0] == "" {
		return "00"
	}
	p := protos[0]
	return string(p[0]) + string(p[len(p)-1])
}

func count2(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

func joinDec(vs []uint16) string {
	s := make([]string, len(vs))
	for i, v := range vs {
		s[i] = strconv.Itoa(int(v))
	}
	return strings.Join(s, "-")
}

func joinDecU8(vs []uint8) string {
	s := make([]string, len(vs))
	for i, v := range vs {
		s[i] = strconv.Itoa(int(v))
	}
	return strings.Join(s, "-")
}

// sortedHex renders values as 4-digit hex, sorted ascending, comma-joined.
func sortedHex(vs []uint16) string {
	h := make([]string, len(vs))
	for i, v := range vs {
		h[i] = fmt.Sprintf("%04x", v)
	}
	sort.Strings(h)
	return strings.Join(h, ",")
}

// orderedHex renders values as 4-digit hex in their original order.
func orderedHex(vs []uint16) string {
	h := make([]string, len(vs))
	for i, v := range vs {
		h[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(h, ",")
}

// hash12 is the first 12 hex chars of sha256(s); empty input -> 12 zeros (per JA4).
func hash12(s string) string {
	if s == "" || s == "_" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// ---- per-connection collection ----

type holder struct {
	mu       sync.Mutex
	ja3, ja4 string
	ready    bool
}

type ctxKey int

const fpKey ctxKey = 0

// Collector captures fingerprints during the TLS handshake and makes them
// available on the request context.
type Collector struct {
	pending sync.Map // remoteAddr string -> *holder
}

func New() *Collector { return &Collector{} }

// ConnContext is wired to http.Server.ConnContext: it registers a holder for
// the connection and stashes it on the context so the request can read it.
func (c *Collector) ConnContext(ctx context.Context, conn net.Conn) context.Context {
	h := &holder{}
	c.pending.Store(conn.RemoteAddr().String(), h)
	return context.WithValue(ctx, fpKey, h)
}

// Observe is the ClientHello hook (called by the TLS config during handshake).
func (c *Collector) Observe(chi *tls.ClientHelloInfo) {
	if chi.Conn == nil {
		return
	}
	if v, ok := c.pending.LoadAndDelete(chi.Conn.RemoteAddr().String()); ok {
		h := v.(*holder)
		ja3, ja4 := JA3(chi), JA4(chi)
		h.mu.Lock()
		h.ja3, h.ja4, h.ready = ja3, ja4, true
		h.mu.Unlock()
	}
}

// ConnState is wired to http.Server.ConnState to clean up holders for
// connections that closed before a ClientHello was observed (e.g. scanners).
func (c *Collector) ConnState(conn net.Conn, state http.ConnState) {
	if state == http.StateClosed {
		c.pending.Delete(conn.RemoteAddr().String())
	}
}

// FromContext returns the JA3 and JA4 fingerprints captured for the request.
func FromContext(ctx context.Context) (ja3, ja4 string, ok bool) {
	v := ctx.Value(fpKey)
	if v == nil {
		return "", "", false
	}
	h := v.(*holder)
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.ready {
		return "", "", false
	}
	return h.ja3, h.ja4, true
}
