// Package tlsutil builds the TLS configuration for HTTPS termination.
//
// Three paths, in order of precedence:
//   - AutoCert: automatic HTTPS via ACME / Let's Encrypt. Certificates are
//     obtained and renewed with no manual steps. Needs the box reachable from
//     the internet on :80 (HTTP-01 challenge) and :443.
//   - Bring your own PEM cert+key (cert_file/key_file): Let's Encrypt done
//     elsewhere, an OVH/Cloudflare origin cert, etc.
//   - Self-signed in memory: local testing only (use curl -k).
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"aggershield/internal/config"
)

// Build returns a *tls.Config for the server and, when ACME is enabled, the
// *autocert.Manager (so the caller can wire its HTTP-01 challenge handler).
// hosts are the site hostnames (used for the self-signed SANs or added to the
// ACME allowlist). The manager is nil unless AutoCert is enabled.
//
// chiHook, if non-nil, is invoked with every ClientHello (used for TLS
// fingerprinting). It works across all three cert modes because we install it
// via GetConfigForClient, which returns nil ("use this config") after observing.
func Build(c config.TLS, hosts []string, chiHook func(*tls.ClientHelloInfo)) (*tls.Config, *autocert.Manager, error) {
	var cfg *tls.Config
	var mgr *autocert.Manager

	if c.AutoCert.Enabled {
		domains := dedupe(append(append([]string{}, c.AutoCert.Domains...), hosts...))
		mgr = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(c.AutoCert.CacheDir),
			HostPolicy: autocert.HostWhitelist(domains...),
			Email:      c.AutoCert.Email,
		}
		cfg = mgr.TLSConfig()
	} else {
		var cert tls.Certificate
		var err error
		if c.SelfSigned {
			cert, err = selfSigned(hosts)
		} else {
			cert, err = tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("tls: %w", err)
		}
		cfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	if chiHook != nil {
		cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			chiHook(chi)
			return nil, nil // keep using cfg (its certs/GetCertificate still apply)
		}
	}
	return cfg, mgr, nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// selfSigned creates an in-memory ECDSA self-signed certificate valid for the
// given hosts (plus localhost / loopback) for one year.
func selfSigned(hosts []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "AggerShield self-signed"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	seen := map[string]bool{}
	add := func(h string) {
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	for _, h := range hosts {
		add(h)
	}
	add("localhost")
	add("127.0.0.1")
	add("::1")

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
