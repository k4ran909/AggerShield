package fingerprint

import (
	"crypto/tls"
	"testing"
)

// chromeLike approximates a browser ClientHello (with GREASE values).
func chromeLike() *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f},
		SupportedCurves:   []tls.CurveID{0x0a0a, tls.X25519, tls.CurveP256},
		SupportedPoints:   []uint8{0},
		SupportedProtos:   []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{0x0a0a, tls.VersionTLS13, tls.VersionTLS12},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
		Extensions:        []uint16{0x0a0a, 0x0000, 0x0010, 0x000d, 0x0033, 0x002b},
		ServerName:        "example.com",
	}
}

// curlLike: a different stack — fewer ciphers, no h2 ALPN, no SNI.
func curlLike() *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0x1301, 0xc02f},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SupportedPoints:   []uint8{0},
		SupportedVersions: []uint16{tls.VersionTLS12},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		Extensions:        []uint16{0x000d, 0x0033},
	}
}

func TestIsGREASE(t *testing.T) {
	for _, g := range []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0xfafa} {
		if !isGREASE(g) {
			t.Fatalf("%#x should be GREASE", g)
		}
	}
	for _, n := range []uint16{0x1301, 0xc02f, 0x0000, tls.VersionTLS13} {
		if isGREASE(n) {
			t.Fatalf("%#x should not be GREASE", n)
		}
	}
}

func TestJA3DeterministicAndGREASEFree(t *testing.T) {
	a := JA3(chromeLike())
	b := JA3(chromeLike())
	if a != b {
		t.Fatal("JA3 must be deterministic for the same ClientHello")
	}
	if len(a) != 32 { // md5 hex
		t.Fatalf("JA3 should be a 32-char md5 hex, got %q", a)
	}
	// A GREASE'd vs non-GREASE'd version of the same hello must match (GREASE filtered).
	withGrease := chromeLike()
	withoutGrease := chromeLike()
	withoutGrease.CipherSuites = []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f}
	withoutGrease.SupportedCurves = []tls.CurveID{tls.X25519, tls.CurveP256}
	withoutGrease.SupportedVersions = []uint16{tls.VersionTLS13, tls.VersionTLS12}
	withoutGrease.Extensions = []uint16{0x0000, 0x0010, 0x000d, 0x0033, 0x002b}
	if JA3(withGrease) != JA3(withoutGrease) {
		t.Fatal("GREASE values must not affect the JA3 fingerprint")
	}
}

func TestDifferentClientsDifferentFingerprints(t *testing.T) {
	if JA3(chromeLike()) == JA3(curlLike()) {
		t.Fatal("different TLS stacks should have different JA3")
	}
	if JA4(chromeLike()) == JA4(curlLike()) {
		t.Fatal("different TLS stacks should have different JA4")
	}
}

func TestJA4Shape(t *testing.T) {
	ja4 := JA4(chromeLike())
	// e.g. t13d0406h2_<12hex>_<12hex>
	if len(ja4) < 20 || ja4[0] != 't' {
		t.Fatalf("unexpected JA4 shape: %q", ja4)
	}
	// SNI present -> 'd', ALPN h2 -> ends "...h2"
	if ja4[3] != 'd' {
		t.Fatalf("JA4 should mark SNI present (d): %q", ja4)
	}
}
