package mcproxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"aggershield/internal/banlist"
	"aggershield/internal/config"
	"aggershield/internal/metrics"
)

func putVarInt(buf *bytes.Buffer, v int) {
	uv := uint32(v)
	for {
		b := byte(uv & 0x7F)
		uv >>= 7
		if uv != 0 {
			b |= 0x80
		}
		buf.WriteByte(b)
		if uv == 0 {
			return
		}
	}
}

// buildHandshake encodes a handshake packet (length-prefixed).
func buildHandshake(proto int, addr string, port uint16, nextState int) []byte {
	var payload bytes.Buffer
	putVarInt(&payload, 0x00) // packet id
	putVarInt(&payload, proto)
	putVarInt(&payload, len(addr))
	payload.WriteString(addr)
	payload.WriteByte(byte(port >> 8))
	payload.WriteByte(byte(port))
	putVarInt(&payload, nextState)

	var pkt bytes.Buffer
	putVarInt(&pkt, payload.Len())
	pkt.Write(payload.Bytes())
	return pkt.Bytes()
}

func TestReadHandshakeValid(t *testing.T) {
	raw := buildHandshake(765, "play.example.com", 25565, stateLogin)
	hs, gotRaw, err := readHandshake(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("readHandshake: %v", err)
	}
	if hs.protocol != 765 || hs.address != "play.example.com" || hs.port != 25565 || hs.nextState != stateLogin {
		t.Fatalf("parsed wrong: %+v", hs)
	}
	if !bytes.Equal(gotRaw, raw) {
		t.Fatalf("raw bytes for replay don't match input")
	}
}

func TestReadHandshakeRejectsJunk(t *testing.T) {
	cases := [][]byte{
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, // VarInt length never terminates
		{0x01, 0x05},                         // claims length 1, wrong packet id (0x05)
		buildHandshake(765, "x", 25565, 9),   // invalid next state
	}
	for i, c := range cases {
		if _, _, err := readHandshake(bytes.NewReader(c)); err == nil {
			t.Fatalf("case %d: expected error for junk input", i)
		}
	}
}

func TestReadHandshakeNoOverRead(t *testing.T) {
	// A handshake immediately followed by a second packet: readHandshake must
	// consume ONLY the handshake, leaving the rest for the splice.
	hs := buildHandshake(765, "a", 25565, stateStatus)
	extra := []byte{0x01, 0x00} // a status-request packet
	r := bytes.NewReader(append(append([]byte{}, hs...), extra...))
	if _, _, err := readHandshake(r); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(r)
	if !bytes.Equal(rest, extra) {
		t.Fatalf("over-read: leftover %v, want %v", rest, extra)
	}
}

// TestProxyForwardsToUpstream is an end-to-end test against a fake TCP backend.
func TestProxyForwardsToUpstream(t *testing.T) {
	// Fake MC server: reads everything and echoes a marker back.
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 256)
		n, _ := c.Read(buf) // should be the replayed handshake
		_, _ = c.Write(append([]byte("UPSTREAM-GOT:"), buf[:n]...))
	}()

	cfg := config.Minecraft{
		Listen: "127.0.0.1:0", Upstream: backend.Addr().String(),
		MaxConnsPerIP: 8, NewConnsPerSec: 100, NewConnsBurst: 100,
		HandshakeTimeout: config.Duration(2 * time.Second),
	}
	bans := banlist.New(time.Minute, time.Hour, 2, time.Hour, 1000, nil)
	defer bans.Close()
	p := New(cfg, bans, metrics.New(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p.ln = ln
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(conn)
		}
	}()
	go func() { <-ctx.Done(); ln.Close() }()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	hs := buildHandshake(765, "play.example.com", 25565, stateLogin)
	if _, err := client.Write(hs); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, 512)
	n, err := client.Read(resp)
	if err != nil {
		t.Fatalf("reading proxied response: %v", err)
	}
	if !bytes.HasPrefix(resp[:n], []byte("UPSTREAM-GOT:")) {
		t.Fatalf("did not get upstream response, got %q", resp[:n])
	}
	if !bytes.Contains(resp[:n], hs) {
		t.Fatalf("handshake was not replayed intact to upstream")
	}
}

func TestProxyBlocksBannedIP(t *testing.T) {
	bans := banlist.New(time.Minute, time.Hour, 2, time.Hour, 1000, nil)
	defer bans.Close()
	bans.BanFor("127.0.0.1", time.Minute)

	cfg := config.Minecraft{
		Upstream: "127.0.0.1:1", MaxConnsPerIP: 8,
		NewConnsPerSec: 100, NewConnsBurst: 100,
		HandshakeTimeout: config.Duration(time.Second),
	}
	mx := metrics.New()
	p := New(cfg, bans, mx, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(c)
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// The proxy should close the connection without forwarding anything.
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, err := client.Read(buf)
	if err == nil && n > 0 {
		t.Fatalf("banned IP should get no data, got %q", buf[:n])
	}
	if mx.McConnRejected.Load() != 1 {
		t.Fatalf("expected 1 rejected connection, got %d", mx.McConnRejected.Load())
	}
}
