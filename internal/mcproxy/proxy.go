package mcproxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"time"

	"aggershield/internal/banlist"
	"aggershield/internal/config"
	"aggershield/internal/connlimit"
	"aggershield/internal/metrics"
	"aggershield/internal/ratelimit"
)

// Proxy is a protocol-aware Minecraft TCP proxy.
type Proxy struct {
	listen   string
	upstream string
	hsTO     time.Duration
	banAbuse bool

	bans     *banlist.Store        // shared with the HTTP guard
	conns    *connlimit.Limiter    // concurrent connections per IP
	connRate *ratelimit.PerIP      // new connections per IP per second
	metrics  *metrics.Metrics
	log      *slog.Logger

	ln net.Listener
}

// New builds a Minecraft proxy. The ban store is shared with the HTTP guard so
// an IP banned in either place is banned everywhere.
func New(cfg config.Minecraft, bans *banlist.Store, mx *metrics.Metrics, log *slog.Logger) *Proxy {
	return &Proxy{
		listen:   cfg.Listen,
		upstream: cfg.Upstream,
		hsTO:     cfg.HandshakeTimeout.Std(),
		banAbuse: cfg.BanOnAbuse,
		bans:     bans,
		conns:    connlimit.New(cfg.MaxConnsPerIP),
		connRate: ratelimit.NewPerIP(cfg.NewConnsPerSec, cfg.NewConnsBurst, 100000, 30*time.Second, 5*time.Minute),
		metrics:  mx,
		log:      log,
	}
}

// ListenAndServe starts accepting connections until ctx is cancelled.
func (p *Proxy) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.listen)
	if err != nil {
		return err
	}
	p.ln = ln
	p.log.Info("Minecraft proxy listening", "listen", p.listen, "upstream", p.upstream)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil // clean shutdown
			default:
				p.log.Warn("mc accept error", "err", err)
				continue
			}
		}
		go p.handle(conn)
	}
}

func (p *Proxy) handle(client net.Conn) {
	defer client.Close()
	p.metrics.McConnTotal.Add(1)
	ip := hostOf(client.RemoteAddr())

	// 1. Ban check (shared list).
	if p.bans.IsBanned(ip) {
		p.reject(ip, "banned")
		return
	}
	// 2. New-connection rate (the main anti-flood lever).
	if !p.connRate.Allow(ip) {
		if p.banAbuse {
			p.bans.Ban(ip)
		}
		p.reject(ip, "new-conn-rate")
		return
	}
	// 3. Concurrent-connection cap per IP.
	release, ok := p.conns.Acquire(ip)
	if !ok {
		p.reject(ip, "max-conns-per-ip")
		return
	}
	defer release()

	// 4. Read + validate the handshake within the timeout (anti-slowloris).
	_ = client.SetReadDeadline(time.Now().Add(p.hsTO))
	hs, raw, err := readHandshake(client)
	if err != nil {
		if p.banAbuse {
			p.bans.Ban(ip) // malformed handshake is a strong bot signal
		}
		p.reject(ip, "bad-handshake")
		return
	}
	_ = client.SetReadDeadline(time.Time{}) // clear deadline for the live session

	// 5. Dial the real server and replay the handshake we consumed.
	up, err := net.DialTimeout("tcp", p.upstream, 5*time.Second)
	if err != nil {
		p.log.Error("mc upstream dial failed", "err", err, "upstream", p.upstream)
		return
	}
	defer up.Close()
	if _, err := up.Write(raw); err != nil {
		return
	}

	p.log.Debug("mc connection accepted", "ip", ip, "next_state", hs.nextState, "addr", hs.address)

	// 6. Splice the two streams together until either side closes.
	done := make(chan struct{}, 2)
	go pipe(up, client, done)
	go pipe(client, up, done)
	<-done
}

func (p *Proxy) reject(ip, reason string) {
	p.metrics.McConnRejected.Add(1)
	p.log.Warn("mc connection rejected", "ip", ip, "reason", reason)
}

func pipe(dst, src net.Conn, done chan<- struct{}) {
	_, _ = io.Copy(dst, src)
	// Unblock the partner copy by closing the write side.
	if c, ok := dst.(*net.TCPConn); ok {
		_ = c.CloseWrite()
	}
	done <- struct{}{}
}

func hostOf(addr net.Addr) string {
	if h, _, err := net.SplitHostPort(addr.String()); err == nil {
		return h
	}
	return addr.String()
}
