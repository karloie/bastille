package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	handshakeTimeout = 10 * time.Second
	rateLimitWindow  = time.Minute
	channelTypeTCP   = "direct-tcpip"
)

type Server struct {
	cfg       Config
	rateMu    sync.Mutex
	rateCnt   map[string]int
	rateNext  time.Time
	tunnelsMu sync.Mutex
	tunnels   map[string]int
}

func NewServer(cfg Config) *Server {
	return &Server{
		cfg:      cfg,
		rateCnt:  make(map[string]int),
		rateNext: time.Now().Add(rateLimitWindow),
		tunnels:  make(map[string]int),
	}
}

func main() {
	cfg := LoadConfig()

	level := slog.LevelInfo
	if v, ok := map[string]slog.Level{
		"DEBUG":   slog.LevelDebug,
		"VERBOSE": slog.LevelDebug - 1,
		"INFO":    slog.LevelInfo,
		"WARN":    slog.LevelWarn,
		"ERROR":   slog.LevelError,
	}[cfg.LogLevel]; ok {
		level = v
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
	slog.Info("Bastille started", "src", "bastille", "version", Version, "commit", GitCommit, "buildTime", BuildTime)

	certOnly := cfg.AUTH_MODE == "certs"
	srv := newBastilleServerConfig(&cfg, certOnly)
	if srv == nil {
		slog.Error("no host keys loaded; refusing to start")
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", cfg.ADDRESS)
	if err != nil {
		slog.Error("listen failed", "src", "bastille", "error", err)
		os.Exit(1)
	}

	slog.Info(
		"Bastille listening",
		"src", "bastille",
		"addr", cfg.ADDRESS,
		"authMode", cfg.AUTH_MODE,
		"maxTunnels", cfg.MaxTunnels,
		"rateLimit", cfg.RateLimit,
		"strictModes", cfg.StrictModes,
		"ciphers", len(cfg.Ciphers),
		"kex", len(cfg.KeyExchanges),
		"macs", len(cfg.MACs),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := NewServer(cfg)
	server.serve(ctx, srv, ln)
}

func (s *Server) serve(ctx context.Context, srv *ssh.ServerConfig, ln net.Listener) {
	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			s.handleConn(ctx, c, srv)
		}(c)
	}
	wg.Wait()
}

func (s *Server) handleConn(ctx context.Context, c net.Conn, srv *ssh.ServerConfig) {
	defer c.Close()
	ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())

	var id [8]byte
	_, _ = rand.Read(id[:])
	cid := hex.EncodeToString(id[:])

	s.rateMu.Lock()
	if time.Now().After(s.rateNext) {
		s.rateCnt = map[string]int{}
		s.rateNext = time.Now().Add(rateLimitWindow)
	}
	s.rateCnt[ip]++
	block := s.rateCnt[ip] > s.cfg.RateLimit
	s.rateMu.Unlock()

	if block {
		logEvent("debug", cid, nil, ip, "rate limited", nil, nil)
		return
	}

	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	sshConn, chans, reqs, err := ssh.NewServerConn(c, srv)
	_ = c.SetDeadline(time.Time{})
	if err != nil {
		logEvent("debug", cid, nil, ip, "handshake failed", nil, err)
		return
	}
	logEvent("debug", cid, sshConn, ip, "handshake", nil, nil)
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for {
		select {
		case <-ctx.Done():
			logEvent("debug", cid, sshConn, ip, "connection canceled", nil, nil)
			return

		case ch, ok := <-chans:
			if !ok {
				return
			}
			if ch.ChannelType() != channelTypeTCP {
				_ = ch.Reject(ssh.UnknownChannelType, channelTypeTCP+" only")
				continue
			}

			dst := dstFromExtra(ch.ExtraData())

			if !s.allowedTunnel(sshConn, dst) {
				logEvent("warn", cid, sshConn, dst, "tunnel denied", nil, nil)
				_ = ch.Reject(ssh.ConnectionFailed, "denied")
				continue
			}

			u := sshConn.User()
			s.tunnelsMu.Lock()
			s.tunnels[u]++
			if s.tunnels[u] > s.cfg.MaxTunnels {
				s.tunnels[u]--
				s.tunnelsMu.Unlock()
				logEvent("warn", cid, sshConn, dst, "too many tunnels", nil, nil)
				_ = ch.Reject(ssh.ResourceShortage, "limit")
				continue
			}
			s.tunnelsMu.Unlock()

			go s.proxy(ctx, cid, ch, dst, sshConn)
		}
	}
}

func dstFromExtra(extra []byte) string {
	var p struct {
		DstHost string
		DstPort uint32
		SrcIP   string
		SrcPort uint32
	}
	_ = ssh.Unmarshal(extra, &p)
	return fmt.Sprintf("%s:%d", p.DstHost, p.DstPort)
}

func (s *Server) allowedTunnel(conn *ssh.ServerConn, dst string) bool {
	if conn == nil || conn.Permissions == nil || conn.Permissions.Extensions == nil {
		return false
	}
	opts := conn.Permissions.Extensions[permissionKey]
	return permitAllowed(opts, dst)
}

func (s *Server) proxy(ctx context.Context, cid string, ch ssh.NewChannel, dst string, sshConn *ssh.ServerConn) {
	defer func() {
		s.tunnelsMu.Lock()
		if s.tunnels[sshConn.User()] > 0 {
			s.tunnels[sshConn.User()]--
		}
		s.tunnelsMu.Unlock()
	}()

	var d net.Dialer
	d.Timeout = s.cfg.DialTO
	dstConn, err := d.DialContext(ctx, "tcp", dst)
	if err != nil {
		_ = ch.Reject(ssh.ConnectionFailed, err.Error())
		logEvent("warn", cid, sshConn, dst, "dial failed", nil, err)
		return
	}

	sc, reqs, err := ch.Accept()
	if err != nil {
		_ = dstConn.Close()
		logEvent("warn", cid, sshConn, dst, "channel accept failed", nil, err)
		return
	}
	go ssh.DiscardRequests(reqs)

	logEvent("info", cid, sshConn, dst, "tunnel opened", nil, nil)

	go sendTunnelNotification(&s.cfg, sshConn.User(), sshConn.RemoteAddr().String(), dst)

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(dstConn, sc); done <- struct{}{} }()
	go func() { _, _ = io.Copy(sc, dstConn); done <- struct{}{} }()

	select {
	case <-ctx.Done():
		_ = dstConn.Close()
		_ = sc.Close()
	case <-done:
		_ = dstConn.Close()
		_ = sc.Close()
	}
	<-done

	logEvent("debug", cid, sshConn, dst, "tunnel closed", nil, nil)
}

func logEvent(lvl string, cid string, meta ssh.ConnMetadata, dst, msg string, value any, err error) {
	attrs := []any{"src", "bastille"}
	if cid != "" {
		attrs = append(attrs, "i", cid)
	}
	if meta != nil {
		attrs = append(attrs, "u", meta.User(), "s", meta.RemoteAddr().String())
	}
	if dst != "" {
		attrs = append(attrs, "t", dst)
	}
	if v, ok := value.(string); ok && strings.HasPrefix(v, "SHA256:") {
		attrs = append(attrs, "k", v)
	} else if value != nil {
		attrs = append(attrs, "v", value)
	}
	if err != nil {
		attrs = append(attrs, "error", err)
	}

	switch lvl {
	case "debug":
		slog.Debug(msg, attrs...)
	case "warn":
		slog.Warn(msg, attrs...)
	case "err":
		slog.Error(msg, attrs...)
	case "fatal":
		slog.Error(msg, attrs...)
		os.Exit(1)
	default:
		slog.Info(msg, attrs...)
	}
}
