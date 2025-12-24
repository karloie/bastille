package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
)

const (
	handshakeTimeout = 10 * time.Second
	channelTypeTCP   = "direct-tcpip"
)

var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = ""
)

type Server struct {
	cfg       Config
	rateMu    sync.Mutex
	rate      map[string]*rate.Limiter
	tunnelsMu sync.Mutex
	tunnels   map[string]int
	metrics   *Metrics
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
	
	metrics := NewMetrics()
	if cfg.MetricsAddress != "" {
		metrics.Enable()
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", metrics.Handler())
			mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok\n"))
			})
			slog.Info("Metrics server starting", "src", "bastille", "addr", cfg.MetricsAddress)
			if err := http.ListenAndServe(cfg.MetricsAddress, mux); err != nil {
				slog.Error("metrics server failed", "src", "bastille", "error", err)
			}
		}()
	}
	
	certOnly := cfg.AuthMode == "certs"
	srv := newSSHServerConfig(&cfg, certOnly, metrics)
	if srv == nil {
		slog.Error("no host keys loaded; refusing to start")
		os.Exit(1)
	}
	bind := cfg.Address
	if bind == "" {
		bind = "0.0.0.0"
	}
	addr := net.JoinHostPort(bind, strconv.Itoa(cfg.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("listen failed", "src", "bastille", "error", err)
		os.Exit(1)
	}
	slog.Info(
		"Bastille listening",
		"src", "bastille",
		"addr", ln.Addr().String(),
		"mode", cfg.AuthMode,
		"strict", cfg.StrictMode,
		"ciphers", len(cfg.Ciphers),
		"kexs", len(cfg.KEXs),
		"macs", len(cfg.MACs),
	)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := NewServer(cfg, metrics)
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
	start := time.Now()
	s.metrics.RecordConnection()
	defer func() {
		s.metrics.RecordConnectionClosed()
		s.metrics.RecordConnectionDuration(time.Since(start))
	}()
	ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	var id [8]byte
	_, _ = rand.Read(id[:])
	cid := hex.EncodeToString(id[:])
	if s.cfg.MaxStartups > 0 {
		s.rateMu.Lock()
		lim := s.rate[ip]
		if lim == nil {
			r := rate.Every(time.Minute / time.Duration(s.cfg.MaxStartups))
			lim = rate.NewLimiter(r, s.cfg.MaxStartups)
			s.rate[ip] = lim
		}
		allow := lim.Allow()
		s.rateMu.Unlock()
		if !allow {
			s.metrics.RecordRateLimitHit()
			logEvent("warn", cid, nil, ip, "rate limited", nil, nil)
			return
		}
	}
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	sshConn, chans, reqs, err := ssh.NewServerConn(c, srv)
	_ = c.SetDeadline(time.Time{})
	if err != nil {
		s.metrics.RecordHandshakeFailure()
		s.metrics.RecordConnectionFailed()
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
			dst := targetAddress(ch.ExtraData())
			if !isTunnelAllowed(sshConn.Permissions, dst) {
				s.metrics.RecordTunnelDenied()
				logEventWithDuration("err", cid, sshConn, dst, "tunnel denied", nil, nil, time.Since(start))
				_ = ch.Reject(ssh.ConnectionFailed, "denied")
				continue
			}
			u := sshConn.User()
			if !s.acquireTunnelSlot(u) {
				logEventWithDuration("warn", cid, sshConn, dst, "too many tunnels", nil, nil, time.Since(start))
				_ = ch.Reject(ssh.ResourceShortage, "limit")
				continue
			}
			go s.proxy(ctx, cid, ch, dst, sshConn, start)
		}
	}
}

func (s *Server) acquireTunnelSlot(user string) bool {
	if user == "" || s.cfg.MaxSessions <= 0 {
		return false
	}
	s.tunnelsMu.Lock()
	defer s.tunnelsMu.Unlock()
	s.tunnels[user]++
	if s.tunnels[user] > s.cfg.MaxSessions {
		s.tunnels[user]--
		return false
	}
	return true
}

func (s *Server) releaseTunnelSlot(user string) {
	if user == "" {
		return
	}
	s.tunnelsMu.Lock()
	if s.tunnels[user] > 0 {
		s.tunnels[user]--
	}
	s.tunnelsMu.Unlock()
}

func NewServer(cfg Config, metrics *Metrics) *Server {
	return &Server{
		cfg:     cfg,
		rate:    make(map[string]*rate.Limiter),
		tunnels: make(map[string]int),
		metrics: metrics,
	}
}

func targetAddress(payload []byte) string {
	var p struct {
		DstHost string
		DstPort uint32
		SrcIP   string
		SrcPort uint32
	}
	_ = ssh.Unmarshal(payload, &p)
	return fmt.Sprintf("%s:%d", p.DstHost, p.DstPort)
}

func isTunnelAllowed(perms *ssh.Permissions, dst string) bool {
	if perms == nil || perms.Extensions == nil {
		return false
	}
	opts := perms.Extensions[permissionKey]
	return isPermitAllowed(opts, dst)
}

func (s *Server) proxy(ctx context.Context, cid string, ch ssh.NewChannel, dst string, sshConn *ssh.ServerConn, start time.Time) {
	defer s.releaseTunnelSlot(sshConn.User())
	var d net.Dialer
	d.Timeout = s.cfg.DialTimeout
	dstConn, err := d.DialContext(ctx, "tcp", dst)
	if err != nil {
		_ = ch.Reject(ssh.ConnectionFailed, err.Error())
		logEventWithDuration("warn", cid, sshConn, dst, "dial failed", nil, err, time.Since(start))
		return
	}
	sc, reqs, err := ch.Accept()
	if err != nil {
		_ = dstConn.Close()
		logEventWithDuration("warn", cid, sshConn, dst, "channel accept failed", nil, err, time.Since(start))
		return
	}
	go ssh.DiscardRequests(reqs)
	s.metrics.RecordTunnelOpened()
	logEventWithDuration("info", cid, sshConn, dst, "tunnel opened", nil, nil, time.Since(start))
	go sendTunnelNotification(ctx, &s.cfg, sshConn.User(), sshConn.RemoteAddr().String(), dst)
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(dstConn, sc)
		s.metrics.RecordBytesOut(n)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(sc, dstConn)
		s.metrics.RecordBytesIn(n)
		done <- struct{}{}
	}()
	select {
	case <-ctx.Done():
		_ = dstConn.Close()
		_ = sc.Close()
	case <-done:
		_ = dstConn.Close()
		_ = sc.Close()
	}
	<-done
	s.metrics.RecordTunnelClosed()
	logEventWithDuration("debug", cid, sshConn, dst, "tunnel closed", nil, nil, time.Since(start))
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

func logEventWithDuration(lvl string, cid string, meta ssh.ConnMetadata, dst, msg string, value any, err error, duration time.Duration) {
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
	if duration > 0 {
		attrs = append(attrs, "d", fmt.Sprintf("%.0fms", duration.Seconds()*1000))
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
