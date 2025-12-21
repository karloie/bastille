package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"log/slog"

	"golang.org/x/crypto/ssh"
)

var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = ""
)

const (
	handshakeTimeout = 10 * time.Second
	rateLimitWindow  = time.Minute
	channelTypeTCP   = "direct-tcpip"
	permissionKey    = "opts"
	permGroupOther   = 0o022
)

var (
	rxPermit       = regexp.MustCompile(`permitopen="?([^"]+)"?`)
	rxUserSanitize = regexp.MustCompile(`[^a-zA-Z0-9._-]`)
)

func permitMatch(pattern, dst string) bool {
	pattern = strings.TrimSpace(pattern)
	ph, pp, ok := strings.Cut(pattern, ":")
	if !ok {
		return false
	}
	dh, dp, ok := strings.Cut(dst, ":")
	if !ok {
		return false
	}
	hostOK := ph == "*" || ph == dh
	portOK := pp == "*" || pp == dp
	return hostOK && portOK
}

func permitAllowed(opts, dst string) bool {
	if opts == "" {
		return false
	}
	for _, o := range strings.Split(opts, ",") {
		if m := rxPermit.FindStringSubmatch(o); len(m) > 1 && permitMatch(m[1], dst) {
			return true
		}
	}
	return false
}

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

	var level slog.Level
	switch cfg.LogLevel {
	case "DEBUG":
		level = slog.LevelDebug
	case "VERBOSE":
		level = slog.LevelDebug - 1
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
	slog.Info("Bastille started", "version", Version, "commit", GitCommit, "buildTime", BuildTime)
	srv := &ssh.ServerConfig{Config: ssh.Config{
		Ciphers:      cfg.Ciphers,
		KeyExchanges: cfg.KeyExchanges,
		MACs:         cfg.MACs,
	}}
	if n := loadHostkeys(&cfg, cfg.HOST_BASE, cfg.HOST_KEYS, srv); n == 0 {
		slog.Error("no host keys loaded; refusing to start")
		os.Exit(1)
	}
	caPub := loadCaKeys(&cfg, cfg.CERT_BASE, cfg.CERT_KEYS)
	cChecker := certChecker(&cfg, caPub, cfg.AUTH_KEYS)
	srv.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if cfg.AUTH_MODE == "certs" {
			if _, ok := key.(*ssh.Certificate); !ok {
				return nil, errors.New("cert required")
			}
		}
		perms, err := cChecker.Authenticate(meta, key)
		if err != nil {
			logEvent("warn", "", meta, "", "auth denied", keyHash(key), err)
			return nil, err
		}
		if perms == nil {
			perms = &ssh.Permissions{}
		}
		if perms.Extensions == nil {
			perms.Extensions = make(map[string]string)
		}
		logEvent("debug", "", meta, "", "auth allowed", keyHash(key), nil)
		if _, isCert := key.(*ssh.Certificate); isCert {
			if opts := loadCertPermit(&cfg, meta.User()); opts != "" {
				perms.Extensions[permissionKey] = opts
			}
		}
		return perms, nil
	}
	ln, err := net.Listen("tcp", cfg.ADDRESS)
	if err != nil {
		slog.Error("listen failed", "error", err)
		os.Exit(1)
	}
	slog.Info("Bastille listening", "config", cfg.String())
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

func (server *Server) proxy(ctx context.Context, cid string, ch ssh.NewChannel, dst string, sshConn *ssh.ServerConn) {
	defer func() {
		server.tunnelsMu.Lock()
		if server.tunnels[sshConn.User()] > 0 {
			server.tunnels[sshConn.User()]--
		}
		server.tunnelsMu.Unlock()
	}()

	var d net.Dialer
	d.Timeout = server.cfg.DialTO
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

	go sendTunnelNotification(&server.cfg, sshConn.User(), sshConn.RemoteAddr().String(), dst)

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

func loadCertPermit(cfg *Config, user string) string {
	for _, tmpl := range cfg.AUTH_KEYS {
		path := filepath.Join(cfg.AUTH_BASE, strings.ReplaceAll(tmpl, "{user}", user))
		if cfg.StrictModes && !strictPathOK(cfg, path) {
			continue
		}
		if opts := readPermitOptions(path); opts != "" {
			return opts
		}
	}
	return ""
}

func readPermitOptions(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	var permits []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lineBytes := sc.Bytes()
		if _, _, opts, _, err := ssh.ParseAuthorizedKey(lineBytes); err == nil && len(opts) > 0 {
			for _, o := range opts {
				if rxPermit.MatchString(o) {
					permits = append(permits, o)
				}
			}
			continue
		}
		raw := sc.Text()
		for _, part := range strings.Split(raw, ",") {
			p := strings.TrimSpace(part)
			if rxPermit.MatchString(p) {
				permits = append(permits, p)
			}
		}
	}
	if len(permits) == 0 {
		return ""
	}
	seen := make(map[string]struct{}, len(permits))
	var out []string
	for _, v := range permits {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return strings.Join(out, ",")
}

func strictPathOK(cfg *Config, path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	mode := fi.Mode()
	if mode&os.ModeSymlink != 0 || !mode.IsRegular() {
		return false
	}
	if mode.Perm()&permGroupOther != 0 {
		return false
	}
	dir := filepath.Dir(path)
	di, err := os.Stat(dir)
	if err != nil {
		return false
	}
	if di.Mode().Perm()&permGroupOther != 0 {
		return false
	}
	if rel, err := filepath.Rel(cfg.AUTH_BASE, path); err != nil || strings.HasPrefix(rel, "..") {
		return false
	}
	return true
}

func logEvent(lvl string, cid string, meta ssh.ConnMetadata, dst, msg string, value any, err error) {
	attrs := []any{}
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
