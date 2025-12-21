package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	defaultTestTimeout = 30 * time.Second
	shortTestTimeout   = 10 * time.Second
	sshDialTimeout     = 5 * time.Second
)

type tlogHandler struct {
	t     *testing.T
	level slog.Level
	attrs []slog.Attr
}

func (h *tlogHandler) Enabled(_ context.Context, lvl slog.Level) bool {
	return lvl >= h.level
}

func (h *tlogHandler) Handle(_ context.Context, rec slog.Record) error {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "level=%s msg=%q", rec.Level.String(), rec.Message)
	for _, a := range h.attrs {

		if a.Key != "" {
			_, _ = fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
		}
	}
	rec.Attrs(func(a slog.Attr) bool {

		if a.Key != "" {
			_, _ = fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
		}
		return true
	})
	h.t.Log(b.String())
	return nil
}

func (h *tlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cp := *h
	cp.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &cp
}

func (h *tlogHandler) WithGroup(_ string) slog.Handler {
	return h
}

func enableTestLogging(t *testing.T) func() {
	orig := slog.Default()
	logger := slog.New(&tlogHandler{t: t, level: slog.LevelDebug})
	slog.SetDefault(logger)
	return func() { slog.SetDefault(orig) }
}

var (
	testHostKey     ssh.Signer
	testCAKey       ssh.Signer
	testLiloKey     ssh.Signer
	testStitchKey   ssh.Signer
	testCertuserKey ssh.Signer
	testWrongKey    ssh.Signer
	target1HostKey  ssh.Signer
	target2HostKey  ssh.Signer
)

func init() {
	testHostKey = loadKey("../test/keys/host_key")
	testCAKey = loadKey("../test/keys/ca_key")
	testLiloKey = loadKey("../test/keys/lilo_key")
	testStitchKey = loadKey("../test/keys/stitch_key")
	testCertuserKey = loadKey("../test/keys/certuser_key")
	testWrongKey = generateTestKey()
	target1HostKey = generateTestKey()
	target2HostKey = generateTestKey()
}

func loadKey(path string) ssh.Signer {
	data, err := os.ReadFile(path)
	if err != nil {
		return generateTestKey()
	}

	keyBytes, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		panic(fmt.Sprintf("decode key %s: %v", path, err))
	}

	if len(keyBytes) != ed25519.PrivateKeySize {
		panic(fmt.Sprintf("invalid key size for %s: got %d, want %d", path, len(keyBytes), ed25519.PrivateKeySize))
	}

	privKey := ed25519.PrivateKey(keyBytes)
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		panic(fmt.Sprintf("create signer from key %s: %v", path, err))
	}
	return signer
}

func generateTestKey() ssh.Signer {
	key, err := ssh.NewSignerFromKey(mustGenerateEd25519())
	if err != nil {
		panic(err)
	}
	return key
}

func mustGenerateEd25519() interface{} {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv
}

func newSSHClientConfig(user string, key ssh.Signer) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         sshDialTimeout,
	}
}

func createTestCert(key ssh.Signer, caKey ssh.Signer, principal string) (ssh.Signer, error) {
	cert := &ssh.Certificate{
		Key:             key.PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           principal + "-cert",
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(time.Now().Unix() - 60),
		ValidBefore:     uint64(time.Now().Unix() + 3600),
	}
	signer, _ := caKey.(ssh.AlgorithmSigner)
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, err
	}
	return ssh.NewCertSigner(cert, key)
}

func waitForPort(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", addr)
}

func setupTestDirs(t *testing.T) (string, func()) {
	tmpDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmpDir, "ca"), 0755); err != nil {
		t.Fatalf("mkdir ca: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "hostkeys"), 0755); err != nil {
		t.Fatalf("mkdir hostkeys: %v", err)
	}
	caPubPath := filepath.Join(tmpDir, "ca", "ca.pub")
	if err := os.WriteFile(caPubPath, ssh.MarshalAuthorizedKey(testCAKey.PublicKey()), 0644); err != nil {
		t.Fatalf("write ca.pub: %v", err)
	}
	hostKeyPath := filepath.Join(tmpDir, "hostkeys", "ssh_host_ed25519_key")
	if _, err := os.Stat(hostKeyPath); err != nil {
		if err := os.WriteFile(hostKeyPath, []byte{}, 0600); err != nil {
			t.Fatalf("write host key: %v", err)
		}
	}
	cleanup := func() {}
	return tmpDir, cleanup
}

type Target struct {
	hostKey ssh.Signer
}

type mockServerContext struct {
	ctx          context.Context
	cancel       context.CancelFunc
	tmpDir       string
	cleanup      func()
	bastilleAddr string
	targetAddrs  []string
}

func newMockServerContext(t *testing.T, timeout time.Duration) *mockServerContext {
	tmpDir, cleanup := setupTestDirs(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	restore := enableTestLogging(t)
	t.Cleanup(restore)

	return &mockServerContext{
		ctx:     ctx,
		cancel:  cancel,
		tmpDir:  tmpDir,
		cleanup: cleanup,
	}
}

func (m *mockServerContext) close() {
	m.cancel()
	m.cleanup()
}

func (m *mockServerContext) startTargets(t *testing.T, targets ...Target) {
	m.targetAddrs = make([]string, 0, len(targets))
	for _, target := range targets {
		addr, err := startMockSSHServer(m.ctx, target.hostKey)
		if err != nil {
			t.Fatalf("failed to start target: %v", err)
		}
		m.targetAddrs = append(m.targetAddrs, addr)
	}
}

func (m *mockServerContext) startBastille(t *testing.T, opts ...func(*Config)) *Server {
	return m.startBastilleWithMode(t, "keys", opts...)
}

func (m *mockServerContext) startBastilleWithMode(t *testing.T, mode string, opts ...func(*Config)) *Server {
	cfg := Config{
		ADDRESS:      "127.0.0.1:0",
		LogLevel:     "ERROR",
		Testing:      true,
		RateLimit:    100,
		MaxTunnels:   10,
		DialTO:       5 * time.Second,
		HOST_BASE:    filepath.Join(m.tmpDir, "hostkeys"),
		HOST_KEYS:    []string{"ssh_host_ed25519_key"},
		CERT_BASE:    filepath.Join(m.tmpDir, "ca"),
		CERT_KEYS:    []string{"ca.pub"},
		AUTH_BASE:    filepath.Join(m.tmpDir, "home"),
		AUTH_KEYS:    []string{"{user}/authorized_keys"},
		AUTH_MODE:    mode,
		Ciphers:      []string{"chacha20-poly1305@openssh.com"},
		KeyExchanges: []string{"curve25519-sha256"},
		MACs:         []string{"hmac-sha2-256-etm@openssh.com"},
		SMTPPort:     587,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	m.writeAuthorizedKeys(t)

	// If not cert-only, reuse the generic startup
	if cfg.AUTH_MODE != "certs" {
		server, addr, err := startBastilleServer(m.ctx, t, cfg)
		if err != nil {
			t.Fatalf("failed to start bastille: %v", err)
		}
		m.bastilleAddr = addr
		slog.Info("bastille listening (test)", "addr", addr, "mode", cfg.AUTH_MODE)
		return server
	}

	// Cert-only: enforce certificate presence during auth
	srv := newSSHServerConfig(&cfg, true)

	ln, err := net.Listen("tcp", cfg.ADDRESS)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go func() {
		<-m.ctx.Done()
		ln.Close()
	}()

	server := NewServer(cfg)
	go server.serve(m.ctx, srv, ln)

	actualAddr := ln.Addr().String()
	if err := waitForPort(actualAddr, 2*time.Second); err != nil {
		t.Fatalf("bastille not ready: %v", err)
	}
	m.bastilleAddr = actualAddr
	slog.Info("bastille (cert-only) listening (test)", "addr", actualAddr)
	return server
}

func (m *mockServerContext) startBastilleCertOnly(t *testing.T) *Server {
	return m.startBastilleWithMode(t, "certs")
}

func (m *mockServerContext) writeAuthorizedKeys(t *testing.T) {
	home := filepath.Join(m.tmpDir, "home")
	if err := os.MkdirAll(filepath.Join(home, "lilo"), 0755); err != nil {
		t.Fatalf("mkdir lilo: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(home, "stitch"), 0755); err != nil {
		t.Fatalf("mkdir stitch: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(home, "certuser"), 0755); err != nil {
		t.Fatalf("mkdir certuser: %v", err)
	}

	write := func(path, content string) {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	var liloPermits []string
	for _, addr := range m.targetAddrs {
		liloPermits = append(liloPermits, fmt.Sprintf(`permitopen="%s"`, addr))
	}
	if len(liloPermits) == 0 {
		liloPermits = append(liloPermits, `permitopen="127.0.0.1:*"`)
	}
	liloLine := fmt.Sprintf("%s %s",
		strings.Join(liloPermits, ","),
		string(ssh.MarshalAuthorizedKey(testLiloKey.PublicKey())),
	)
	write(filepath.Join(home, "lilo", "authorized_keys"), liloLine)

	stitchPerm := ""
	if len(m.targetAddrs) >= 2 {
		stitchPerm = fmt.Sprintf(`permitopen="%s" `, m.targetAddrs[1])
	}
	stitchLine := fmt.Sprintf("%s%s",
		stitchPerm,
		string(ssh.MarshalAuthorizedKey(testStitchKey.PublicKey())),
	)
	write(filepath.Join(home, "stitch", "authorized_keys"), stitchLine)

	certPerm := ""
	if len(m.targetAddrs) >= 1 {
		certPerm = fmt.Sprintf(`permitopen="%s" `, m.targetAddrs[0])
	}
	write(filepath.Join(home, "certuser", "authorized_keys"), certPerm)
}

func startMockSSHServer(ctx context.Context, hostKey ssh.Signer) (string, error) {
	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	config.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}

	actualAddr := listener.Addr().String()
	slog.Info("mock target listening", "addr", actualAddr)

	var wg sync.WaitGroup
	done := make(chan struct{})

	wg.Add(1)
	go func() {
		defer close(done)
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleMockSSH(conn, config)
		}
	}()

	go func() {
		<-ctx.Done()
		listener.Close()
		wg.Wait()
	}()

	if err := waitForPort(actualAddr, 2*time.Second); err != nil {
		listener.Close()
		return "", err
	}

	return actualAddr, nil
}

func handleMockSSH(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer sconn.Close()

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChan.Accept()
		if err != nil {
			continue
		}

		go func() {
			for req := range requests {
				if req.Type == "exec" {
					req.Reply(true, nil)
					channel.Write([]byte("mock-target-response\n"))
					channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					channel.Close()
				}
			}
		}()
	}
}

func newSSHServerConfig(cfg *Config, certOnly bool) *ssh.ServerConfig {
	srv := &ssh.ServerConfig{
		Config: ssh.Config{
			Ciphers:      cfg.Ciphers,
			KeyExchanges: cfg.KeyExchanges,
			MACs:         cfg.MACs,
		},
	}
	srv.AddHostKey(testHostKey)

	caPub := []ssh.PublicKey{testCAKey.PublicKey()}
	cChecker := certChecker(cfg, caPub, cfg.AUTH_KEYS)

	srv.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if certOnly {
			if _, ok := key.(*ssh.Certificate); !ok {
				return nil, errors.New("cert required")
			}
		}
		perms, err := cChecker.Authenticate(meta, key)
		if err != nil {
			return nil, err
		}
		if perms == nil {
			perms = &ssh.Permissions{}
		}
		if perms.Extensions == nil {
			perms.Extensions = make(map[string]string)
		}
		if opts := loadCertPermit(cfg, meta.User()); opts != "" {
			perms.Extensions[permissionKey] = opts
		}
		return perms, nil
	}
	return srv
}

func startBastilleServer(ctx context.Context, t *testing.T, cfg Config) (*Server, string, error) {

	srv := newSSHServerConfig(&cfg, cfg.AUTH_MODE == "certs")

	ln, err := net.Listen("tcp", cfg.ADDRESS)
	if err != nil {
		return nil, "", err
	}

	actualAddr := ln.Addr().String()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	server := NewServer(cfg)
	go server.serve(ctx, srv, ln)

	if err := waitForPort(actualAddr, 2*time.Second); err != nil {
		ln.Close()
		return nil, "", err
	}

	return server, actualAddr, nil
}

func sshConnect(user, proxyUser, proxyAddr, targetAddr string, key ssh.Signer) (*ssh.Client, error) {
	proxyConfig := &ssh.ClientConfig{
		User: proxyUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	proxyConn, err := ssh.Dial("tcp", proxyAddr, proxyConfig)
	if err != nil {
		return nil, fmt.Errorf("proxy dial failed: %w", err)
	}

	targetHost, targetPort, err := net.SplitHostPort(targetAddr)
	if err != nil {
		proxyConn.Close()
		return nil, err
	}

	conn, err := proxyConn.Dial("tcp", fmt.Sprintf("%s:%s", targetHost, targetPort))
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("target dial failed: %w", err)
	}

	targetConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	ncc, chans, reqs, err := ssh.NewClientConn(conn, targetAddr, targetConfig)
	if err != nil {
		conn.Close()
		proxyConn.Close()
		return nil, fmt.Errorf("target handshake failed: %w", err)
	}

	return ssh.NewClient(ncc, chans, reqs), nil
}
