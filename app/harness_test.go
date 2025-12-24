package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	defaultTestTimeout = 30 * time.Second
	shortTestTimeout   = 10 * time.Second
)

func TestMain(m *testing.M) {
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	slog.SetDefault(slog.New(handler))
	os.Exit(m.Run())
}

func setEnv(t *testing.T, k, v string) {
	t.Helper()
	if err := os.Setenv(k, v); err != nil {
		t.Fatalf("setenv %s: %v", k, err)
	}
	t.Cleanup(func() { _ = os.Unsetenv(k) })
}

func withCapturedStderr(t *testing.T, fn func() error) (string, error) {
	t.Helper()

	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	t.Cleanup(func() { os.Stderr = orig })

	os.Stderr = w
	vErr := fn()

	_ = w.Close()
	out, _ := io.ReadAll(r)
	return string(out), vErr
}

func mustMkdirAll(t *testing.T, path string, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, perm); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path string, data string, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), perm); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustWriteFileChmod(t *testing.T, path string, data string, writePerm os.FileMode, chmodPerm os.FileMode) {
	t.Helper()
	mustWriteFile(t, path, data, writePerm)
	if err := os.Chmod(path, chmodPerm); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

func mustSymlink(t *testing.T, oldname, newname string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests are unreliable on Windows without elevated privileges")
	}
	if err := os.Symlink(oldname, newname); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}
}

func mustGenEd25519Signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

func mustAuthorizedKeyLine(t *testing.T, signer ssh.Signer, prefixOpts string) string {
	t.Helper()
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if prefixOpts != "" {
		return prefixOpts + " " + key + "\n"
	}
	return key + "\n"
}

func mustLoadCertPermit(t *testing.T, cfg *Config, user string) string {
	t.Helper()
	opts := loadCertPermit(cfg, user)
	if opts == "" {
		t.Fatalf("expected non-empty permit options for user %q", user)
	}
	return opts
}

func assertAllowedTunnel(t *testing.T, perms *ssh.Permissions, dst string) {
	t.Helper()
	if !isTunnelAllowed(perms, dst) {
		t.Fatalf("expected allow for %q", dst)
	}
}

func assertDeniedTunnel(t *testing.T, perms *ssh.Permissions, dst string) {
	t.Helper()
	if isTunnelAllowed(perms, dst) {
		t.Fatalf("expected deny for %q", dst)
	}
}

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }

type testConnMetadata struct {
	user string
	ra   net.Addr
	la   net.Addr
}

func (f *testConnMetadata) User() string          { return f.user }
func (f *testConnMetadata) SessionID() []byte     { return nil }
func (f *testConnMetadata) ClientVersion() []byte { return nil }
func (f *testConnMetadata) ServerVersion() []byte { return nil }
func (f *testConnMetadata) RemoteAddr() net.Addr  { return f.ra }
func (f *testConnMetadata) LocalAddr() net.Addr   { return f.la }

type testHarness struct {
	ctx         context.Context
	cancel      context.CancelFunc
	tmpDir      string
	serverAddr  string
	targetAddrs []string

	caKey     ssh.Signer
	liloKey   ssh.Signer
	stitchKey ssh.Signer
	naniKey   ssh.Signer
	wrongKey  ssh.Signer

	target1HostKey ssh.Signer
	target2HostKey ssh.Signer

	runTargets int // 0 = unchanged/default, 1 = one target, 2 = two targets
	preRunHook func(t *testing.T, h *testHarness, cfg *Config)
}

type HarnessScenario struct {
	Addr    string
	Targets []string
	Keys    HarnessKeys
	TmpDir  string
}

type HarnessKeys struct {
	CA     ssh.Signer
	Lilo   ssh.Signer
	Stitch ssh.Signer
	Nani   ssh.Signer
	Wrong  ssh.Signer
}

func (h *testHarness) Keys() HarnessKeys {
	return HarnessKeys{
		CA:     h.caKey,
		Lilo:   h.liloKey,
		Stitch: h.stitchKey,
		Nani:   h.naniKey,
		Wrong:  h.wrongKey,
	}
}

func (h *testHarness) Addr() string { return h.serverAddr }

func (h *testHarness) TargetAddrs() []string { return h.targetAddrs }

func (h *testHarness) TmpDir() string { return h.tmpDir }

func (h *testHarness) Scenario() HarnessScenario {
	targets := make([]string, len(h.targetAddrs))
	copy(targets, h.targetAddrs)

	return HarnessScenario{
		Addr:    h.serverAddr,
		Targets: targets,
		Keys:    h.Keys(),
		TmpDir:  h.tmpDir,
	}
}

func (h *testHarness) WithOneTarget() *testHarness {
	h.runTargets = 1
	return h
}

func (h *testHarness) WithTwoTargets() *testHarness {
	h.runTargets = 2
	return h
}

func (h *testHarness) WithPreRunConfig(fn func(t *testing.T, h *testHarness, cfg *Config)) *testHarness {
	h.preRunHook = fn
	return h
}

func (h *testHarness) startConfiguredTargets(t *testing.T) {
	switch h.runTargets {
	case 1:
		h.StartOneTarget(t)
	case 2:
		h.StartTwoTargets(t)
	default:
	}
}

func (h *testHarness) Close() {
	h.cancel()
}

func (h *testHarness) close() {
	h.Close()
}

func newHarness(t *testing.T, timeout time.Duration) *testHarness {
	h := &testHarness{}
	h.caKey = newSignerEd25519()
	h.liloKey = newSignerEd25519()
	h.stitchKey = newSignerEd25519()
	h.naniKey = newSignerEd25519()
	h.wrongKey = newSignerEd25519()
	h.target1HostKey = newSignerEd25519()
	h.target2HostKey = newSignerEd25519()

	h.tmpDir = setupHarnessDir(t, h.caKey)

	h.ctx, h.cancel = context.WithTimeout(context.Background(), timeout)
	return h
}

func setupHarnessDir(t *testing.T, caKey ssh.Signer) string {
	tmpDir := t.TempDir()

	mustMkdirAll(t, filepath.Join(tmpDir, "ca"), 0o755)
	mustMkdirAll(t, filepath.Join(tmpDir, "hostkeys"), 0o755)

	caPubPath := filepath.Join(tmpDir, "ca", "ca.pub")
	mustWriteFile(t, caPubPath, string(ssh.MarshalAuthorizedKey(caKey.PublicKey())), 0o644)

	return tmpDir
}

func waitForTCPPort(addr string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for %s", addr)
		case <-ticker.C:
		}
	}
}

func newSigner(path string) ssh.Signer {
	_ = path
	return newSignerEd25519()
}

func newSignerEd25519() ssh.Signer {
	key, err := ssh.NewSignerFromKey(newKeyEd25519())
	if err != nil {
		panic(err)
	}
	return key
}

func newKeyEd25519() any {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv
}

func newTestCert(key ssh.Signer, caKey ssh.Signer, principal string) (ssh.Signer, error) {
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

func harnessLogLevelFromEnv() string {
	v := strings.TrimSpace(os.Getenv("TEST_LOG"))
	if v != "" {
		return strings.ToUpper(v)
	}
	return "WARN"
}

func harnessDefaultConfig(tmpDir string, mode string) Config {
	return Config{
		Address:  "127.0.0.1",
		Port:     0,
		LogLevel: harnessLogLevelFromEnv(),
		Testing:  true,

		MaxStartups: 100,
		MaxSessions: 10,

		DialTimeout: 5 * time.Second,

		HostKeys: []string{filepath.Join(tmpDir, "hostkeys")},
		CertKeys: []string{filepath.Join(tmpDir, "ca")},
		AuthKeys: []string{
			filepath.Join(tmpDir, "home/{user}/authorized_keys"),
		},

		AuthMode: mode,

		Ciphers:  []string{"chacha20-poly1305@openssh.com"},
		KEXs:     []string{"curve25519-sha256"},
		MACs:     []string{"hmac-sha2-256-etm@openssh.com"},
		SmtpPort: 587,
	}
}

func (h *testHarness) run(t *testing.T, opts ...func(*Config)) *Server {
	return h.runWithMode(t, "keys", opts...)
}

func (h *testHarness) RunScenario(t *testing.T, opts ...func(*Config)) HarnessScenario {
	h.startConfiguredTargets(t)

	cfg := harnessDefaultConfig(h.tmpDir, "keys")
	for _, opt := range opts {
		opt(&cfg)
	}
	if h.preRunHook != nil {
		h.preRunHook(t, h, &cfg)
	}
	h.writeAuthorizedKeys(t)

	server, addr, err := startServer(h.ctx, t, cfg)
	if err != nil {
		t.Fatalf("failed to start bastille: %v", err)
	}
	h.serverAddr = addr
	_ = server

	return h.Scenario()
}

func (h *testHarness) runWithMode(t *testing.T, mode string, opts ...func(*Config)) *Server {
	cfg := harnessDefaultConfig(h.tmpDir, mode)
	for _, opt := range opts {
		opt(&cfg)
	}
	h.writeAuthorizedKeys(t)

	if cfg.AuthMode != "certs" {
		server, addr, err := startServer(h.ctx, t, cfg)
		if err != nil {
			t.Fatalf("failed to start bastille: %v", err)
		}
		h.serverAddr = addr
		return server
	}

	srv := newTestSSHServerConfig(&cfg, true)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go func() {
		<-h.ctx.Done()
		ln.Close()
	}()

	metrics := NewMetrics()
	server := NewServer(cfg, metrics)
	go server.serve(h.ctx, srv, ln)

	actualAddr := ln.Addr().String()
	if err := waitForTCPPort(actualAddr, 2*time.Second); err != nil {
		t.Fatalf("bastille not ready: %v", err)
	}
	h.serverAddr = actualAddr
	return server
}

func (h *testHarness) runWithCertOnly(t *testing.T) *Server {
	return h.runWithMode(t, "certs")
}

func (h *testHarness) RunScenarioWithCertOnly(t *testing.T, opts ...func(*Config)) HarnessScenario {
	h.startConfiguredTargets(t)

	cfg := harnessDefaultConfig(h.tmpDir, "certs")
	for _, opt := range opts {
		opt(&cfg)
	}
	if h.preRunHook != nil {
		h.preRunHook(t, h, &cfg)
	}
	h.writeAuthorizedKeys(t)

	srv := newTestSSHServerConfig(&cfg, true)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go func() {
		<-h.ctx.Done()
		ln.Close()
	}()

	metrics := NewMetrics()
	server := NewServer(cfg, metrics)
	go server.serve(h.ctx, srv, ln)

	actualAddr := ln.Addr().String()
	if err := waitForTCPPort(actualAddr, 2*time.Second); err != nil {
		t.Fatalf("bastille not ready: %v", err)
	}
	h.serverAddr = actualAddr
	_ = server

	return h.Scenario()
}

func (h *testHarness) writeAuthorizedKeys(t *testing.T) {
	home := filepath.Join(h.tmpDir, "home")
	for _, u := range []string{"lilo", "stitch", "nani"} {
		mustMkdirAll(t, filepath.Join(home, u), 0o755)
	}

	write := func(user, content string) {
		mustWriteFile(t, filepath.Join(home, user, "authorized_keys"), content, 0o644)
	}

	permitAt := func(i int) string {
		if i >= 0 && i < len(h.targetAddrs) {
			return fmt.Sprintf(`permitopen="%s"`, h.targetAddrs[i])
		}
		return ""
	}

	liloPermits := make([]string, 0, len(h.targetAddrs))
	for _, addr := range h.targetAddrs {
		liloPermits = append(liloPermits, fmt.Sprintf(`permitopen="%s"`, addr))
	}
	if len(liloPermits) == 0 {
		liloPermits = append(liloPermits, `permitopen="127.0.0.1:*"`)
	}
	write("lilo", fmt.Sprintf("%s %s",
		strings.Join(liloPermits, ","),
		string(ssh.MarshalAuthorizedKey(h.liloKey.PublicKey())),
	))

	stitchPrefix := ""
	if p := permitAt(1); p != "" {
		stitchPrefix = p + " "
	}
	write("stitch", fmt.Sprintf("%s%s",
		stitchPrefix,
		string(ssh.MarshalAuthorizedKey(h.stitchKey.PublicKey())),
	))

	naniPrefix := ""
	if p := permitAt(0); p != "" {
		naniPrefix = p + " "
	}
	write("nani", naniPrefix)
}

func newTestSSHServerConfig(cfg *Config, certOnly bool) *ssh.ServerConfig {
	metrics := NewMetrics()
	srv := newSSHServerConfig(cfg, certOnly, metrics)
	if srv == nil {
		srv = &ssh.ServerConfig{
			Config: ssh.Config{
				Ciphers:      cfg.Ciphers,
				KeyExchanges: cfg.KEXs,
				MACs:         cfg.MACs,
			},
		}
	}
	return srv
}

func startServer(ctx context.Context, t *testing.T, cfg Config) (*Server, string, error) {
	srv := newTestSSHServerConfig(&cfg, cfg.AuthMode == "certs")
	ln, err := net.Listen("tcp", cfg.Address+":0")
	if err != nil {
		return nil, "", err
	}
	actualAddr := ln.Addr().String()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	metrics := NewMetrics()
	server := NewServer(cfg, metrics)
	go server.serve(ctx, srv, ln)
	if err := waitForTCPPort(actualAddr, 2*time.Second); err != nil {
		ln.Close()
		return nil, "", err
	}
	return server, actualAddr, nil
}

var (
	targetLogOnc sync.Once
	targetLog    bool
)

func targetLoggingEnabled() bool {
	targetLogOnc.Do(func() {
		v := os.Getenv("TEST_LOG")
		targetLog = v == "1" || v == "true" || v == "TRUE" || v == "yes" || v == "YES"
	})
	return targetLog
}

func tlog(format string, args ...any) {
	if targetLoggingEnabled() {
		slog.Debug("[test-target] " + fmt.Sprintf(format, args...))
	}
}

func (h *testHarness) startTargets(t *testing.T, hostKeys ...ssh.Signer) {
	if len(hostKeys) == 0 {
		if h.target1HostKey != nil {
			hostKeys = append(hostKeys, h.target1HostKey)
		}
		if h.target2HostKey != nil {
			hostKeys = append(hostKeys, h.target2HostKey)
		}
	}

	h.targetAddrs = make([]string, 0, len(hostKeys))
	for _, hostKey := range hostKeys {
		addr, err := startTarget(h.ctx, hostKey)
		if err != nil {
			t.Fatalf("failed to start target: %v", err)
		}
		h.targetAddrs = append(h.targetAddrs, addr)
	}
}

func (h *testHarness) StartTargets(t *testing.T, hostKeys ...ssh.Signer) {
	h.startTargets(t, hostKeys...)
}

func (h *testHarness) StartOneTarget(t *testing.T) {
	h.startTargets(t, h.target1HostKey)
}

func (h *testHarness) StartTwoTargets(t *testing.T) {
	h.startTargets(t, h.target1HostKey, h.target2HostKey)
}

func startTarget(ctx context.Context, hostKey ssh.Signer) (string, error) {
	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	config.AddHostKey(hostKey)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	actualAddr := listener.Addr().String()
	tlog("listening addr=%s", actualAddr)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			tlog("accepted remote=%s local=%s", conn.RemoteAddr().String(), conn.LocalAddr().String())
			go startTargetHandler(conn, config)
		}
	}()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		wg.Wait()
		tlog("shutdown addr=%s", actualAddr)
	}()
	if err := waitForTCPPort(actualAddr, 2*time.Second); err != nil {
		_ = listener.Close()
		return "", err
	}
	return actualAddr, nil
}

func startTargetHandler(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	var id [8]byte
	_, _ = rand.Read(id[:])
	cid := hex.EncodeToString(id[:])

	tlog("conn start cid=%s remote=%s", cid, conn.RemoteAddr().String())

	sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		tlog("handshake failed cid=%s err=%v", cid, err)
		return
	}
	defer sconn.Close()

	tlog("handshake ok cid=%s user=%q remote=%s", cid, sconn.User(), sconn.RemoteAddr().String())

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		ct := newChan.ChannelType()
		tlog("new channel cid=%s type=%s", cid, ct)

		if ct != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			tlog("channel rejected cid=%s type=%s", cid, ct)
			continue
		}

		channel, requests, err := newChan.Accept()
		if err != nil {
			tlog("channel accept failed cid=%s err=%v", cid, err)
			continue
		}

		go func() {
			defer func() { _ = channel.Close() }()
			for req := range requests {
				tlog("request cid=%s type=%s wantReply=%v", cid, req.Type, req.WantReply)
				if req.Type == "exec" {
					_ = req.Reply(true, nil)
					_, _ = channel.Write([]byte("mock-target-response\n"))
					_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					tlog("exec handled cid=%s", cid)
					return
				}
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}()
	}

	tlog("conn end cid=%s", cid)
}

func newSSHConfig(user string, key ssh.Signer) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
}

type proxyClient struct {
	target *ssh.Client
	proxy  *ssh.Client
}

func (c *proxyClient) Close() error {
	var err error
	if c.target != nil {
		err = c.target.Close()
	}
	if c.proxy != nil {
		_ = c.proxy.Close()
	}
	return err
}

func sshJump(proxyUser, proxyAddr, targetUser, targetAddr string, authKeys ssh.Signer) (*proxyClient, error) {
	auth := []ssh.AuthMethod{ssh.PublicKeys(authKeys)}
	cb := ssh.InsecureIgnoreHostKey()
	to := 5 * time.Second
	config := &ssh.ClientConfig{
		User:            proxyUser,
		Auth:            auth,
		HostKeyCallback: cb,
		Timeout:         to,
	}
	dialer := &net.Dialer{Timeout: to}
	proxyTcpConn, err := dialer.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy dial failed: %w", err)
	}
	proxySshConn, proxyChans, proxyReqs, err := ssh.NewClientConn(proxyTcpConn, proxyAddr, config)
	if err != nil {
		_ = proxyTcpConn.Close()
		// Preserve sentinel errors (e.g. ErrCertRequired / ErrNoKey) if the server returned them.
		return nil, errors.Join(fmt.Errorf("proxy handshake failed"), err)
	}
	proxySshClient := ssh.NewClient(proxySshConn, proxyChans, proxyReqs)
	targetTcpClient, err := proxySshClient.Dial("tcp", targetAddr)
	if err != nil {
		_ = proxySshClient.Close()
		return nil, fmt.Errorf("target dial failed: %w", err)
	}
	targetConn, targetChans, targetReqs, err := ssh.NewClientConn(
		targetTcpClient,
		targetAddr,
		&ssh.ClientConfig{
			User:            targetUser,
			Auth:            auth,
			HostKeyCallback: cb,
			Timeout:         to,
		})
	if err != nil {
		_ = targetTcpClient.Close()
		_ = proxySshClient.Close()
		return nil, errors.Join(fmt.Errorf("target handshake failed"), err)
	}
	targetClient := ssh.NewClient(targetConn, targetChans, targetReqs)
	return &proxyClient{target: targetClient, proxy: proxySshClient}, nil
}
