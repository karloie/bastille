package main

import (
	"context"
	"errors"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func rootJoin(parts ...string) string {
	all := append([]string{string(filepath.Separator)}, parts...)
	return filepath.Join(all...)
}

func miniConfig() Config {
	return Config{
		Port:        22222,
		AuthKeys:    []string{},
		CertKeys:    []string{},
		HostKeys:    []string{},
		Ciphers:     []string{"chacha20-poly1305@openssh.com"},
		KEXs:        []string{"curve25519-sha256"},
		MACs:        []string{"hmac-sha2-256-etm@openssh.com"},
		RsaMin:      3072,
		AuthMode:    "optional",
		StrictMode:  false,
		MaxSessions: 1,
		MaxStartups: 1,
		LogLevel:    "INFO",
		Testing:     true,
		DialTimeout: 0,
		SmtpHost:    "",
		SmtpMail:    "",
		SmtpSecret:  "/run/secrets/smtp_pass",
		SmtpPort:    587,
		SmtpUser:    "",
	}
}

func clearEnv() {
	for _, k := range []string{
		EnvListenAddress, EnvListenPort, EnvMaxSessions, EnvMaxStartups, EnvLogLevel, EnvStrictMode, EnvAuthMode,
		EnvAuthKeys, EnvCertKeys, EnvHostKeys,
		EnvCiphers, EnvKEXs, EnvMACs, EnvRSAMin,
		EnvSmtpPort, EnvSmtpHost, EnvSmtpMail, EnvSmtpUser, EnvSmtpSecret,
		EnvTesting,
	} {
		os.Unsetenv(k)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	clearEnv()
	cfg := LoadConfig()

	if cfg.Address != "" {
		t.Fatalf("expected default ListenAddress to be empty, got %q", cfg.Address)
	}
	if cfg.Port != 22222 {
		t.Fatalf("expected default Port=22222, got %d", cfg.Port)
	}
	if cfg.MaxSessions != 5 {
		t.Fatalf("expected default MaxSessions=5, got %d", cfg.MaxSessions)
	}
	if cfg.LogLevel != "INFO" {
		t.Fatalf("expected default LogLevel=INFO, got %q", cfg.LogLevel)
	}

	if len(cfg.CertKeys) != 2 || cfg.CertKeys[0] != "/home/{user}/.ssh/ca.pub" || cfg.CertKeys[1] != "/ca" {
		t.Fatalf("expected default TrustedUserCAKeys=[/home/{user}/.ssh/ca.pub /ca], got %v", cfg.CertKeys)
	}

	if len(cfg.Ciphers) == 0 {
		t.Fatal("expected non-empty Ciphers list")
	}
}

func TestLoadConfigEnvOverrides(t *testing.T) {
	clearEnv()
	setEnv(t, EnvListenAddress, "0.0.0.0")
	setEnv(t, EnvListenPort, "10022")

	cfg := LoadConfig()
	if cfg.Address != "0.0.0.0" {
		t.Fatalf("ListenAddress override failed, got %q", cfg.Address)
	}
	if cfg.Port != 10022 {
		t.Fatalf("Port override failed, got %d", cfg.Port)
	}
}

func TestParseAlgorithmListModifiers(t *testing.T) {
	cases := []struct {
		name string
		env  string
		def  []string
		want func([]string) bool
	}{
		{
			name: "adds algorithm with + prefix",
			env:  "+aes256-cbc",
			def:  []string{"chacha20-poly1305"},
			want: func(got []string) bool { return slices.Contains(got, "aes256-cbc") },
		},
		{
			name: "removes algorithms by glob with - prefix",
			env:  "-chacha20-*",
			def:  []string{"chacha20-poly1305", "aes256-gcm@openssh.com"},
			want: func(got []string) bool {
				for _, v := range got {
					if strings.HasPrefix(v, "chacha20-") {
						return false
					}
				}
				return true
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearEnv()
			setEnv(t, EnvCiphers, tc.env)
			got := parseAlgorithmList("Ciphers", tc.def)
			if !tc.want(got) {
				t.Fatalf("unexpected result: env=%q def=%v got=%v", tc.env, tc.def, got)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	clearEnv()

	type tc struct {
		name string
		env  map[string]string
		cfg  func() Config
		want bool
	}
	cases := []tc{
		{
			name: "invalid MaxSessions",
			env:  map[string]string{EnvMaxSessions: "0"},
			cfg: func() Config {
				c := miniConfig()
				c.MaxSessions = 0
				return c
			},
			want: false,
		},
		{
			name: "invalid MaxStartups",
			env:  map[string]string{EnvMaxStartups: "-1"},
			cfg: func() Config {
				c := miniConfig()
				c.MaxStartups = -1
				return c
			},
			want: false,
		},
		{
			name: "invalid MinRsaSize too small",
			env:  map[string]string{EnvRSAMin: "512"},
			cfg: func() Config {
				c := miniConfig()
				c.RsaMin = 512
				return c
			},
			want: false,
		},
		{
			name: "MinRsaSize zero allowed",
			env:  map[string]string{EnvRSAMin: "0"},
			cfg: func() Config {
				c := miniConfig()
				c.RsaMin = 0
				return c
			},
			want: true,
		},
		{
			name: "MinRsaSize valid",
			env:  map[string]string{EnvRSAMin: "3072"},
			cfg: func() Config {
				c := miniConfig()
				c.RsaMin = 3072
				return c
			},
			want: true,
		},
		{
			name: "invalid LogLevel",
			env:  map[string]string{EnvLogLevel: "INVALID"},
			cfg: func() Config {
				return Config{
					MaxSessions: 5, MaxStartups: 10, LogLevel: "INVALID", SmtpPort: 587,
					Ciphers: []string{"test"}, KEXs: []string{"test"}, MACs: []string{"test"},
				}
			},
			want: false,
		},
		{
			name: "invalid Smtp port",
			env:  map[string]string{EnvSmtpPort: "99999"},
			cfg: func() Config {
				return Config{
					MaxSessions: 5, MaxStartups: 10, LogLevel: "INFO", SmtpPort: 99999,
					Ciphers: []string{"test"}, KEXs: []string{"test"}, MACs: []string{"test"},
				}
			},
			want: false,
		},
		{
			name: "StrictMode enabled errors when no AuthorizedKeysFile bases derived",
			cfg: func() Config {
				c := miniConfig()
				c.StrictMode = true
				c.AuthKeys = []string{"/*.pub"}
				return c
			},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				setEnv(t, k, v)
			}
			c := tc.cfg()
			err := c.Validate()
			if tc.want && err != nil {
				t.Fatalf("expected validation to pass, got %v", err)
			}
			if !tc.want && err == nil {
				t.Fatalf("expected validation to fail")
			}
		})
	}
}

func TestConfigValidateStrictModesWarning(t *testing.T) {
	cfg := miniConfig()
	cfg.StrictMode = false
	cfg.AuthKeys = []string{"/*.pub"}

	vErr := cfg.Validate()

	if vErr != nil {
		t.Fatalf("unexpected validation error with StrictMode disabled: %v", vErr)
	}
}

func asSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		out[filepath.Clean(s)] = struct{}{}
	}
	return out
}

func setEq(a, b []string) bool {
	am := asSet(a)
	bm := asSet(b)
	if len(am) != len(bm) {
		return false
	}
	for k := range am {
		if _, ok := bm[k]; !ok {
			return false
		}
	}
	return true
}

func TestAllowedBases(t *testing.T) {
	cases := []struct {
		name         string
		in           []string
		wantFixed    []string
		wantPatterns []string
	}{
		{
			name: "basic",
			in: []string{
				rootJoin("home", "{user}", ".ssh", "authorized_keys"),
				rootJoin("home", "{user}"),
			},
			wantFixed: []string{rootJoin("home")},
			wantPatterns: []string{
				rootJoin("home", "{user}"),
				rootJoin("home", "{user}", ".ssh"),
			},
		},
		{
			name: "with globs and dirs",
			in: []string{
				rootJoin("etc", "ssh", "keys", "*.pub"),
				rootJoin("opt", "ssh", "auth", "{user}", "keys"),
			},
			wantFixed: []string{
				rootJoin("etc", "ssh"),
				rootJoin("opt", "ssh", "auth"),
			},
			wantPatterns: []string{
				rootJoin("opt", "ssh", "auth", "{user}"),
				rootJoin("opt", "ssh", "auth", "{user}", "keys"),
			},
		},
		{
			name: "de-duplication",
			in: []string{
				rootJoin("home", "{user}", ".ssh", "authorized_keys"),
				rootJoin("home", "{user}", ".ssh", "known_hosts"),
				rootJoin("home", "{user}"),
				rootJoin("home", "{user}", "random", "..", ".ssh", "extra"),
			},
			wantFixed: []string{rootJoin("home")},
			wantPatterns: []string{
				rootJoin("home", "{user}"),
				rootJoin("home", "{user}", ".ssh"),
			},
		},
		{
			name: "glob root edge",
			in: []string{
				string(filepath.Separator) + "*.pub",
				rootJoin("etc", "ssh", "trusted", "*.pub"),
			},
			wantFixed:    []string{rootJoin("etc", "ssh")},
			wantPatterns: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixed, patterns := allowedBases(tc.in)

			if tc.name == "glob root edge" {
				if len(patterns) != 0 {
					t.Fatalf("expected no user patterns, got: %v", patterns)
				}
				if !reflect.DeepEqual(asSet(fixed), asSet(tc.wantFixed)) {
					t.Fatalf("fixed bases mismatch:\n  got:  %v\n  want: %v", fixed, tc.wantFixed)
				}
				return
			}

			if !setEq(fixed, tc.wantFixed) {
				t.Fatalf("fixed bases mismatch:\n  got:  %v\n  want: %v", fixed, tc.wantFixed)
			}
			if !setEq(patterns, tc.wantPatterns) {
				t.Fatalf("pattern bases mismatch:\n  got:  %v\n  want: %v", patterns, tc.wantPatterns)
			}
		})
	}
}

func TestMatchesUser(t *testing.T) {
	cases := []struct {
		name     string
		pattern  string
		absPath  string
		wantOK   bool
		wantBase string
	}{
		{
			name:     "with suffix",
			pattern:  rootJoin("home", "{user}", ".ssh"),
			absPath:  rootJoin("home", "lilo", ".ssh", "authorized_keys"),
			wantOK:   true,
			wantBase: rootJoin("home", "lilo", ".ssh"),
		},
		{
			name:     "no suffix",
			pattern:  rootJoin("home", "{user}"),
			absPath:  rootJoin("home", "lilo", "docs", "file.txt"),
			wantOK:   true,
			wantBase: rootJoin("home", "lilo"),
		},
		{
			name:    "mismatch",
			pattern: rootJoin("home", "{user}", ".ssh"),
			absPath: rootJoin("var", "lilo", ".ssh", "authorized_keys"),
			wantOK:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, ok := matchesUser(tc.pattern, tc.absPath)
			if ok != tc.wantOK {
				t.Fatalf("unexpected ok for pattern %q path %q: got %v want %v", tc.pattern, tc.absPath, ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if filepath.Clean(base) != filepath.Clean(tc.wantBase) {
				t.Fatalf("base root mismatch:\n  got:  %s\n  want: %s", base, tc.wantBase)
			}
		})
	}
}

func TestAllowedBasesDeduplication(t *testing.T) {
	auth := []string{
		rootJoin("home", "{user}", ".ssh", "authorized_keys"),
		rootJoin("home", "{user}", ".ssh", "known_hosts"),
		rootJoin("home", "{user}"),
		rootJoin("home", "{user}", "random", "..", ".ssh", "extra"),
	}

	_, patterns := allowedBases(auth)

	wantPatternsSet := asSet([]string{
		rootJoin("home", "{user}"),
		rootJoin("home", "{user}", ".ssh"),
	})

	gotSet := asSet(patterns)
	for k := range wantPatternsSet {
		if _, ok := gotSet[k]; !ok {
			sort.Strings(patterns)
			want := make([]string, 0, len(wantPatternsSet))
			for s := range wantPatternsSet {
				want = append(want, s)
			}
			sort.Strings(want)
			t.Fatalf("pattern bases missing %q\n  got:  %v\n  want: %v", k, patterns, want)
		}
	}
}

func TestAllowedTunnel(t *testing.T) {
	t.Parallel()

	type tc struct {
		name    string
		perms   *ssh.Permissions
		dst     string
		allowed bool
	}

	cases := []tc{
		{
			name:    "denies when perms is nil",
			perms:   nil,
			dst:     "127.0.0.1:22",
			allowed: false,
		},
		{
			name:    "denies when extensions are nil",
			perms:   &ssh.Permissions{},
			dst:     "127.0.0.1:22",
			allowed: false,
		},
		{
			name:    "denies when opts missing",
			perms:   &ssh.Permissions{Extensions: map[string]string{}},
			dst:     "127.0.0.1:22",
			allowed: false,
		},
		{
			name: "allows when permitopen matches",
			perms: &ssh.Permissions{
				Extensions: map[string]string{
					permissionKey: `permitopen="127.0.0.1:22"`,
				},
			},
			dst:     "127.0.0.1:22",
			allowed: true,
		},
		{
			name: "denies when permitopen does not match",
			perms: &ssh.Permissions{
				Extensions: map[string]string{
					permissionKey: `permitopen="127.0.0.1:22"`,
				},
			},
			dst:     "127.0.0.1:23",
			allowed: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isTunnelAllowed(c.perms, c.dst); got != c.allowed {
				t.Fatalf("isTunnelAllowed(perms, %q)=%v, want %v", c.dst, got, c.allowed)
			}
		})
	}
}

func TestServerCreation(t *testing.T) {
	cfg := Config{
		MaxStartups: 10,
		MaxSessions: 5,
	}

	metrics := NewMetrics()
	server := NewServer(cfg, metrics)

	if server == nil {
		t.Fatal("NewServer returned nil")
	}

	if server.cfg.MaxStartups != 10 {
		t.Errorf("expected MaxStartups 10, got %d", server.cfg.MaxStartups)
	}

	if server.cfg.MaxSessions != 5 {
		t.Errorf("expected MaxSessions 5, got %d", server.cfg.MaxSessions)
	}

	if server.rate == nil {
		t.Error("rate map not initialized")
	}

	if server.tunnels == nil {
		t.Error("tunnels map not initialized")
	}
}

func TestTargetAddress(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		port     uint32
		expected string
	}{
		{
			name:     "localhost with standard port",
			host:     "127.0.0.1",
			port:     22,
			expected: "127.0.0.1:22",
		},
		{
			name:     "hostname with custom port",
			host:     "example.com",
			port:     8080,
			expected: "example.com:8080",
		},
		{
			name:     "IPv6 address",
			host:     "::1",
			port:     443,
			expected: "::1:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := targetAddress(ssh.Marshal(struct {
				DstHost string
				DstPort uint32
				SrcIP   string
				SrcPort uint32
			}{
				DstHost: tt.host,
				DstPort: tt.port,
				SrcIP:   "127.0.0.1",
				SrcPort: 12345,
			}))
			if got != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}
func TestLogEvent(t *testing.T) {
	tests := []struct {
		name  string
		level string
		cid   string
		dst   string
		msg   string
		value any
		err   error
	}{
		{
			name:  "debug level",
			level: "debug",
			cid:   "abc123",
			dst:   "127.0.0.1:22",
			msg:   "test message",
			value: nil,
			err:   nil,
		},
		{
			name:  "warn level with error",
			level: "warn",
			cid:   "def456",
			dst:   "example.com:443",
			msg:   "connection failed",
			value: nil,
			err:   context.DeadlineExceeded,
		},
		{
			name:  "info level with key hash",
			level: "info",
			cid:   "ghi789",
			dst:   "",
			msg:   "auth success",
			value: "SHA256:abcdef1234567890",
			err:   nil,
		},
		{
			name:  "default level",
			level: "",
			cid:   "",
			dst:   "",
			msg:   "generic message",
			value: 42,
			err:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("logEvent panicked: %v", r)
				}
			}()

			logEvent(tt.level, tt.cid, nil, tt.dst, tt.msg, tt.value, tt.err)
		})
	}
}

func TestServerShutdown(t *testing.T) {
	t.Run("stops on context cancel", func(t *testing.T) {
		cfg := Config{
			MaxStartups: 10,
			MaxSessions: 5,
		}
		metrics := NewMetrics()
		server := NewServer(cfg, metrics)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}

		sshCfg := &ssh.ServerConfig{}
		sshCfg.AddHostKey(mustGenEd25519Signer(t))

		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan struct{})
		go func() {
			server.serve(ctx, sshCfg, ln)
			close(done)
		}()

		time.Sleep(50 * time.Millisecond)

		cancel()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("serve did not stop after context cancel")
		}
	})
}

func TestConstants(t *testing.T) {
	if handshakeTimeout != 10*time.Second {
		t.Errorf("expected handshakeTimeout to be 10s, got %v", handshakeTimeout)
	}

	if channelTypeTCP != "direct-tcpip" {
		t.Errorf("expected channelTypeTCP to be 'direct-tcpip', got %s", channelTypeTCP)
	}
}

func TestNotificationDisabled(t *testing.T) {
	cfg := Config{
		SmtpHost: "",
		SmtpMail: "",
	}
	sendTunnelNotification(context.Background(), &cfg, "testuser", "192.0.2.1:12345", "198.51.100.1:22")
}

func TestNotificationMissingPassword(t *testing.T) {
	cfg := Config{
		SmtpHost:   "smtp.example.com",
		SmtpMail:   "test@example.com",
		SmtpPort:   587,
		SmtpUser:   "test@example.com",
		SmtpSecret: "/nonexistent/smtp_pass",
	}
	sendTunnelNotification(context.Background(), &cfg, "testuser", "192.0.2.1:12345", "198.51.100.1:22")
}

func TestNotificationValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	passFile := filepath.Join(tmpDir, "smtp_pass")
	if err := os.WriteFile(passFile, []byte("testpassword\n"), 0600); err != nil {
		t.Fatalf("failed to write password file: %v", err)
	}
	cfg := Config{
		SmtpHost:   "smtp.example.com",
		SmtpMail:   "test@example.com",
		SmtpPort:   587,
		SmtpUser:   "test@example.com",
		SmtpSecret: passFile,
	}
	sendTunnelNotification(context.Background(), &cfg, "testuser", "192.0.2.1:12345", "198.51.100.1:22")
}

func TestNotificationMocked(t *testing.T) {
	originalSend := sendMail
	defer func() { sendMail = originalSend; resetSmtpState() }()
	resetSmtpState()

	tmpDir := t.TempDir()
	passFile := filepath.Join(tmpDir, "smtp_pass")
	if err := os.WriteFile(passFile, []byte("secret\n"), 0600); err != nil {
		t.Fatalf("write pass: %v", err)
	}

	calls := 0
	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		calls++
		return nil
	}

	cfg := Config{
		SmtpHost:   "smtp.example.com",
		SmtpMail:   "test@example.com",
		SmtpPort:   587,
		SmtpUser:   "test@example.com",
		SmtpSecret: passFile,
	}

	sendTunnelNotification(context.Background(), &cfg, "alice", "1.2.3.4:1111", "5.6.7.8:22")
	if calls != 1 {
		t.Fatalf("expected sendMail to be called once, got %d", calls)
	}

	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		calls++
		return errors.New("fail")
	}
	sendTunnelNotification(context.Background(), &cfg, "alice", "1.2.3.4:1111", "5.6.7.8:22")
	if calls != 2 {
		t.Fatalf("expected sendMail to be called twice, got %d", calls)
	}
}

func TestMetrics(t *testing.T) {
	m := NewMetrics()
	m.Enable()
	
	m.RecordConnection()
	m.RecordTunnelOpened()
	m.RecordBytesIn(1024)
	m.RecordBytesOut(2048)
	
	if m.connectionsTotal.Load() != 1 {
		t.Errorf("expected 1 connection, got %d", m.connectionsTotal.Load())
	}
	if m.tunnelsActive.Load() != 1 {
		t.Errorf("expected 1 active tunnel, got %d", m.tunnelsActive.Load())
	}
	if m.bytesTransferredIn.Load() != 1024 {
		t.Errorf("expected 1024 bytes in, got %d", m.bytesTransferredIn.Load())
	}
	if m.bytesTransferredOut.Load() != 2048 {
		t.Errorf("expected 2048 bytes out, got %d", m.bytesTransferredOut.Load())
	}
}
