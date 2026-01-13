package main

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func requireIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration-heavy test in -short mode")
	}
}

func assertRemoteExecHasOutput(t *testing.T, client *proxyClient, cmd string) {
	t.Helper()

	session, err := client.target.NewSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}
	if len(output) == 0 {
		t.Fatal("expected output, got none")
	}
}

func sshJumpAndExec(
	t *testing.T,
	proxyUser string,
	proxyAddr string,
	targetUser string,
	targetAddr string,
	key ssh.Signer,
	cmd string,
) error {
	t.Helper()

	client, err := sshJump(proxyUser, proxyAddr, targetUser, targetAddr, key)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	assertRemoteExecHasOutput(t, client, cmd)
	return nil
}

func countSuccessfulSSHJumps(
	t *testing.T,
	n int,
	proxyUser string,
	proxyAddr string,
	targetUser string,
	targetAddr string,
	key ssh.Signer,
	onFail func(i int, err error),
) int {
	t.Helper()

	success := 0
	for i := 0; i < n; i++ {
		client, err := sshJump(proxyUser, proxyAddr, targetUser, targetAddr, key)
		if err != nil {
			if onFail != nil {
				onFail(i, err)
			}
			continue
		}
		success++
		_ = client.Close()
	}
	return success
}

func assertSessionChannelRejected(t *testing.T, bastilleAddr string, liloKey ssh.Signer) {
	t.Helper()

	config := newSSHConfig("lilo", liloKey)
	client, err := ssh.Dial("tcp", bastilleAddr, config)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err == nil {
		_ = session.Close()
		t.Fatal("expected session channel to be rejected")
	}
}

func TestPermitOpenAccess(t *testing.T) {
	requireIntegration(t)

	t.Parallel()
	h := newHarness(t, defaultTestTimeout).WithTwoTargets()
	defer h.Close()

	s := h.RunScenario(t)

	target1Addr := s.Targets[0]
	target2Addr := s.Targets[1]
	bastilleAddr := s.Addr
	keys := s.Keys

	tests := []struct {
		name       string
		proxyUser  string
		targetAddr string
		key        ssh.Signer
		wantErr    bool
	}{
		{name: "allows lilo to access target1", proxyUser: "lilo", targetAddr: target1Addr, key: keys.Lilo, wantErr: false},
		{name: "allows lilo to access target2", proxyUser: "lilo", targetAddr: target2Addr, key: keys.Lilo, wantErr: false},
		{name: "allows stitch to access target2", proxyUser: "stitch", targetAddr: target2Addr, key: keys.Stitch, wantErr: false},
		{name: "denies stitch access to target1", proxyUser: "stitch", targetAddr: target1Addr, key: keys.Stitch, wantErr: true},
		{name: "denies wrong key", proxyUser: "lilo", targetAddr: target1Addr, key: keys.Wrong, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sshJumpAndExec(t, tt.proxyUser, bastilleAddr, "root", tt.targetAddr, tt.key, "echo test")
			if (err != nil) != tt.wantErr {
				t.Fatalf("sshJumpAndExec() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCertOnlyMode(t *testing.T) {
	requireIntegration(t)

	t.Parallel()
	h := newHarness(t, shortTestTimeout).WithOneTarget()
	defer h.Close()

	s := h.RunScenarioWithCertOnly(t /* no opts */)

	target1Addr := s.Targets[0]
	bastilleAddr := s.Addr
	keys := s.Keys

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "allows certificate authentication",
			run: func(t *testing.T) {
				certSigner, err := newTestCert(keys.Nani, keys.CA, "nani")
				if err != nil {
					t.Fatalf("failed to create cert signer: %v", err)
				}
				if err := sshJumpAndExec(t, "nani", bastilleAddr, "root", target1Addr, certSigner, "echo test"); err != nil {
					t.Fatalf("cert auth failed: %v", err)
				}
			},
		},
		{
			name: "rejects regular key for cert user",
			run: func(t *testing.T) {
				_, err := sshJump("nani", bastilleAddr, "root", target1Addr, keys.Lilo)
				if err == nil {
					t.Fatal("expected regular key to be rejected for cert user")
				}
			},
		},
		{
			name: "rejects regular key in cert-only mode",
			run: func(t *testing.T) {
				config := newSSHConfig("lilo", keys.Lilo)
				_, err := ssh.Dial("tcp", bastilleAddr, config)
				if err == nil {
					t.Fatal("expected regular key to be rejected in cert-only mode")
				}
			},
		},
		{
			name: "accepts certificate in cert-only mode",
			run: func(t *testing.T) {
				certSigner, err := newTestCert(keys.Lilo, keys.CA, "lilo")
				if err != nil {
					t.Fatalf("failed to create cert signer: %v", err)
				}
				config := newSSHConfig("lilo", certSigner)
				client, err := ssh.Dial("tcp", bastilleAddr, config)
				if err != nil {
					t.Fatalf("cert auth failed: %v", err)
				}
				_ = client.Close()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

func TestTrustedUserCAKeys(t *testing.T) {
	requireIntegration(t)

	t.Parallel()

	cases := []struct {
		name    string
		certKey string
		setup   func(t *testing.T, m *testHarness) ssh.Signer
		wantErr bool
	}{
		{
			name:    "accepts per-user CA key",
			certKey: filepath.Join("{tmp}", "home", "{user}", ".ssh", "ca.pub"),
			setup: func(t *testing.T, m *testHarness) ssh.Signer {
				userDir := filepath.Join(m.TmpDir(), "home", "lilo", ".ssh")
				mustMkdirAll(t, userDir, 0o755)

				caPath := filepath.Join(userDir, "ca.pub")
				newCA := newSignerEd25519()
				certSigner, err := newTestCert(m.Keys().Lilo, newCA, "lilo")
				if err != nil {
					t.Fatalf("failed to create cert signer: %v", err)
				}
				mustWriteFile(t, caPath, string(ssh.MarshalAuthorizedKey(newCA.PublicKey())), 0o644)
				return certSigner
			},
			wantErr: false,
		},
		{
			name:    "rejects templated CERT_KEYS outside allowed base",
			certKey: filepath.Join("{tmp}", "outside", "{user}", "ca.pub"),
			setup: func(t *testing.T, m *testHarness) ssh.Signer {
				outsideDir := filepath.Join(m.TmpDir(), "outside", "lilo")
				mustMkdirAll(t, outsideDir, 0o755)

				outsideCert := filepath.Join(outsideDir, "id_ed25519-cert.pub")
				newCA := newSignerEd25519()
				certSigner, err := newTestCert(m.Keys().Lilo, newCA, "lilo")
				if err != nil {
					t.Fatalf("failed to create cert signer: %v", err)
				}
				mustWriteFile(t, outsideCert, string(ssh.MarshalAuthorizedKey(certSigner.PublicKey())), 0o644)
				return certSigner
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, defaultTestTimeout).
				WithOneTarget().
				WithPreRunConfig(func(t *testing.T, h *testHarness, cfg *Config) {

					cfg.CertKeys = []string{strings.ReplaceAll(tc.certKey, "{tmp}", h.TmpDir())}
					cfg.AuthMode = "certs"
				})
			defer h.Close()

			certSigner := tc.setup(t, h)

			s := h.RunScenario(t)

			targetAddr := s.Targets[0]
			_, err := sshJump("lilo", s.Addr, "root", targetAddr, certSigner)
			if (err != nil) != tc.wantErr {
				t.Fatalf("sshJump() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestPerSourceRateLimit(t *testing.T) {
	requireIntegration(t)

	t.Parallel()
	h := newHarness(t, shortTestTimeout).WithOneTarget()
	defer h.Close()

	s := h.RunScenario(t, func(c *Config) {
		c.MaxStartups = 3
	})

	target1Addr := s.Targets[0]
	bastilleAddr := s.Addr
	keys := s.Keys

	successCount := countSuccessfulSSHJumps(
		t,
		5,
		"lilo",
		bastilleAddr,
		"root",
		target1Addr,
		keys.Lilo,
		func(i int, err error) {
			t.Logf("connection %d failed: %v", i, err)
		},
	)

	if successCount != 2 {
		t.Errorf("rate limiting not working correctly: expected exactly 2 connections, got %d", successCount)
	}
}

func TestMaxSessionsLimit(t *testing.T) {
	requireIntegration(t)

	t.Parallel()
	h := newHarness(t, shortTestTimeout).WithOneTarget()
	defer h.Close()

	s := h.RunScenario(t, func(c *Config) {
		c.MaxSessions = 2
	})

	target1Addr := s.Targets[0]
	bastilleAddr := s.Addr
	keys := s.Keys

	var clients []*proxyClient
	for i := 0; i < 3; i++ {
		client, err := sshJump("lilo", bastilleAddr, "root", target1Addr, keys.Lilo)
		if err != nil {
			t.Logf("connection %d failed (expected if > MaxTunnels): %v", i, err)
			continue
		}
		clients = append(clients, client)
	}

	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()

	if len(clients) != 2 {
		t.Errorf("tunnel limit not enforced correctly: expected exactly 2 tunnels, got %d", len(clients))
	}
}

func TestRejectSessionChannel(t *testing.T) {
	requireIntegration(t)

	t.Parallel()
	h := newHarness(t, shortTestTimeout)
	defer h.Close()

	s := h.RunScenario(t)
	assertSessionChannelRejected(t, s.Addr, s.Keys.Lilo)
}
