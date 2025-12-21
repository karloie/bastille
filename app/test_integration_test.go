package main

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestAccess(t *testing.T) {
	t.Parallel()
	m := newMockServerContext(t, defaultTestTimeout)
	defer m.close()

	m.startTargets(t,
		Target{hostKey: target1HostKey},
		Target{hostKey: target2HostKey},
	)
	m.startBastille(t)

	target1Addr := m.targetAddrs[0]
	target2Addr := m.targetAddrs[1]
	bastilleAddr := m.bastilleAddr

	tests := []struct {
		name       string
		proxyUser  string
		targetAddr string
		key        ssh.Signer
		wantErr    bool
	}{
		{
			name:       "lilo can access target1",
			proxyUser:  "lilo",
			targetAddr: target1Addr,
			key:        testLiloKey,
			wantErr:    false,
		},
		{
			name:       "lilo can access target2",
			proxyUser:  "lilo",
			targetAddr: target2Addr,
			key:        testLiloKey,
			wantErr:    false,
		},
		{
			name:       "stitch can access target2",
			proxyUser:  "stitch",
			targetAddr: target2Addr,
			key:        testStitchKey,
			wantErr:    false,
		},
		{
			name:       "stitch cannot access target1",
			proxyUser:  "stitch",
			targetAddr: target1Addr,
			key:        testStitchKey,
			wantErr:    true,
		},
		{
			name:       "wrong key denied",
			proxyUser:  "lilo",
			targetAddr: target1Addr,
			key:        testWrongKey,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := sshConnect("root", tt.proxyUser, bastilleAddr, tt.targetAddr, tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("sshConnect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			defer client.Close()

			session, err := client.NewSession()
			if err != nil {
				t.Fatalf("failed to create session: %v", err)
			}
			defer session.Close()

			output, err := session.CombinedOutput("echo test")
			if err != nil {
				t.Errorf("command failed: %v", err)
			}

			if len(output) == 0 {
				t.Error("expected output, got none")
			}
		})
	}
}

func TestRateLimit(t *testing.T) {
	t.Parallel()
	m := newMockServerContext(t, shortTestTimeout)
	defer m.close()

	m.startTargets(t, Target{hostKey: target1HostKey})
	m.startBastille(t, func(c *Config) {
		c.RateLimit = 3
	})

	target1Addr := m.targetAddrs[0]
	bastilleAddr := m.bastilleAddr

	successCount := 0
	for i := 0; i < 5; i++ {
		client, err := sshConnect("root", "lilo", bastilleAddr, target1Addr, testLiloKey)
		if err == nil {
			successCount++
			t.Logf("connection %d succeeded", i)
			client.Close()
		} else {
			t.Logf("connection %d failed: %v", i, err)
		}
	}

	if successCount != 2 {
		t.Errorf("rate limiting not working correctly: expected exactly 2 connections, got %d", successCount)
	}
}

func TestMaxTunnels(t *testing.T) {
	t.Parallel()
	m := newMockServerContext(t, shortTestTimeout)
	defer m.close()

	m.startTargets(t, Target{hostKey: target1HostKey})
	m.startBastille(t, func(c *Config) {
		c.MaxTunnels = 2
	})

	target1Addr := m.targetAddrs[0]
	bastilleAddr := m.bastilleAddr

	var clients []*ssh.Client
	for i := 0; i < 3; i++ {
		client, err := sshConnect("root", "lilo", bastilleAddr, target1Addr, testLiloKey)
		if err != nil {
			t.Logf("connection %d failed (expected if > MaxTunnels): %v", i, err)
			continue
		}
		clients = append(clients, client)
	}

	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()

	if len(clients) != 2 {
		t.Errorf("tunnel limit not enforced correctly: expected exactly 2 tunnels, got %d", len(clients))
	}
}

func TestInvalidChannel(t *testing.T) {
	t.Parallel()
	m := newMockServerContext(t, shortTestTimeout)
	defer m.close()

	m.startBastille(t)
	bastilleAddr := m.bastilleAddr

	config := newSSHClientConfig("lilo", testLiloKey)

	client, err := ssh.Dial("tcp", bastilleAddr, config)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err == nil {
		session.Close()
		t.Error("expected session channel to be rejected")
	}
}

func TestCertificateAuth(t *testing.T) {
	t.Parallel()
	m := newMockServerContext(t, defaultTestTimeout)
	defer m.close()

	m.startTargets(t, Target{hostKey: target1HostKey})
	m.startBastille(t)

	target1Addr := m.targetAddrs[0]
	bastilleAddr := m.bastilleAddr

	t.Run("cert auth allows access", func(t *testing.T) {
		certSigner, err := createTestCert(testCertuserKey, testCAKey, "certuser")
		if err != nil {
			t.Fatalf("failed to create cert signer: %v", err)
		}

		client, err := sshConnect("root", "certuser", bastilleAddr, target1Addr, certSigner)
		if err != nil {
			t.Fatalf("cert auth failed: %v", err)
		}
		defer client.Close()

		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}
		defer session.Close()

		output, err := session.CombinedOutput("echo test")
		if err != nil {
			t.Errorf("command failed: %v", err)
		}

		if len(output) == 0 {
			t.Error("expected output, got none")
		}
	})

	t.Run("regular key rejected for cert user", func(t *testing.T) {
		_, err := sshConnect("root", "certuser", bastilleAddr, target1Addr, testLiloKey)
		if err == nil {
			t.Error("expected regular key to be rejected for cert user")
		}
	})
}

func TestCertAuthEnforced(t *testing.T) {
	t.Parallel()
	m := newMockServerContext(t, shortTestTimeout)
	defer m.close()

	m.startTargets(t, Target{hostKey: target1HostKey})
	m.startBastilleCertOnly(t)

	bastilleAddr := m.bastilleAddr

	t.Run("regular key rejected in cert-only mode", func(t *testing.T) {
		config := newSSHClientConfig("lilo", testLiloKey)

		_, err := ssh.Dial("tcp", bastilleAddr, config)
		if err == nil {
			t.Error("expected regular key to be rejected in cert-only mode")
		}
	})

	t.Run("certificate accepted in cert-only mode", func(t *testing.T) {
		certSigner, err := createTestCert(testLiloKey, testCAKey, "lilo")
		if err != nil {
			t.Fatalf("failed to create cert signer: %v", err)
		}

		config := newSSHClientConfig("lilo", certSigner)

		client, err := ssh.Dial("tcp", bastilleAddr, config)
		if err != nil {
			t.Fatalf("cert auth failed: %v", err)
		}
		client.Close()
	})
}
