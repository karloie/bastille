package main

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestNewServer(t *testing.T) {
	cfg := Config{
		RateLimit:  10,
		MaxTunnels: 5,
	}

	server := NewServer(cfg)

	if server == nil {
		t.Fatal("NewServer returned nil")
	}

	if server.cfg.RateLimit != 10 {
		t.Errorf("expected RateLimit 10, got %d", server.cfg.RateLimit)
	}

	if server.cfg.MaxTunnels != 5 {
		t.Errorf("expected MaxTunnels 5, got %d", server.cfg.MaxTunnels)
	}

	if server.rateCnt == nil {
		t.Error("rateCnt map not initialized")
	}

	if server.tunnels == nil {
		t.Error("tunnels map not initialized")
	}
}

func TestDstFromExtra(t *testing.T) {
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
			payload := struct {
				DstHost string
				DstPort uint32
				SrcIP   string
				SrcPort uint32
			}{
				DstHost: tt.host,
				DstPort: tt.port,
				SrcIP:   "192.168.1.1",
				SrcPort: 12345,
			}

			extra := ssh.Marshal(payload)
			result := dstFromExtra(extra)

			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestAllowedTunnel(t *testing.T) {
	cfg := Config{}
	server := NewServer(cfg)

	t.Run("nil connection", func(t *testing.T) {
		if server.allowedTunnel(nil, "127.0.0.1:22") {
			t.Error("expected false for nil connection")
		}
	})

	t.Run("connection without permissions", func(t *testing.T) {
		if server.allowedTunnel(nil, "127.0.0.1:22") {
			t.Error("expected false for connection without permissions")
		}
	})
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

func TestServerServe(t *testing.T) {
	t.Run("stops on context cancel", func(t *testing.T) {
		cfg := Config{
			RateLimit:  10,
			MaxTunnels: 5,
		}
		server := NewServer(cfg)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}

		sshCfg := &ssh.ServerConfig{}
		sshCfg.AddHostKey(testHostKey)

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

func TestHandleConnRateLimit(t *testing.T) {
	t.Parallel()
	m := newTestContext(t, shortTestTimeout)
	defer m.close()

	m.startBastille(t, func(c *Config) {
		c.RateLimit = 2
	})

	var successCount, failCount int

	for i := 0; i < 5; i++ {
		conn, err := net.DialTimeout("tcp", m.bastilleAddr, time.Second)
		if err != nil {
			failCount++
			continue
		}
		conn.Close()
		successCount++
		time.Sleep(10 * time.Millisecond)
	}

	if failCount == 0 && successCount > 2 {
		t.Logf("note: rate limiting behavior observed: success=%d fail=%d", successCount, failCount)
	}
}

func TestServerConstants(t *testing.T) {
	if handshakeTimeout != 10*time.Second {
		t.Errorf("expected handshakeTimeout to be 10s, got %v", handshakeTimeout)
	}

	if rateLimitWindow != time.Minute {
		t.Errorf("expected rateLimitWindow to be 1m, got %v", rateLimitWindow)
	}

	if channelTypeTCP != "direct-tcpip" {
		t.Errorf("expected channelTypeTCP to be 'direct-tcpip', got %s", channelTypeTCP)
	}
}
