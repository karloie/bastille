package main

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestLoadConfigDefaults(t *testing.T) {
	clearEnv()
	cfg := LoadConfig()
	if cfg.ADDRESS != ":22222" {
		t.Errorf("expected default Listen :22222, got %s", cfg.ADDRESS)
	}
	if cfg.MaxTunnels != 5 {
		t.Errorf("expected default MaxTunnels=5, got %d", cfg.MaxTunnels)
	}
	if cfg.LogLevel != "INFO" {
		t.Errorf("expected default LogLevel=INFO, got %s", cfg.LogLevel)
	}
	if cfg.AUTH_BASE != "/home" {
		t.Errorf("expected default AUTH_BASE=/home, got %s", cfg.AUTH_BASE)
	}
	if cfg.CERT_BASE != "/ca" {
		t.Errorf("expected default CERT_BASE=/ca, got %s", cfg.CERT_BASE)
	}
	if cfg.HOST_BASE != "/hostkeys" {
		t.Errorf("expected default HOST_BASE=/hostkeys, got %s", cfg.HOST_BASE)
	}
	if len(cfg.Ciphers) == 0 {
		t.Errorf("expected non-empty Ciphers list")
	}
}

func TestEnvOverrides(t *testing.T) {
	clearEnv()
	os.Setenv("LISTEN", "0.0.0.0:10022")
	os.Setenv("MAX_TUNNELS", "9")
	os.Setenv("LOGLEVEL", "WARN")
	cfg := LoadConfig()
	if cfg.ADDRESS != "0.0.0.0:10022" {
		t.Errorf("LISTEN override failed, got %s", cfg.ADDRESS)
	}
	if cfg.MaxTunnels != 9 {
		t.Errorf("MAX_TUNNELS override failed, got %d", cfg.MaxTunnels)
	}
	if cfg.LogLevel != "WARN" {
		t.Errorf("LOGLEVEL override failed, got %s", cfg.LogLevel)
	}
}

func TestSplitList(t *testing.T) {
	in := "a,b, c ,"
	out := splitList(in)
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("splitList failed: got %v, want %v", out, want)
	}
}

func TestEvalAlgorithmsAdd(t *testing.T) {
	os.Setenv("CIPHERS", "+aes256-cbc")
	def := []string{"chacha20-poly1305"}
	got := evalAlgorithms("CIPHERS", def)
	if !slices.Contains(got, "aes256-cbc") {
		t.Errorf("expected aes256-cbc to be added, got %v", got)
	}
}

func TestEvalAlgorithmsRemove(t *testing.T) {
	os.Setenv("CIPHERS", "-chacha20-*")
	def := []string{"chacha20-poly1305", "aes256-gcm@openssh.com"}
	got := evalAlgorithms("CIPHERS", def)
	for _, v := range got {
		if strings.HasPrefix(v, "chacha20-") {
			t.Errorf("expected chacha20-* to be removed, got %v", got)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	clearEnv()
	t.Run("invalid MaxTunnels", func(t *testing.T) {
		os.Setenv("MAX_TUNNELS", "0")
		defer os.Unsetenv("MAX_TUNNELS")
		cfg := Config{MaxTunnels: 0, RateLimit: 10, LogLevel: "INFO", SMTPPort: 587, Ciphers: []string{"test"}, KeyExchanges: []string{"test"}, MACs: []string{"test"}}
		if err := cfg.Validate(); err == nil {
			t.Error("expected config validation to fail for MaxTunnels=0")
		}
	})

	t.Run("invalid RateLimit", func(t *testing.T) {
		os.Setenv("RATE", "-1")
		defer os.Unsetenv("RATE")
		cfg := Config{MaxTunnels: 5, RateLimit: -1, LogLevel: "INFO", SMTPPort: 587, Ciphers: []string{"test"}, KeyExchanges: []string{"test"}, MACs: []string{"test"}}
		if err := cfg.Validate(); err == nil {
			t.Error("expected config validation to fail for RATE=-1")
		}
	})

	t.Run("invalid LogLevel", func(t *testing.T) {
		os.Setenv("LOGLEVEL", "INVALID")
		defer os.Unsetenv("LOGLEVEL")
		cfg := Config{MaxTunnels: 5, RateLimit: 10, LogLevel: "INVALID", SMTPPort: 587, Ciphers: []string{"test"}, KeyExchanges: []string{"test"}, MACs: []string{"test"}}
		if err := cfg.Validate(); err == nil {
			t.Error("expected config validation to fail for invalid LOGLEVEL")
		}
	})

	t.Run("invalid SMTP port", func(t *testing.T) {
		os.Setenv("SMTP_PORT", "99999")
		defer os.Unsetenv("SMTP_PORT")
		cfg := Config{MaxTunnels: 5, RateLimit: 10, LogLevel: "INFO", SMTPPort: 99999, Ciphers: []string{"test"}, KeyExchanges: []string{"test"}, MACs: []string{"test"}}
		if err := cfg.Validate(); err == nil {
			t.Error("expected config validation to fail for invalid SMTP_PORT")
		}
	})
}

func clearEnv() {
	for _, k := range []string{
		"LISTEN", "MAX_TUNNELS", "LOGLEVEL",
		"CIPHERS", "KEXALGORITHMS", "MACS", "RATE", "SMTP_PORT",
	} {
		os.Unsetenv(k)
	}
}
