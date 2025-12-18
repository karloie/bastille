package main

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestLoadConfigDefaults verifies that LoadConfig sets sensible defaults.
func TestLoadConfigDefaults(t *testing.T) {
	// Clear relevant env vars to force defaults
	clearEnv()

	cfg := LoadConfig()

	if cfg.ADDRESS != ":22222" {
		t.Errorf("expected default Listen :22222, got %s", cfg.ADDRESS)
	}
	if cfg.MaxTunnels != 5 {
		t.Errorf("expected default MaxTunnels=5, got %d", cfg.MaxTunnels)
	}
	if !cfg.Debug {
		t.Errorf("expected default Debug=true")
	}
	if len(cfg.Ciphers) == 0 {
		t.Errorf("expected non-empty Ciphers list")
	}
}

// TestEnvOverrides ensures env variables override defaults correctly.
func TestEnvOverrides(t *testing.T) {
	clearEnv()
	os.Setenv("LISTEN", "0.0.0.0:10022")
	os.Setenv("MAX_TUNNELS", "9")
	os.Setenv("DEBUG", "false")

	cfg := LoadConfig()

	if cfg.ADDRESS != "0.0.0.0:10022" {
		t.Errorf("LISTEN override failed, got %s", cfg.ADDRESS)
	}
	if cfg.MaxTunnels != 9 {
		t.Errorf("MAX_TUNNELS override failed, got %d", cfg.MaxTunnels)
	}
	if cfg.Debug {
		t.Errorf("DEBUG override failed, expected false")
	}
}

// TestSplitList verifies comma-separated parsing.
func TestSplitList(t *testing.T) {
	in := "a,b, c ,"
	out := splitList(in)
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("splitList failed: got %v, want %v", out, want)
	}
}

// TestEvalAlgorithmsAdd verifies “+” prefix adds algorithms.
func TestEvalAlgorithmsAdd(t *testing.T) {
	os.Setenv("CIPHERS", "+aes256-cbc")
	def := []string{"chacha20-poly1305"}
	got := evalAlgorithms("CIPHERS", def)
	if !contains(got, "aes256-cbc") {
		t.Errorf("expected aes256-cbc to be added, got %v", got)
	}
}

// TestEvalAlgorithmsRemove verifies “-” prefix removes algorithms.
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

// Helper: clear relevant env vars between tests
func clearEnv() {
	for _, k := range []string{
		"LISTEN", "MAX_TUNNELS", "DEBUG",
		"CIPHERS", "KEXALGORITHMS", "MACS",
	} {
		os.Unsetenv(k)
	}
}

// Helper: contains element
func contains(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}
