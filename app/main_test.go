package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))
	os.Exit(m.Run())
}

func TestLoadCertPermit(t *testing.T) {
	tmpDir, cleanup := setupTestDirs(t)
	defer cleanup()

	home := filepath.Join(tmpDir, "home", "lilo")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatalf("mkdir lilo: %v", err)
	}
	ak := filepath.Join(home, "authorized_keys")
	expected := `permitopen="127.0.0.1:11111",permitopen="127.0.0.1:22222"`
	if err := os.WriteFile(ak, []byte(expected+"\n"), 0644); err != nil {
		t.Fatalf("write authorized_keys: %v", err)
	}

	cfg := Config{
		AUTH_BASE: filepath.Join(tmpDir, "home"),
		AUTH_KEYS: []string{"{user}/authorized_keys"},
	}

	opts := loadCertPermit(&cfg, "lilo")
	if opts == "" {
		t.Error("expected permitopen options for lilo, got empty")
	}

	if opts != expected {
		t.Errorf("unexpected permitopen options: %s", opts)
	}
}
