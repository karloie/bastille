package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestKeyHash(t *testing.T) {
	t.Run("nil key returns empty string", func(t *testing.T) {
		result := keyHash(nil)
		if result != "" {
			t.Errorf("expected empty string for nil key, got %q", result)
		}
	})
	t.Run("valid key returns fingerprint", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatalf("failed to create signer: %v", err)
		}
		result := keyHash(signer.PublicKey())
		if !strings.HasPrefix(result, "ssh-ed25519:") {
			t.Errorf("expected hash to start with 'ssh-ed25519:', got %q", result)
		}
		if len(result) < 20 {
			t.Errorf("hash too short: %q", result)
		}
	})

	t.Run("same key produces same hash", func(t *testing.T) {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		signer, _ := ssh.NewSignerFromKey(priv)
		pub := signer.PublicKey()
		hash1 := keyHash(pub)
		hash2 := keyHash(pub)
		if hash1 != hash2 {
			t.Errorf("expected same hash for same key, got %q and %q", hash1, hash2)
		}
	})

	t.Run("different keys produce different hashes", func(t *testing.T) {
		_, priv1, _ := ed25519.GenerateKey(rand.Reader)
		signer1, _ := ssh.NewSignerFromKey(priv1)

		_, priv2, _ := ed25519.GenerateKey(rand.Reader)
		signer2, _ := ssh.NewSignerFromKey(priv2)

		hash1 := keyHash(signer1.PublicKey())
		hash2 := keyHash(signer2.PublicKey())

		if hash1 == hash2 {
			t.Error("expected different hashes for different keys")
		}
	})
}

func TestKeysEqual(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	signer1, _ := ssh.NewSignerFromKey(priv1)
	key1 := signer1.PublicKey()

	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	signer2, _ := ssh.NewSignerFromKey(priv2)
	key2 := signer2.PublicKey()

	t.Run("same key is equal", func(t *testing.T) {
		if !keysEqual(key1, key1) {
			t.Error("expected same key to be equal to itself")
		}
	})

	t.Run("different keys are not equal", func(t *testing.T) {
		if keysEqual(key1, key2) {
			t.Error("expected different keys to not be equal")
		}
	})

	t.Run("nil keys return false", func(t *testing.T) {
		if keysEqual(nil, nil) {
			t.Error("expected nil keys to return false")
		}
		if keysEqual(key1, nil) {
			t.Error("expected key and nil to return false")
		}
		if keysEqual(nil, key1) {
			t.Error("expected nil and key to return false")
		}
	})
}

func TestConfigString(t *testing.T) {
	cfg := Config{
		ADDRESS:    "127.0.0.1:22222",
		LogLevel:   "INFO",
		MaxTunnels: 5,
		RateLimit:  10,
		SMTPPort:   587,
	}
	result := cfg.String()
	if !strings.Contains(result, "127.0.0.1:22222") {
		t.Error("expected String() to contain ADDRESS")
	}
	if !strings.Contains(result, "INFO") {
		t.Error("expected String() to contain LogLevel")
	}
	if !strings.Contains(result, "\"MaxTunnels\": 5") {
		t.Error("expected String() to contain MaxTunnels")
	}
	if !strings.Contains(result, "\"RateLimit\": 10") {
		t.Error("expected String() to contain RateLimit")
	}
	if !strings.HasPrefix(strings.TrimSpace(result), "{") {
		t.Error("expected String() to return JSON starting with {")
	}
}
