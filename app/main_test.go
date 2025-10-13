package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
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
		AUTH_KEYS: []string{filepath.Join(tmpDir, "home", "{user}", "authorized_keys")},
	}

	opts := loadCertPermit(&cfg, "lilo")
	if opts == "" {
		t.Error("expected permitopen options for lilo, got empty")
	}

	if opts != expected {
		t.Errorf("unexpected permitopen options: %s", opts)
	}
}

func rootJoin(parts ...string) string {
	all := append([]string{string(filepath.Separator)}, parts...)
	return filepath.Join(all...)
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

func TestDeriveAllowedBases_BasicUserTemplates(t *testing.T) {
	auth := []string{
		rootJoin("home", "{user}", ".ssh", "authorized_keys"),
		rootJoin("home", "{user}"),
	}

	fixed, patterns := deriveAllowedBases(auth)
	wantFixed := []string{rootJoin("home")}
	wantPatterns := []string{
		rootJoin("home", "{user}"),
		rootJoin("home", "{user}", ".ssh"),
	}

	if !setEq(fixed, wantFixed) {
		t.Fatalf("fixed bases mismatch:\n  got:  %v\n  want: %v", fixed, wantFixed)
	}
	if !setEq(patterns, wantPatterns) {
		t.Fatalf("pattern bases mismatch:\n  got:  %v\n  want: %v", patterns, wantPatterns)
	}
}

func TestDeriveAllowedBases_WithGlobsAndDirs(t *testing.T) {
	auth := []string{
		rootJoin("etc", "ssh", "keys", "*.pub"),          // glob -> base should include /etc/ssh
		rootJoin("opt", "ssh", "auth", "{user}", "keys"), // dir template
	}

	fixed, patterns := deriveAllowedBases(auth)
	wantFixed := []string{
		rootJoin("etc", "ssh"),
		rootJoin("opt", "ssh", "auth"),
	}
	wantPatterns := []string{
		rootJoin("opt", "ssh", "auth", "{user}"),
		rootJoin("opt", "ssh", "auth", "{user}", "keys"),
	}

	if !setEq(fixed, wantFixed) {
		t.Fatalf("fixed bases mismatch:\n  got:  %v\n  want: %v", fixed, wantFixed)
	}
	if !setEq(patterns, wantPatterns) {
		t.Fatalf("pattern bases mismatch:\n  got:  %v\n  want: %v", patterns, wantPatterns)
	}
}

func TestMatchesUserBase_WithSuffix(t *testing.T) {
	pattern := rootJoin("home", "{user}", ".ssh")
	absPath := rootJoin("home", "lilo", ".ssh", "authorized_keys")

	base, ok := matchesUserBase(pattern, absPath)
	if !ok {
		t.Fatalf("expected match for pattern %q with path %q", pattern, absPath)
	}

	wantBase := rootJoin("home", "lilo", ".ssh")
	if filepath.Clean(base) != filepath.Clean(wantBase) {
		t.Fatalf("base root mismatch:\n  got:  %s\n  want: %s", base, wantBase)
	}
}

func TestMatchesUserBase_NoSuffix(t *testing.T) {
	pattern := rootJoin("home", "{user}")
	absPath := rootJoin("home", "lilo", "docs", "file.txt")

	base, ok := matchesUserBase(pattern, absPath)
	if !ok {
		t.Fatalf("expected match for pattern %q with path %q", pattern, absPath)
	}

	wantBase := rootJoin("home", "lilo")
	if filepath.Clean(base) != filepath.Clean(wantBase) {
		t.Fatalf("base root mismatch:\n  got:  %s\n  want: %s", base, wantBase)
	}
}

func TestMatchesUserBase_Mismatch(t *testing.T) {
	pattern := rootJoin("home", "{user}", ".ssh")
	absPath := rootJoin("var", "lilo", ".ssh", "authorized_keys")

	if _, ok := matchesUserBase(pattern, absPath); ok {
		t.Fatalf("expected no match for pattern %q with path %q", pattern, absPath)
	}
}

func TestDeriveAllowedBases_DeDuplication(t *testing.T) {
	auth := []string{
		rootJoin("home", "{user}", ".ssh", "authorized_keys"),
		rootJoin("home", "{user}", ".ssh", "known_hosts"),
		rootJoin("home", "{user}"),
		rootJoin("home", "{user}", "random", "..", ".ssh", "extra"), // cleans to /home/{user}/.ssh/extra
	}

	fixed, patterns := deriveAllowedBases(auth)

	wantFixed := []string{rootJoin("home")}
	wantPatternsSet := asSet([]string{
		rootJoin("home", "{user}"),
		rootJoin("home", "{user}", ".ssh"),
	})

	if !setEq(fixed, wantFixed) {
		t.Fatalf("fixed bases mismatch:\n  got:  %v\n  want: %v", fixed, wantFixed)
	}

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

func TestDeriveAllowedBases_GlobRootEdge(t *testing.T) {
	auth := []string{
		string(filepath.Separator) + "*.pub",
		rootJoin("etc", "ssh", "trusted", "*.pub"),
	}

	fixed, patterns := deriveAllowedBases(auth)
	if len(patterns) != 0 {
		t.Fatalf("expected no user patterns, got: %v", patterns)
	}

	wantFixed := []string{rootJoin("etc", "ssh")}
	if !reflect.DeepEqual(asSet(fixed), asSet(wantFixed)) {
		t.Fatalf("fixed bases mismatch:\n  got:  %v\n  want: %v", fixed, wantFixed)
	}
}

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

func TestStrictPathOK(t *testing.T) {
	tmpDir := t.TempDir()
	authBase := filepath.Join(tmpDir, "auth")
	if err := os.MkdirAll(authBase, 0755); err != nil {
		t.Fatalf("failed to create auth base: %v", err)
	}

	cfg := &Config{}

	t.Run("valid file passes", func(t *testing.T) {
		validFile := filepath.Join(authBase, "valid_file")
		if err := os.WriteFile(validFile, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create valid file: %v", err)
		}

		if !strictPathOK(cfg, validFile) {
			t.Error("expected valid file to pass strict check")
		}
	})

	t.Run("rejects file with group write", func(t *testing.T) {
		groupWrite := filepath.Join(authBase, "group_write")
		if err := os.WriteFile(groupWrite, []byte("test"), 0664); err != nil {
			t.Fatalf("failed to create group-writable file: %v", err)
		}

		if strictPathOK(cfg, groupWrite) {
			t.Error("expected group-writable file to be rejected")
		}
	})

	t.Run("rejects file with other write", func(t *testing.T) {
		otherWrite := filepath.Join(authBase, "other_write")
		if err := os.WriteFile(otherWrite, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create other-writable file: %v", err)
		}
		if err := os.Chmod(otherWrite, 0602); err != nil {
			t.Fatalf("failed to chmod other-writable file: %v", err)
		}

		if strictPathOK(cfg, otherWrite) {
			t.Error("expected other-writable file to be rejected")
		}
	})

	t.Run("rejects symlink", func(t *testing.T) {
		target := filepath.Join(authBase, "target")
		symlink := filepath.Join(authBase, "symlink")

		if err := os.WriteFile(target, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create target: %v", err)
		}
		if err := os.Symlink(target, symlink); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}

		if strictPathOK(cfg, symlink) {
			t.Error("expected symlink to be rejected")
		}
	})

	t.Run("rejects directory", func(t *testing.T) {
		dir := filepath.Join(authBase, "subdir")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create directory: %v", err)
		}

		if strictPathOK(cfg, dir) {
			t.Error("expected directory to be rejected")
		}
	})

	t.Run("rejects nonexistent file", func(t *testing.T) {
		nonexistent := filepath.Join(authBase, "does_not_exist")

		if strictPathOK(cfg, nonexistent) {
			t.Error("expected nonexistent file to be rejected")
		}
	})

	t.Run("rejects path outside auth base", func(t *testing.T) {
		outside := filepath.Join(tmpDir, "outside_auth_base")
		if err := os.WriteFile(outside, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create outside file: %v", err)
		}

		if strictPathOK(cfg, outside) {
			t.Error("expected file outside AUTH_BASE to be rejected")
		}
	})

	t.Run("rejects path traversal attempt", func(t *testing.T) {
		traversal := filepath.Join(authBase, "..", "escape")
		if err := os.WriteFile(traversal, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create traversal file: %v", err)
		}

		if strictPathOK(cfg, traversal) {
			t.Error("expected path traversal to be rejected")
		}
	})

	t.Run("rejects when parent directory is group writable", func(t *testing.T) {
		badDir := filepath.Join(authBase, "bad_perms_dir")
		if err := os.MkdirAll(badDir, 0777); err != nil {
			t.Fatalf("failed to create bad dir: %v", err)
		}
		if err := os.Chmod(badDir, 0777); err != nil {
			t.Fatalf("failed to chmod bad dir: %v", err)
		}

		fileInBadDir := filepath.Join(badDir, "file")
		if err := os.WriteFile(fileInBadDir, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create file in bad dir: %v", err)
		}

		if strictPathOK(cfg, fileInBadDir) {
			t.Error("expected file in group-writable directory to be rejected")
		}
	})

	t.Run("accepts file in subdirectory with good permissions", func(t *testing.T) {
		goodDir := filepath.Join(authBase, "good_dir")
		if err := os.MkdirAll(goodDir, 0755); err != nil {
			t.Fatalf("failed to create good dir: %v", err)
		}

		fileInGoodDir := filepath.Join(goodDir, "file")
		if err := os.WriteFile(fileInGoodDir, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create file in good dir: %v", err)
		}

		if !strictPathOK(cfg, fileInGoodDir) {
			t.Error("expected file in properly secured directory to pass")
		}
	})
}
