package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStrictPathOK(t *testing.T) {
	tmpDir := t.TempDir()
	authBase := filepath.Join(tmpDir, "auth")
	if err := os.MkdirAll(authBase, 0755); err != nil {
		t.Fatalf("failed to create auth base: %v", err)
	}

	cfg := &Config{
	}

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
