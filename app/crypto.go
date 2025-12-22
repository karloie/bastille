package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	fingerprintLength = 16
	permDirDefault    = 0o755
	permPrivateKey    = 0o600
	permPublicKey     = 0o644
)

func keyHash(k ssh.PublicKey) string {
	if k == nil {
		return ""
	}
	h := sha256.Sum256(k.Marshal())
	fp := base64.RawStdEncoding.EncodeToString(h[:])
	if len(fp) > fingerprintLength {
		fp = fp[:fingerprintLength]
	}
	return fmt.Sprintf("%s:%s", k.Type(), fp)
}

func keysEqual(a, b ssh.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	x, y := a.Marshal(), b.Marshal()
	if len(x) != len(y) {
		return false
	}
	return subtle.ConstantTimeCompare(x, y) == 1
}

func loadHostkeys(cfg *Config, hostKeys []string, srvCfg *ssh.ServerConfig) int {
	// HOST_KEYS accepts absolute files, directories, or globs.
	// - Files are read as private keys.
	// - Directories are scanned for ssh_host_*_key (excluding *.pub); also considered for generation.
	// - Globs are expanded.
	var candidates []string
	var genTargets []string

	for _, raw := range hostKeys {
		hk := strings.TrimSpace(raw)
		if hk == "" {
			continue
		}
		// Glob patterns
		if strings.ContainsAny(hk, "*?[") {
			if matches, err := filepath.Glob(hk); err == nil {
				candidates = append(candidates, matches...)
			} else {
				logEvent("warn", "", nil, hk, "glob error", nil, err)
			}
			continue
		}

		fi, err := os.Stat(hk)
		if err == nil && fi.IsDir() {
			// Scan directory for typical private host keys
			entries, derr := os.ReadDir(hk)
			if derr != nil {
				logEvent("warn", "", nil, hk, "host dir read failed", nil, derr)
			} else {
				for _, e := range entries {
					if e.IsDir() {
						continue
					}
					name := e.Name()
					if strings.HasPrefix(name, "ssh_host_") && strings.HasSuffix(name, "_key") && !strings.HasSuffix(name, ".pub") {
						candidates = append(candidates, filepath.Join(hk, name))
					}
				}
			}
			// Consider this directory for ed25519 generation
			genTargets = append(genTargets, filepath.Join(hk, "ssh_host_ed25519_key"))
			continue
		}

		// Treat as file path (may or may not exist yet)
		candidates = append(candidates, hk)
		if strings.Contains(strings.ToLower(hk), "ed25519") {
			genTargets = append(genTargets, hk)
		}
	}

	// De-duplicate candidates while preserving order
	seen := make(map[string]struct{}, len(candidates))
	uniq := make([]string, 0, len(candidates))
	for _, p := range candidates {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		uniq = append(uniq, p)
	}

	loaded := 0
	for _, path := range uniq {
		nameLower := strings.ToLower(filepath.Base(path))
		// Prefer generating/ensuring ed25519 when referenced
		if strings.Contains(nameLower, "ed25519") {
			if s, ok := ensureEd25519HostKey(path); ok {
				srvCfg.AddHostKey(s)
				loaded++
				logEvent("info", "", nil, path, "host key loaded/generated", nil, nil)
				continue
			}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			logEvent("warn", "", nil, path, "host key read failed", nil, err)
			continue
		}
		s, err := ssh.ParsePrivateKey(b)
		if err != nil {
			logEvent("warn", "", nil, path, "host key parse failed", nil, err)
			continue
		}
		srvCfg.AddHostKey(s)
		loaded++
		logEvent("info", "", nil, path, "host key loaded", nil, nil)
	}

	// If nothing loaded, attempt to generate an ed25519 key at the first writable generation target.
	if loaded == 0 {
		for _, tgt := range genTargets {
			if s, ok := ensureEd25519HostKey(tgt); ok {
				srvCfg.AddHostKey(s)
				loaded++
				logEvent("info", "", nil, tgt, "host key generated (fallback)", nil, nil)
				break
			}
		}
	}

	return loaded
}

func ensureEd25519HostKey(path string) (ssh.Signer, bool) {
	if b, err := os.ReadFile(path); err == nil {
		if s, err := ssh.ParsePrivateKey(b); err == nil {
			return s, true
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		logEvent("warn", "", nil, path, "ed25519 keygen failed", nil, err)
		return nil, false
	}
	if err := os.MkdirAll(filepath.Dir(path), permDirDefault); err != nil {
		logEvent("warn", "", nil, path, "mkdir failed", nil, err)
		// Fallback: use a temp directory to place the host key
		if tmpDir, terr := os.MkdirTemp("", "bastille-hostkeys-*"); terr == nil {
			path = filepath.Join(tmpDir, filepath.Base(path))
			logEvent("info", "", nil, path, "using temp path for host key", nil, nil)
		} else {
			logEvent("warn", "", nil, path, "temp dir create failed", nil, terr)
			return nil, false
		}
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		logEvent("warn", "", nil, path, "marshal pkcs8 failed", nil, err)
		return nil, false
	}
	pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}
	if err := os.WriteFile(path, pem.EncodeToMemory(pemBlock), permPrivateKey); err != nil {
		logEvent("warn", "", nil, path, "write private key failed", nil, err)
		// Fallback: try writing to a temp directory instead
		if tmpDir, terr := os.MkdirTemp("", "bastille-hostkeys-*"); terr == nil {
			path = filepath.Join(tmpDir, filepath.Base(path))
			if werr := os.WriteFile(path, pem.EncodeToMemory(pemBlock), permPrivateKey); werr != nil {
				logEvent("warn", "", nil, path, "write private key failed (temp)", nil, werr)
				return nil, false
			}
			logEvent("info", "", nil, path, "host key written to temp path", nil, nil)
		} else {
			logEvent("warn", "", nil, path, "temp dir create failed", nil, terr)
			return nil, false
		}
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err == nil {
		pubPath := path + ".pub"
		if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), permPublicKey); err != nil {
			logEvent("warn", "", nil, pubPath, "write public key failed", nil, err)
		} else {
			logEvent("info", "", nil, pubPath, "host public key written", nil, nil)
		}
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		logEvent("warn", "", nil, path, "new signer failed", nil, err)
		return nil, false
	}
	logEvent("info", "", nil, path, "ed25519 host key generated", nil, nil)
	return s, true
}

func loadCaKeys(cfg *Config, paths []string) []ssh.PublicKey {
	// CERT_KEYS is a comma-separated list of absolute files, directories, or globs.
	// Directories are scanned for *.pub; globs are expanded; files are read as-is.
	var files []string

	for _, raw := range paths {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		// Glob patterns
		if strings.ContainsAny(p, "*?[") {
			if matches, err := filepath.Glob(p); err == nil {
				files = append(files, matches...)
			} else {
				logEvent("warn", "", nil, p, "glob error", nil, err)
			}
			continue
		}
		// File or directory
		fi, err := os.Stat(p)
		if err != nil {
			logEvent("warn", "", nil, p, "read error", nil, err)
			continue
		}
		if fi.IsDir() {
			entries, err := os.ReadDir(p)
			if err != nil {
				logEvent("warn", "", nil, p, "dir read failed", nil, err)
				continue
			}
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".pub") {
					files = append(files, filepath.Join(p, e.Name()))
				}
			}
			continue
		}
		// Regular file
		files = append(files, p)
	}

	// De-duplicate while preserving order
	seen := make(map[string]struct{}, len(files))
	uniq := make([]string, 0, len(files))
	for _, f := range files {
		if _, ok := seen[f]; ok {
			continue
		}
		seen[f] = struct{}{}
		uniq = append(uniq, f)
	}

	// Load one or more authorized keys per file
	out := make([]ssh.PublicKey, 0, len(uniq))
	for _, path := range uniq {
		b, err := os.ReadFile(path)
		if err != nil {
			logEvent("warn", "", nil, path, "read error", nil, err)
			continue
		}
		rest := b
		for len(rest) > 0 {
			pub, _, _, r, err := ssh.ParseAuthorizedKey(rest)
			if err != nil {
				logEvent("warn", "", nil, path, "parse error", nil, err)
				break
			}
			out = append(out, pub)
			logEvent("info", "", nil, path, "ca key loaded", nil, nil)
			rest = r
		}
	}
	return out
}
