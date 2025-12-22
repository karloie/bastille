package main

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

func certChecker(cfg *Config, caPub []ssh.PublicKey, authFiles []string) *ssh.CertChecker {
	return &ssh.CertChecker{
		IsUserAuthority: func(key ssh.PublicKey) bool {
			for _, k := range caPub {
				if keysEqual(k, key) {
					return true
				}
			}
			return false
		},
		UserKeyFallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			user := rxUserSanitize.ReplaceAllString(conn.User(), "")

			// Expand AUTH_KEYS entries into concrete file paths:
			// - Replace {user}
			// - Expand globs
			// - If directory, scan all regular files in it
			var candidates []string
			for _, tmpl := range authFiles {
				p := strings.ReplaceAll(tmpl, "{user}", user)
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				// Glob patterns
				if strings.ContainsAny(p, "*?[") {
					if matches, err := filepath.Glob(p); err == nil {
						candidates = append(candidates, matches...)
					}
					continue
				}
				// Directory
				if fi, err := os.Stat(p); err == nil && fi.IsDir() {
					if entries, derr := os.ReadDir(p); derr == nil {
						for _, e := range entries {
							if !e.IsDir() {
								candidates = append(candidates, filepath.Join(p, e.Name()))
							}
						}
					}
					continue
				}
				// File (or non-existent path; evalPermissions will fail safely)
				candidates = append(candidates, p)
			}

			// De-duplicate while preserving order, then evaluate
			seen := make(map[string]struct{}, len(candidates))
			for _, path := range candidates {
				if _, ok := seen[path]; ok {
					continue
				}
				seen[path] = struct{}{}
				if perm, ok := evalPermissions(cfg, path, pubKey); ok {
					return perm, nil
				}
			}
			return nil, errors.New("no key")
		},
	}
}

func evalPermissions(cfg *Config, path string, key ssh.PublicKey) (*ssh.Permissions, bool) {
	if cfg.StrictModes && !strictPathOK(cfg, path) {
		logEvent("warn", "", nil, path, "strictmodes denied", nil, nil)
		return nil, false
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		pub, _, opts, _, err := ssh.ParseAuthorizedKey(sc.Bytes())
		if err == nil && keysEqual(pub, key) {
			return &ssh.Permissions{Extensions: map[string]string{permissionKey: strings.Join(opts, ",")}}, true
		}
	}
	return nil, false
}
