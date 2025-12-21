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
			for _, tmpl := range authFiles {
				path := filepath.Join(cfg.AUTH_BASE, strings.ReplaceAll(tmpl, "{user}", user))
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
