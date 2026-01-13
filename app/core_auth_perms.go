package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

var (
	ErrNoKey        = errors.New("no key")
	ErrCertRequired = errors.New("cert required")
)

const (
	permissionKey     = "opts"
	fingerprintLength = 16
)

var (
	rxPermit = regexp.MustCompile(`permitopen="?([^"]+)"?`)
	rxUser   = regexp.MustCompile(`[^a-zA-Z0-9._-]`)
)

type permitOpenRule struct {
	host string
	port string
}

func parsePermitOpenRule(opt string) (permitOpenRule, bool) {
	m := rxPermit.FindStringSubmatch(strings.TrimSpace(opt))
	if len(m) <= 1 {
		return permitOpenRule{}, false
	}
	pattern := strings.TrimSpace(m[1])
	ph, pp, ok := strings.Cut(pattern, ":")
	if !ok {
		return permitOpenRule{}, false
	}
	ph, pp = strings.TrimSpace(ph), strings.TrimSpace(pp)
	if ph == "" || pp == "" {
		return permitOpenRule{}, false
	}
	return permitOpenRule{host: ph, port: pp}, true
}

func matchPermitOpenRule(r permitOpenRule, dstHost, dstPort string) bool {
	hostOK := r.host == "*" || r.host == dstHost
	portOK := r.port == "*" || r.port == dstPort
	return hostOK && portOK
}

func isPermitAllowed(opts, dst string) bool {
	if opts == "" {
		return false
	}
	dh, dp, ok := strings.Cut(dst, ":")
	if !ok {
		return false
	}
	dh, dp = strings.TrimSpace(dh), strings.TrimSpace(dp)
	if dh == "" || dp == "" {
		return false
	}

	for _, o := range strings.Split(opts, ",") {
		r, ok := parsePermitOpenRule(o)
		if !ok {
			continue
		}
		if matchPermitOpenRule(r, dh, dp) {
			return true
		}
	}
	return false
}

func certChecker(cfg *Config, caPub []ssh.PublicKey, authFiles []string) *ssh.CertChecker {
	return &ssh.CertChecker{
		IsUserAuthority: func(key ssh.PublicKey) bool {
			for _, k := range caPub {
				if areKeysEqual(k, key) {
					return true
				}
			}
			return false
		},
		UserKeyFallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			user := rxUser.ReplaceAllString(conn.User(), "")
			candidates := expandPathSpecs(authFiles, user, func(_ string, e os.DirEntry) bool {
				return !e.IsDir()
			}, nil)

			for _, path := range uniqStrings(candidates) {
				if perm, ok := checkKeyPermissions(cfg, path, pubKey); ok {
					return perm, nil
				}
			}
			return nil, ErrNoKey
		},
	}
}

func checkKeyPermissions(cfg *Config, path string, key ssh.PublicKey) (*ssh.Permissions, bool) {
	if !isAuthKeysPathAllowed(cfg, path) {
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
		if err == nil && areKeysEqual(pub, key) {
			return &ssh.Permissions{
				Extensions: map[string]string{
					permissionKey: strings.Join(opts, ","),
				},
			}, true
		}
	}
	return nil, false
}

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

func areKeysEqual(a, b ssh.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	x, y := a.Marshal(), b.Marshal()
	if len(x) != len(y) {
		return false
	}
	return subtle.ConstantTimeCompare(x, y) == 1
}
