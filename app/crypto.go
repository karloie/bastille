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

func loadHostkeys(cfg *Config, base string, hostKeys []string, srvCfg *ssh.ServerConfig) int {
	loaded := 0
	for _, hk := range hostKeys {
		path := filepath.Join(base, hk)
		nameLower := strings.ToLower(hk)
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
		return nil, false
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		logEvent("warn", "", nil, path, "marshal pkcs8 failed", nil, err)
		return nil, false
	}
	pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}
	if err := os.WriteFile(path, pem.EncodeToMemory(pemBlock), permPrivateKey); err != nil {
		logEvent("warn", "", nil, path, "write private key failed", nil, err)
		return nil, false
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

func loadCaKeys(cfg *Config, base string, paths []string) []ssh.PublicKey {
	out := make([]ssh.PublicKey, 0, len(paths))
	for _, p := range paths {
		path := filepath.Join(base, p)
		b, err := os.ReadFile(path)
		if err != nil {
			logEvent("warn", "", nil, path, "read error", nil, err)
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			logEvent("warn", "", nil, path, "parse error", nil, err)
			continue
		}
		out = append(out, pub)
		logEvent("info", "", nil, path, "ca key loaded", nil, nil)
	}
	return out
}
