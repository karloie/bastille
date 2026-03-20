package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/karloie/bastille/pkg/config"
	"golang.org/x/crypto/ssh"
)

const (
	permGroupOther = 0o022
	permDirDefault = 0o755
	permPrivateKey = 0o600
	permPublicKey  = 0o644
)

func loadHostkeys(cfg *config.Config, hostKeys []string, srvCfg *ssh.ServerConfig) int {
	var genTargets []string
	candidates := config.ExpandPathSpecs(hostKeys, "", func(_ string, e os.DirEntry) bool {
		if e.IsDir() {
			return false
		}
		name := e.Name()
		return strings.HasPrefix(name, "ssh_host_") &&
			strings.HasSuffix(name, "_key") &&
			!strings.HasSuffix(name, ".pub")
	}, func(path string, err error) {
		config.LogEvent("warn", "", nil, path, "host key path scan failed", nil, err)
	})
	for _, raw := range hostKeys {
		hk := strings.TrimSpace(raw)
		if hk == "" {
			continue
		}
		fi, err := os.Stat(hk)
		if err == nil && fi.IsDir() {
			genTargets = append(genTargets, filepath.Join(hk, "ssh_host_ed25519_key"))
			continue
		}
		if strings.Contains(strings.ToLower(hk), "ed25519") {
			genTargets = append(genTargets, hk)
		}
	}
	uniq := config.UniqStrings(candidates)
	loaded := 0
	for _, path := range uniq {
		nameLower := strings.ToLower(filepath.Base(path))
		if strings.Contains(nameLower, "ed25519") {
			if s, ok := ensureEd25519HostKey(path); ok {
				srvCfg.AddHostKey(s)
				loaded++
				continue
			}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			config.LogEvent("warn", "", nil, path, "host key read failed", nil, err)
			continue
		}
		s, err := ssh.ParsePrivateKey(b)
		if err != nil {
			config.LogEvent("warn", "", nil, path, "host key parse failed", nil, err)
			continue
		}
		if cfg != nil && cfg.RsaMin > 0 {
			if ck, ok := s.PublicKey().(ssh.CryptoPublicKey); ok {
				if rsaKey, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok {
					if rsaKey.N.BitLen() < cfg.RsaMin {
						config.LogEvent(
							"warn",
							"",
							nil,
							path,
							"host key rejected (rsa too small)",
							nil,
							fmt.Errorf("%d < %d", rsaKey.N.BitLen(), cfg.RsaMin),
						)
						continue
					}
				}
			}
		}
		srvCfg.AddHostKey(s)
		loaded++
		config.LogEvent("debug", "", nil, path, "host key loaded", nil, nil)
	}
	if loaded == 0 {
		for _, tgt := range genTargets {
			if s, ok := ensureEd25519HostKey(tgt); ok {
				srvCfg.AddHostKey(s)
				loaded++
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
		config.LogEvent("warn", "", nil, path, "ed25519 keygen failed", nil, err)
		return nil, false
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		config.LogEvent("warn", "", nil, path, "marshal pkcs8 failed", nil, err)
		return nil, false
	}
	pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}
	pemBytes := pem.EncodeToMemory(pemBlock)
	if err := os.MkdirAll(filepath.Dir(path), permDirDefault); err != nil {
		config.LogEvent("warn", "", nil, path, "mkdir failed", nil, err)
		if tmpDir, terr := os.MkdirTemp("", "bastille-hostkeys-*"); terr == nil {
			path = filepath.Join(tmpDir, filepath.Base(path))
			config.LogEvent("info", "", nil, path, "using temp path for host key", nil, nil)
		} else {
			return nil, false
		}
	}
	if err := os.WriteFile(path, pemBytes, permPrivateKey); err != nil {
		if tmpDir, terr := os.MkdirTemp("", "bastille-hostkeys-*"); terr == nil {
			path = filepath.Join(tmpDir, filepath.Base(path))
			if werr := os.WriteFile(path, pemBytes, permPrivateKey); werr != nil {
				config.LogEvent("warn", "", nil, path, "write private key failed (temp)", nil, werr)
				return nil, false
			}
			config.LogEvent("info", "", nil, path, "host key written to temp path", nil, nil)
		} else {
			config.LogEvent("warn", "", nil, path, "write private key failed", nil, err)
			return nil, false
		}
	} else {
		level := "warn"
		if strings.Contains(path, os.TempDir()) || strings.Contains(path, "/tmp/") {
			level = "debug"
		}
		config.LogEvent(level, "", nil, path, "ed25519 host key generated", nil, nil)
	}
	if pubSigner, err := ssh.NewPublicKey(pub); err == nil {
		_ = os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(pubSigner), permPublicKey)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		config.LogEvent("warn", "", nil, path, "signer create failed", nil, err)
		return nil, false
	}
	return s, true
}
