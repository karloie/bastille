package main

import (
	"bufio"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

func isCAPathAllowed(cfg *Config, path string, strictLogMsg string) bool {
	if !isCertPathAllowed(cfg, path) {
		if strictLogMsg != "" {
			logEvent("warn", "", nil, path, strictLogMsg, nil, nil)
		} else {
			logEvent("err", "", nil, path, "path denied (ca key)", nil, nil)
		}
		return false
	}
	return true
}

func parseCAKeyFile(cfg *Config, path string, strictLogMsg string, logParse bool) []ssh.PublicKey {
	if !isCAPathAllowed(cfg, path, strictLogMsg) {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if logParse {
			logEvent("warn", "", nil, path, "read error", nil, err)
		}
		return nil
	}
	var out []ssh.PublicKey
	rest := b
	for len(rest) > 0 {
		pub, _, _, r, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			if logParse {
				logEvent("warn", "", nil, path, "parse error", nil, err)
			}
			break
		}
		if cert, ok := pub.(*ssh.Certificate); ok && cert.SignatureKey != nil {
			out = append(out, cert.SignatureKey)
		} else {
			out = append(out, pub)
		}
		if logParse {
			logEvent("debug", "", nil, path, "ca key loaded", nil, nil)
		}
		rest = r
	}
	return out
}

func loadStaticCAKeys(cfg *Config, paths []string) []ssh.PublicKey {
	files := expandPathSpecs(paths, "", func(_ string, e os.DirEntry) bool {
		return !e.IsDir() && strings.HasSuffix(e.Name(), ".pub")
	}, func(path string, err error) {
		logEvent("warn", "", nil, path, "ca path scan failed", nil, err)
	})
	uniq := uniqStrings(files)
	out := make([]ssh.PublicKey, 0, len(uniq))
	for _, path := range uniq {
		keys := parseCAKeyFile(cfg, path, "strictmodes denied (ca key)", true)
		out = append(out, keys...)
	}
	return out
}

func loadPerUserCAKeys(cfg *Config, user string, templatedSpecs []string) []ssh.PublicKey {
	user = rxUser.ReplaceAllString(user, "")
	if user == "" || len(templatedSpecs) == 0 {
		return nil
	}
	files := expandPathSpecs(templatedSpecs, user, func(_ string, e os.DirEntry) bool {
		return !e.IsDir() && strings.HasSuffix(e.Name(), ".pub")
	}, nil)
	out := make([]ssh.PublicKey, 0, len(files))
	for _, f := range uniqStrings(files) {
		keys := parseCAKeyFile(cfg, f, "", false)
		out = append(out, keys...)
	}
	return out
}

func loadCertPermit(cfg *Config, user string) string {
	for _, tmpl := range cfg.AuthKeys {
		path := strings.ReplaceAll(tmpl, "{user}", user)
		if !isAuthKeysPathAllowed(cfg, path) {
			continue
		}
		if opts := parsePermitOptionsFromFile(path); opts != "" {
			return opts
		}
	}
	return ""
}

func parsePermitOptionsFromLine(lineBytes []byte, raw string) []string {
	var permits []string
	if _, _, opts, _, err := ssh.ParseAuthorizedKey(lineBytes); err == nil && len(opts) > 0 {
		for _, o := range opts {
			if _, ok := parsePermitOpenRule(o); ok {
				permits = append(permits, o)
			}
		}
		return permits
	}
	for _, part := range strings.Split(raw, ",") {
		p := strings.TrimSpace(part)
		if _, ok := parsePermitOpenRule(p); ok {
			permits = append(permits, p)
		}
	}
	return permits
}

func parsePermitOptionsFromFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	var permits []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		permits = append(permits, parsePermitOptionsFromLine(sc.Bytes(), sc.Text())...)
	}
	if len(permits) == 0 {
		return ""
	}
	return strings.Join(uniqStrings(permits), ",")
}

func newSSHServerConfig(cfg *Config, certOnly bool, metrics *Metrics) *ssh.ServerConfig {
	srv := &ssh.ServerConfig{
		Config: ssh.Config{
			Ciphers:      cfg.Ciphers,
			KeyExchanges: cfg.KEXs,
			MACs:         cfg.MACs,
		},
	}
	if n := loadHostkeys(cfg, cfg.HostKeys, srv); n == 0 {
		return nil
	}
	var staticSpecs []string
	var templatedSpecs []string
	for _, s := range cfg.CertKeys {
		t := strings.TrimSpace(s)
		if t == "" {
			continue
		}
		if strings.Contains(t, "{user}") {
			templatedSpecs = append(templatedSpecs, t)
		} else {
			staticSpecs = append(staticSpecs, t)
		}
	}
	staticCAs := loadStaticCAKeys(cfg, staticSpecs)
	srv.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if certOnly {
			if _, ok := key.(*ssh.Certificate); !ok {
				err := ErrCertRequired
				metrics.RecordAuthDenied()
				logEvent("err", "", meta, "", "auth denied", keyHash(key), err)
				return nil, err
			}
		}
		if cfg != nil && cfg.RsaMin > 0 {
			k := key
			if cert, ok := key.(*ssh.Certificate); ok {
				k = cert.Key
			}
			if ck, ok := k.(ssh.CryptoPublicKey); ok {
				if rsaKey, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok {
					if rsaKey.N.BitLen() < cfg.RsaMin {
						err := fmt.Errorf("rsa key too small: %d < %d", rsaKey.N.BitLen(), cfg.RsaMin)
						metrics.RecordAuthDenied()
						logEvent("err", "", meta, "", "auth denied", keyHash(key), err)
						return nil, err
					}
				}
			}
		}
		effectiveCAs := make([]ssh.PublicKey, 0, len(staticCAs)+4)
		effectiveCAs = append(effectiveCAs, staticCAs...)
		effectiveCAs = append(effectiveCAs, loadPerUserCAKeys(cfg, meta.User(), templatedSpecs)...)
		checker := certChecker(cfg, effectiveCAs, cfg.AuthKeys)
		perms, err := checker.Authenticate(meta, key)
		if err != nil {
			metrics.RecordAuthDenied()
			logEvent("err", "", meta, "", "auth denied", keyHash(key), err)
			return nil, err
		}
		if perms == nil {
			perms = &ssh.Permissions{}
		}
		if perms.Extensions == nil {
			perms.Extensions = make(map[string]string)
		}
		logEvent("debug", "", meta, "", "auth allowed", keyHash(key), nil)
		if _, isCert := key.(*ssh.Certificate); isCert {
			if opts := loadCertPermit(cfg, meta.User()); opts != "" {
				perms.Extensions[permissionKey] = opts
			}
		}
		return perms, nil
	}
	_ = filepath.Separator
	return srv
}
