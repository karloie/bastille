package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = ""
)

const (
	permissionKey     = "opts"
	permGroupOther    = 0o022
	fingerprintLength = 16
	permDirDefault    = 0o755
	permPrivateKey    = 0o600
	permPublicKey     = 0o644
)

var (
	rxPermit       = regexp.MustCompile(`permitopen="?([^"]+)"?`)
	rxUserSanitize = regexp.MustCompile(`[^a-zA-Z0-9._-]`)
)

func permitMatch(pattern, dst string) bool {
	pattern = strings.TrimSpace(pattern)
	ph, pp, ok := strings.Cut(pattern, ":")
	if !ok {
		return false
	}
	dh, dp, ok := strings.Cut(dst, ":")
	if !ok {
		return false
	}
	hostOK := ph == "*" || ph == dh
	portOK := pp == "*" || pp == dp
	return hostOK && portOK
}

func permitAllowed(opts, dst string) bool {
	if opts == "" {
		return false
	}
	for _, o := range strings.Split(opts, ",") {
		if m := rxPermit.FindStringSubmatch(o); len(m) > 1 && permitMatch(m[1], dst) {
			return true
		}
	}
	return false
}

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
			candidates := expandPathSpecs(authFiles, user, func(_ string, e os.DirEntry) bool {
				return !e.IsDir()
			}, nil)

			for _, path := range uniqStrings(candidates) {
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
	var genTargets []string

	candidates := expandPathSpecs(hostKeys, "", func(_ string, e os.DirEntry) bool {
		if e.IsDir() {
			return false
		}
		name := e.Name()
		return strings.HasPrefix(name, "ssh_host_") && strings.HasSuffix(name, "_key") && !strings.HasSuffix(name, ".pub")
	}, func(path string, err error) {
		logEvent("warn", "", nil, path, "host key path scan failed", nil, err)
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

	uniq := uniqStrings(candidates)

	loaded := 0
	for _, path := range uniq {
		nameLower := strings.ToLower(filepath.Base(path))
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
	files := expandPathSpecs(paths, "", func(_ string, e os.DirEntry) bool {
		return !e.IsDir() && strings.HasSuffix(e.Name(), ".pub")
	}, func(path string, err error) {
		logEvent("warn", "", nil, path, "ca path scan failed", nil, err)
	})

	uniq := uniqStrings(files)

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

func loadTemplatedCertAuthorities(cfg *Config, user string, templatedSpecs []string) []ssh.PublicKey {
	user = rxUserSanitize.ReplaceAllString(user, "")
	if user == "" || len(templatedSpecs) == 0 {
		return nil
	}

	files := expandPathSpecs(templatedSpecs, user, func(_ string, e os.DirEntry) bool {
		return !e.IsDir() && strings.HasSuffix(e.Name(), ".pub")
	}, nil)

	out := make([]ssh.PublicKey, 0, len(files))
	for _, f := range uniqStrings(files) {

		if !certStrictPathOK(cfg, f) {
			continue
		}

		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}

		rest := b
		for len(rest) > 0 {
			pub, _, _, r, err := ssh.ParseAuthorizedKey(rest)
			if err != nil {
				break
			}
			if cert, ok := pub.(*ssh.Certificate); ok && cert.SignatureKey != nil {
				out = append(out, cert.SignatureKey)
			} else {
				out = append(out, pub)
			}
			rest = r
		}
	}

	return out
}

func newBastilleServerConfig(cfg *Config, certOnly bool) *ssh.ServerConfig {
	srv := &ssh.ServerConfig{Config: ssh.Config{
		Ciphers:      cfg.Ciphers,
		KeyExchanges: cfg.KeyExchanges,
		MACs:         cfg.MACs,
	}}

	if n := loadHostkeys(cfg, cfg.HOST_KEYS, srv); n == 0 {
		return nil
	}

	staticSpecs, templatedSpecs := splitCertKeys(cfg.CERT_KEYS)
	staticCAs := loadCaKeys(cfg, staticSpecs)

	srv.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if certOnly {
			if _, ok := key.(*ssh.Certificate); !ok {
				err := errors.New("cert required")
				logEvent("warn", "", meta, "", "auth denied", keyHash(key), err)
				return nil, err
			}
		}

		effectiveCAs := make([]ssh.PublicKey, 0, len(staticCAs)+4)
		effectiveCAs = append(effectiveCAs, staticCAs...)
		effectiveCAs = append(effectiveCAs, loadTemplatedCertAuthorities(cfg, meta.User(), templatedSpecs)...)

		checker := certChecker(cfg, effectiveCAs, cfg.AUTH_KEYS)
		perms, err := checker.Authenticate(meta, key)
		if err != nil {
			logEvent("warn", "", meta, "", "auth denied", keyHash(key), err)
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

	return srv
}

func expandPathSpecs(specs []string, user string, allowDirEntry func(dir string, e os.DirEntry) bool, onError func(path string, err error)) []string {
	if len(specs) == 0 {
		return nil
	}

	var out []string
	for _, raw := range specs {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if user != "" {
			p = strings.ReplaceAll(p, "{user}", user)
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
		}
		if strings.ContainsAny(p, "*?[") {
			matches, err := filepath.Glob(p)
			if err == nil {
				out = append(out, matches...)
			} else if onError != nil {
				onError(p, err)
			}
			continue
		}
		fi, err := os.Stat(p)
		if err == nil && fi.IsDir() {
			entries, derr := os.ReadDir(p)
			if derr == nil {
				for _, e := range entries {
					if allowDirEntry(p, e) {
						out = append(out, filepath.Join(p, e.Name()))
					}
				}
			} else if onError != nil {
				onError(p, derr)
			}
			continue
		}
		if err != nil && onError != nil {
			onError(p, err)
		}
		out = append(out, p)
	}
	return out
}

func loadCertPermit(cfg *Config, user string) string {
	for _, tmpl := range cfg.AUTH_KEYS {
		path := strings.ReplaceAll(tmpl, "{user}", user)
		if cfg.StrictModes && !strictPathOK(cfg, path) {
			continue
		}
		if opts := readPermitOptions(path); opts != "" {
			return opts
		}
	}
	return ""
}

func readPermitOptions(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	var permits []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lineBytes := sc.Bytes()
		if _, _, opts, _, err := ssh.ParseAuthorizedKey(lineBytes); err == nil && len(opts) > 0 {
			for _, o := range opts {
				if rxPermit.MatchString(o) {
					permits = append(permits, o)
				}
			}
			continue
		}
		raw := sc.Text()
		for _, part := range strings.Split(raw, ",") {
			p := strings.TrimSpace(part)
			if rxPermit.MatchString(p) {
				permits = append(permits, p)
			}
		}
	}
	if len(permits) == 0 {
		return ""
	}
	return strings.Join(uniqStrings(permits), ",")
}

func strictPathOK(cfg *Config, path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	mode := fi.Mode()
	if mode&os.ModeSymlink != 0 || !mode.IsRegular() {
		return false
	}
	if mode.Perm()&permGroupOther != 0 {
		return false
	}

	if !cfg.StrictModes {
		dir := filepath.Dir(path)
		di, err := os.Stat(dir)
		if err != nil {
			return false
		}
		if di.Mode().Perm()&permGroupOther != 0 {
			return false
		}
		return true
	}

	if hasSymlinkComponent(path) {
		return false
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	if rp, err := filepath.EvalSymlinks(absPath); err == nil {
		absPath = rp
	} else {
		return false
	}

	fixedBases, patternedBases := deriveAllowedBases(cfg.AUTH_KEYS)
	if len(fixedBases) == 0 && len(patternedBases) == 0 {
		return false
	}

	var matchedBase string
	matched := false

	for _, b := range fixedBases {
		if strings.TrimSpace(b) == "" {
			continue
		}
		bAbs, err := filepath.Abs(b)
		if err != nil {
			continue
		}
		if rb, err := filepath.EvalSymlinks(bAbs); err == nil {
			bAbs = rb
		}
		rel, err := filepath.Rel(bAbs, absPath)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			matched = true
			matchedBase = bAbs
			break
		}
	}

	if !matched {
		for _, pat := range patternedBases {
			if baseRoot, ok := matchesUserBase(pat, absPath); ok {
				matched = true
				matchedBase = baseRoot
				break
			}
		}
	}

	if !matched {
		return false
	}

	dir := filepath.Dir(absPath)
	for {
		di, err := os.Lstat(dir)
		if err != nil {
			return false
		}
		if di.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if di.Mode().Perm()&permGroupOther != 0 {
			return false
		}
		if dir == matchedBase {
			break
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
		rel, err := filepath.Rel(matchedBase, next)
		if err != nil {
			return false
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			break
		}
		dir = next
	}
	return true
}

func deriveAllowedBases(templates []string) (fixed []string, patterns []string) {
	for _, tmpl := range templates {
		t := strings.TrimSpace(tmpl)
		if t == "" {
			continue
		}
		t = filepath.Clean(t)
		if i := indexAny(t, "*?["); i >= 0 {
			if j := strings.LastIndexByte(t[:i], byte(filepath.Separator)); j >= 0 {
				t = t[:j]
			} else {
				continue
			}
		}

		if strings.Contains(t, "{user}") {
			idx := strings.Index(t, "{user}")
			pre := strings.TrimRight(t[:idx], string(filepath.Separator))
			post := strings.TrimPrefix(t[idx+len("{user}"):], string(filepath.Separator))

			if pre != "" {
				fixed = append(fixed, pre)
				patterns = append(patterns, filepath.Join(pre, "{user}"))
				if post != "" {
					postDir := filepath.Dir(post)
					if postDir != "." && postDir != post {
						patterns = append(patterns, filepath.Join(pre, "{user}", postDir))
					} else {
						patterns = append(patterns, filepath.Join(pre, "{user}", post))
					}
				}
			} else {
				patterns = append(patterns, "{user}")
				if post != "" {
					postDir := filepath.Dir(post)
					if postDir != "." && postDir != post {
						patterns = append(patterns, filepath.Join("{user}", postDir))
					} else {
						patterns = append(patterns, filepath.Join("{user}", post))
					}
				}
			}
		} else {
			dir := filepath.Dir(t)
			if dir != "." && dir != "" {
				fixed = append(fixed, dir)
			}
		}
	}
	return uniqStrings(fixed), uniqStrings(patterns)
}

func uniqStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		c := filepath.Clean(s)
		if c == "." || c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

func indexAny(s, chars string) int {
	for i, r := range s {
		if strings.ContainsRune(chars, r) {
			return i
		}
	}
	return -1
}

func splitCertKeys(specs []string) (static []string, templated []string) {
	for _, s := range specs {
		t := strings.TrimSpace(s)
		if t == "" {
			continue
		}
		if strings.Contains(t, "{user}") {
			templated = append(templated, t)
		} else {
			static = append(static, t)
		}
	}
	return
}

func matchesUserBase(pattern string, absPath string) (string, bool) {
	idx := strings.Index(pattern, "{user}")
	if idx < 0 {
		return "", false
	}
	pre := filepath.Clean(strings.TrimRight(pattern[:idx], string(filepath.Separator)))
	postRaw := strings.TrimPrefix(pattern[idx+len("{user}"):], string(filepath.Separator))
	post := ""
	if postRaw != "" {
		post = filepath.Clean(postRaw)
	}

	rest := absPath
	if pre != "" {
		prefix := pre
		if absPath == prefix {
			rest = ""
		} else {
			prefixWithSep := prefix + string(filepath.Separator)
			if !strings.HasPrefix(absPath, prefixWithSep) {
				return "", false
			}
			rest = absPath[len(prefixWithSep):]
		}
	} else {
		rest = strings.TrimPrefix(rest, string(filepath.Separator))
	}

	sepIdx := strings.IndexRune(rest, filepath.Separator)
	var userSeg, afterUser string
	if sepIdx >= 0 {
		userSeg = rest[:sepIdx]
		afterUser = rest[sepIdx+1:]
	} else {
		userSeg = rest
		afterUser = ""
	}
	if userSeg == "" {
		return "", false
	}

	if post != "" {
		postPrefix := post + string(filepath.Separator)
		if !(afterUser == post || strings.HasPrefix(afterUser, postPrefix)) {
			return "", false
		}
		baseRoot := filepath.Clean(filepath.Join(pre, userSeg, post))
		rel, err := filepath.Rel(baseRoot, absPath)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", false
		}
		return baseRoot, true
	}

	baseRoot := filepath.Clean(filepath.Join(pre, userSeg))
	rel, err := filepath.Rel(baseRoot, absPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return baseRoot, true
}

func hasSymlinkComponent(p string) bool {
	abs, err := filepath.Abs(p)
	if err != nil {
		return true
	}
	cur := ""
	if filepath.IsAbs(abs) {
		cur = string(filepath.Separator)
	}
	parts := splitPathSegments(abs)
	for i, seg := range parts {
		if i == 0 && cur == string(filepath.Separator) {
			cur = filepath.Join(cur, seg)
		} else if cur == "" {
			cur = seg
		} else {
			cur = filepath.Join(cur, seg)
		}
		fi, err := os.Lstat(cur)
		if err != nil {
			return true
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

func splitPathSegments(p string) []string {
	clean := filepath.Clean(p)
	if clean == string(filepath.Separator) || clean == "." {
		return nil
	}
	parts := strings.Split(clean, string(filepath.Separator))
	out := make([]string, 0, len(parts))
	for _, s := range parts {
		if s != "" && s != "." {
			out = append(out, s)
		}
	}
	return out
}

func certStrictPathOK(cfg *Config, path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	mode := fi.Mode()
	if mode&os.ModeSymlink != 0 || !mode.IsRegular() {
		return false
	}
	if mode.Perm()&permGroupOther != 0 {
		return false
	}

	if hasSymlinkComponent(path) {
		return false
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	if rp, err := filepath.EvalSymlinks(absPath); err == nil {
		absPath = rp
	} else {
		return false
	}

	fixedBases, patternedBases := deriveAllowedBases(cfg.CERT_KEYS)
	if len(fixedBases) == 0 && len(patternedBases) == 0 {
		return false
	}

	var matchedBase string
	matched := false

	for _, b := range fixedBases {
		if strings.TrimSpace(b) == "" {
			continue
		}
		bAbs, err := filepath.Abs(b)
		if err != nil {
			continue
		}
		if rb, err := filepath.EvalSymlinks(bAbs); err == nil {
			bAbs = rb
		}
		rel, err := filepath.Rel(bAbs, absPath)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			matched = true
			matchedBase = bAbs
			break
		}
	}

	if !matched {
		for _, pat := range patternedBases {
			if baseRoot, ok := matchesUserBase(pat, absPath); ok {
				matched = true
				matchedBase = baseRoot
				break
			}
		}
	}
	if !matched {
		return false
	}

	dir := filepath.Dir(absPath)
	for {
		di, err := os.Lstat(dir)
		if err != nil {
			return false
		}
		if di.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if di.Mode().Perm()&permGroupOther != 0 {
			return false
		}
		if dir == matchedBase {
			break
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
		rel, err := filepath.Rel(matchedBase, next)
		if err != nil {
			return false
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			break
		}
		dir = next
	}
	return true
}
