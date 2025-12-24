package main

import (
	"os"
	"path/filepath"
	"strings"
)

func isAuthKeysPathAllowed(cfg *Config, path string) bool {
	if !isBasicPathValid(path) {
		logEvent("err", "", nil, path, "path denied (authorized_keys: basic)", nil, nil)
		return false
	}
	if cfg == nil || !cfg.StrictMode {
		return true
	}
	if !isStrictPathValid(cfg, path) {
		logEvent("err", "", nil, path, "path denied (authorized_keys: strict)", nil, nil)
		return false
	}
	return true
}

func expandPathSpecs(
	specs []string,
	user string,
	allowDirEntry func(dir string, e os.DirEntry) bool,
	onError func(path string, err error),
) []string {
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

func isAllowed(absPath string, fixedBases []string, patternedBases []string) (string, bool) {
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
			return bAbs, true
		}
	}
	for _, p := range patternedBases {
		if base, ok := matchesUser(p, absPath); ok {
			return base, true
		}
	}
	return "", false
}

func allowedBases(templates []string) (fixed []string, patterns []string) {
	for _, tmpl := range templates {
		t := strings.TrimSpace(tmpl)
		if t == "" {
			continue
		}
		t = filepath.Clean(t)
		if i := strings.IndexAny(t, "*?["); i >= 0 {
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

func matchesUser(pattern string, absPath string) (string, bool) {
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
	absPath = filepath.Clean(absPath)
	userSeg := ""
	rel := ""
	if pre != "" {
		rel, _ = filepath.Rel(pre, absPath)
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", false
		}
	} else {
		if filepath.IsAbs(absPath) {
			rel = strings.TrimPrefix(absPath, string(filepath.Separator))
		} else {
			rel = absPath
		}
	}
	parts := strings.Split(rel, string(filepath.Separator))
	for _, p := range parts {
		if p != "" && p != "." {
			userSeg = p
			break
		}
	}
	if userSeg == "" {
		return "", false
	}
	if post != "" {
		baseRoot := filepath.Clean(filepath.Join(pre, userSeg, post))
		rel2, err := filepath.Rel(baseRoot, absPath)
		if err != nil || rel2 == ".." || strings.HasPrefix(rel2, ".."+string(filepath.Separator)) {
			return "", false
		}
		return baseRoot, true
	}
	baseRoot := filepath.Clean(filepath.Join(pre, userSeg))
	rel2, err := filepath.Rel(baseRoot, absPath)
	if err != nil || rel2 == ".." || strings.HasPrefix(rel2, ".."+string(filepath.Separator)) {
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
	clean := filepath.Clean(abs)
	if clean == string(filepath.Separator) || clean == "." {
		return false
	}
	parts := strings.Split(clean, string(filepath.Separator))
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

func isBasicPathValid(path string) bool {
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

func isStrictPathValid(cfg *Config, path string) bool {
	if cfg == nil {
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
	fixedBases, patternedBases := allowedBases(cfg.AuthKeys)
	matchedBase, ok := isAllowed(absPath, fixedBases, patternedBases)
	if !ok || matchedBase == "" {
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

func isPathValid(cfg *Config, path string) bool {
	if !isBasicPathValid(path) {
		return false
	}
	if cfg == nil || !cfg.StrictMode {
		return true
	}
	return isStrictPathValid(cfg, path)
}

func isCertPathAllowed(cfg *Config, path string) bool {
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
	fixedBases, patternedBases := allowedBases(cfg.CertKeys)
	if len(fixedBases) == 0 && len(patternedBases) == 0 {
		return false
	}
	_, ok := isAllowed(absPath, fixedBases, patternedBases)
	if !ok {
		return false
	}
	return true
}
