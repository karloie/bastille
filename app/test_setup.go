//go:build ignore

package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// Sources
	emojiCastle   = "🏰"
	emojiBastille = "亗"
	emojiTarget     = "🎯"
	emojiHarness  = "💻"

	// Status / actions
	emojiPass1           = "✅"
	emojiPass2           = "☑️ "
	emojiPassUnit        = "✅"
	emojiPassIntegration = "🤝"
	emojiFail            = "❌"
	emojiDenied          = "⛔"
	emojiOpen            = "🔗"
	emojiHandshake       = "🤝"
	emojiRateLimited     = "🚦"
	emojiSkip            = "⏭️"

	// Misc
	emojiPackage        = "📦"
	emojiSmtp           = "📧"
	emojiHostKey        = "🔐"
	emojiPubKey         = "🔑"
	emojiLock           = "🔒"
	emojiNote           = "📝"
)

func main() {
	mode := "setup"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "setup":
		if err := generateTestData(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "fmt", "format":
		if err := runFormatter(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown mode %q. Use: setup|fmt\n", mode)
		os.Exit(2)
	}
}

func generateTestData() error {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostPub, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	liloPub, liloPriv, _ := ed25519.GenerateKey(rand.Reader)
	stitchPub, stitchPriv, _ := ed25519.GenerateKey(rand.Reader)
	certuserPub, certuserPriv, _ := ed25519.GenerateKey(rand.Reader)

	caSigner := mustSigner(caPriv)
	liloSigner := mustSigner(liloPriv)
	stitchSigner := mustSigner(stitchPriv)

	if err := os.MkdirAll(filepath.Join("test", "ca"), 0755); err != nil {
		return fmt.Errorf("mkdir test/ca: %w", err)
	}
	if err := os.MkdirAll(filepath.Join("test", "hostkeys"), 0755); err != nil {
		return fmt.Errorf("mkdir test/hostkeys: %w", err)
	}
	if err := os.MkdirAll(filepath.Join("test", "home", "lilo"), 0755); err != nil {
		return fmt.Errorf("mkdir test/home/lilo: %w", err)
	}
	if err := os.MkdirAll(filepath.Join("test", "home", "stitch"), 0755); err != nil {
		return fmt.Errorf("mkdir test/home/stitch: %w", err)
	}
	if err := os.MkdirAll(filepath.Join("test", "home", "certuser"), 0755); err != nil {
		return fmt.Errorf("mkdir test/home/certuser: %w", err)
	}
	if err := os.MkdirAll(filepath.Join("test", "keys"), 0755); err != nil {
		return fmt.Errorf("mkdir test/keys: %w", err)
	}

	caPath := filepath.Join("test", "ca", "ca.pub")
	if err := os.WriteFile(caPath, ssh.MarshalAuthorizedKey(caSigner.PublicKey()), 0644); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}
	fmt.Printf("🔑 %s\n", caPath)

	hostKeyPath := filepath.Join("test", "hostkeys", "ssh_host_ed25519_key")
	if err := writeSSHPrivateKey(hostKeyPath, hostPriv); err != nil {
		return fmt.Errorf("write host key: %w", err)
	}
	fmt.Printf("🔐 %s\n", hostKeyPath)

	liloAuth := fmt.Sprintf(
		`permitopen="127.0.0.1:*" %s`,
		string(ssh.MarshalAuthorizedKey(liloSigner.PublicKey())),
	)
	{
		authSpec := os.Getenv("AUTH_KEYS")
		if strings.TrimSpace(authSpec) == "" {
			// Default location
			liloPath := filepath.Join("test", "home", "lilo", "authorized_keys")
			if err := os.MkdirAll(filepath.Dir(liloPath), 0755); err != nil {
				return fmt.Errorf("mkdir lilo auth: %w", err)
			}
			if err := os.WriteFile(liloPath, []byte(liloAuth), 0644); err != nil {
				return fmt.Errorf("write lilo auth: %w", err)
			}
			fmt.Printf("📜 %s\n", liloPath)
		} else {
			for _, tmpl := range strings.Split(authSpec, ",") {
				t := strings.TrimSpace(tmpl)
				if t == "" || strings.ContainsAny(t, "*?[") {
					// Cannot materialize globs for writing; skip
					continue
				}
				p := strings.ReplaceAll(t, "{user}", "lilo")
				if fi, err := os.Stat(p); err == nil && fi.IsDir() {
					p = filepath.Join(p, "lilo.authorized_keys")
				}
				if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
					return fmt.Errorf("mkdir lilo auth: %w", err)
				}
				if err := os.WriteFile(p, []byte(liloAuth), 0644); err != nil {
					return fmt.Errorf("write lilo auth: %w", err)
				}
				fmt.Printf("📜 %s\n", p)
			}
		}
	}

	stitchAuth := fmt.Sprintf(
		`permitopen="127.0.0.1:*" %s`,
		string(ssh.MarshalAuthorizedKey(stitchSigner.PublicKey())),
	)
	{
		authSpec := os.Getenv("AUTH_KEYS")
		if strings.TrimSpace(authSpec) == "" {
			// Default location
			stitchPath := filepath.Join("test", "home", "stitch", "authorized_keys")
			if err := os.MkdirAll(filepath.Dir(stitchPath), 0755); err != nil {
				return fmt.Errorf("mkdir stitch auth: %w", err)
			}
			if err := os.WriteFile(stitchPath, []byte(stitchAuth), 0644); err != nil {
				return fmt.Errorf("write stitch auth: %w", err)
			}
			fmt.Printf("📜 %s\n", stitchPath)
		} else {
			for _, tmpl := range strings.Split(authSpec, ",") {
				t := strings.TrimSpace(tmpl)
				if t == "" || strings.ContainsAny(t, "*?[") {
					continue
				}
				p := strings.ReplaceAll(t, "{user}", "stitch")
				if fi, err := os.Stat(p); err == nil && fi.IsDir() {
					p = filepath.Join(p, "stitch.authorized_keys")
				}
				if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
					return fmt.Errorf("mkdir stitch auth: %w", err)
				}
				if err := os.WriteFile(p, []byte(stitchAuth), 0644); err != nil {
					return fmt.Errorf("write stitch auth: %w", err)
				}
				fmt.Printf("📜 %s\n", p)
			}
		}
	}

	certuserAuth := fmt.Sprintf(`permitopen="127.0.0.1:*" `)
	{
		authSpec := os.Getenv("AUTH_KEYS")
		if strings.TrimSpace(authSpec) == "" {
			// Default location
			certuserPath := filepath.Join("test", "home", "certuser", "authorized_keys")
			if err := os.MkdirAll(filepath.Dir(certuserPath), 0755); err != nil {
				return fmt.Errorf("mkdir certuser auth: %w", err)
			}
			if err := os.WriteFile(certuserPath, []byte(certuserAuth), 0644); err != nil {
				return fmt.Errorf("write certuser auth: %w", err)
			}
			fmt.Printf("📜 %s\n", certuserPath)
		} else {
			for _, tmpl := range strings.Split(authSpec, ",") {
				t := strings.TrimSpace(tmpl)
				if t == "" || strings.ContainsAny(t, "*?[") {
					continue
				}
				p := strings.ReplaceAll(t, "{user}", "certuser")
				if fi, err := os.Stat(p); err == nil && fi.IsDir() {
					p = filepath.Join(p, "certuser.authorized_keys")
				}
				if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
					return fmt.Errorf("mkdir certuser auth: %w", err)
				}
				if err := os.WriteFile(p, []byte(certuserAuth), 0644); err != nil {
					return fmt.Errorf("write certuser auth: %w", err)
				}
				fmt.Printf("📜 %s\n", p)
			}
		}
	}

	keysDir := filepath.Join("test", "keys")

	keys := map[string]struct {
		priv ed25519.PrivateKey
		pub  ed25519.PublicKey
	}{
		"ca_key":       {caPriv, caPub},
		"lilo_key":     {liloPriv, liloPub},
		"stitch_key":   {stitchPriv, stitchPub},
		"certuser_key": {certuserPriv, certuserPub},
		"host_key":     {hostPriv, hostPub},
	}

	for name, key := range keys {
		privPath := filepath.Join(keysDir, name)
		hexKey := hex.EncodeToString(key.priv)
		if err := os.WriteFile(privPath, []byte(hexKey), 0600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
		fmt.Printf("🔐 %s\n", privPath)

		pubPath := privPath + ".pub"
		signer := mustSigner(key.priv)
		if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0644); err != nil {
			return fmt.Errorf("write %s.pub: %w", name, err)
		}
		fmt.Printf("🔑 %s\n", pubPath)
	}

	return nil
}

func writeSSHPrivateKey(path string, key ed25519.PrivateKey) error {
	hexKey := hex.EncodeToString(key)
	return os.WriteFile(path, []byte(hexKey), 0600)
}

func mustSigner(key ed25519.PrivateKey) ssh.Signer {
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		panic(err)
	}
	return signer
}

type event struct {
	Time    time.Time `json:"Time"`
	Action  string    `json:"Action"`
	Package string    `json:"Package"`
	Test    string    `json:"Test,omitempty"`
	Elapsed float64   `json:"Elapsed,omitempty"`
	Output  string    `json:"Output,omitempty"`
}

func runFormatter() error {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	totalPass := 0
	totalFail := 0
	totalSkip := 0
	seenPkgs := map[string]struct{}{}
	anyFailure := false

	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var e event
		if err := json.Unmarshal(line, &e); err != nil {
			fmt.Println(string(line))
			continue
		}
		if e.Package != "" {
			seenPkgs[e.Package] = struct{}{}
		}

		switch e.Action {
		case "run":
		case "output":
			txt := strings.TrimSuffix(e.Output, "\n")
			txt = stripFileLinePrefix(txt)
			if isHarnessNoise(txt) {
				continue
			}
			if e.Test != "" {
				emoji, cleaned := sourceEmojiAndClean(txt)
				fmt.Printf("%s [%s] %s\n", emoji, e.Test, cleaned)
			} else {
				emoji, cleaned := sourceEmojiAndClean(txt)
				fmt.Printf("%s %s\n", emoji, cleaned)
			}
		case "pass":
			if e.Test != "" {
				totalPass++
				fmt.Printf("%s %s (%s)\n", statusIcon(e.Test, true), label(e.Package, e.Test), fmtElapsed(e.Elapsed))
			} else {
			}
		case "fail":
			if e.Test != "" {
				totalFail++
				anyFailure = true
				fmt.Printf("%s %s FAIL %s (%s)\n", emojiHarness, statusIcon(e.Test, false), label(e.Package, e.Test), fmtElapsed(e.Elapsed))
			} else {
				anyFailure = true
				fmt.Printf("%s %s FAIL package %s (%s)\n", emojiPackage, emojiFail, shortPkg(e.Package), fmtElapsed(e.Elapsed))
			}
		case "skip":
			if e.Test != "" {
				totalSkip++
				fmt.Printf("%s SKIP %s\n", emojiHarness, label(e.Package, e.Test))
			} else {
				fmt.Printf("%s SKIP package %s\n", emojiPackage, shortPkg(e.Package))
			}
		}
	}

	pkgCount := len(seenPkgs)
	fmt.Printf("\n%s PASS %d   %s FAIL %d   %s  SKIP %d  in %d %s(s)\n", emojiPassUnit, totalPass, emojiFail, totalFail, emojiSkip, totalSkip, pkgCount, emojiPackage)

	if err := sc.Err(); err != nil {
		return err
	}
	if anyFailure {
		os.Exit(1)
	}
	return nil
}



func label(pkg, test string) string {
	return test
}

func shortPkg(pkg string) string {
	if pkg == "" {
		return ""
	}
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		return pkg[i+1:]
	}
	return pkg
}



func isIntegrationTest(name string) bool {
	return strings.HasPrefix(name, "TestAccess") ||
		strings.HasPrefix(name, "TestRateLimit") ||
		strings.HasPrefix(name, "TestMaxTunnels") ||
		strings.HasPrefix(name, "TestInvalidChannel") ||
		strings.HasPrefix(name, "TestCertificateAuth") ||
		strings.HasPrefix(name, "TestCertAuthEnforced")
}

func statusIcon(name string, passed bool) string {
	if passed {
		if isIntegrationTest(name) {
			return emojiPass2
		} else {
			return emojiPass1
		}
	}
	return emojiFail
}

func fmtElapsed(sec float64) string {
	if sec <= 0 {
		return "0s"
	}
	d := time.Duration(sec * float64(time.Second))
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func isHarnessNoise(line string) bool {
	if strings.HasPrefix(line, "=== RUN   ") {
		return true
	}
	if strings.HasPrefix(line, "=== PAUSE ") {
		return true
	}
	if strings.HasPrefix(line, "=== CONT  ") {
		return true
	}
	if strings.HasPrefix(line, "--- PASS: ") {
		return true
	}
	if strings.HasPrefix(line, "--- FAIL: ") {
		return true
	}
	if strings.HasPrefix(line, "--- SKIP: ") {
		return true
	}
	if strings.HasPrefix(line, "ok  ") || strings.HasPrefix(line, "FAIL\t") {
		return true
	}
	return false
}

func stripFileLinePrefix(s string) string {
	j := strings.Index(s, ".go:")
	if j > 0 {
		n := j + len(".go:")
		for n < len(s) && s[n] >= '0' && s[n] <= '9' {
			n++
		}
		if n < len(s) && s[n] == ':' {
			n++
			for n < len(s) && s[n] == ' ' {
				n++
			}
			return strings.TrimLeft(s[n:], " ")
		}
	}
	return s
}

func sourceEmojiAndClean(s string) (string, string) {
	// Map src tokens to emojis and strip the src=... token from the line; also strip level=...
	emoji := emojiHarness
	if strings.Contains(s, "src=bastille") {
		emoji = emojiBastille
	}
	if strings.Contains(s, "src=mock") {
		emoji = emojiTarget
	}
	clean := strings.ReplaceAll(s, " src=bastille", "")
	clean = strings.ReplaceAll(clean, " src=mock", "")
	clean = stripLevelToken(clean)
	return emoji, clean
}

func decorateLog(test, txt string) (string, string) {
	lower := strings.ToLower(txt)

	switch {
	case strings.Contains(lower, "mock target listening"):
		return emojiTarget, txt

	case strings.Contains(lower, "bastille"):
		return emojiBastille, txt

	case strings.Contains(lower, "tunnel opened"):
		return emojiPass1, txt
	case strings.Contains(lower, "tunnel denied"):
		return emojiDenied, txt
	case strings.Contains(lower, "too many tunnels"):
		return emojiFail, txt

	case strings.Contains(lower, "dial failed"):
		return emojiFail, txt
	case strings.Contains(lower, "handshake failed"):
		return emojiFail, txt
	case strings.Contains(lower, "smtp"):
		return emojiSmtp, txt
	case strings.Contains(lower, "host key "):
		return emojiHostKey, txt
	case strings.Contains(lower, "host public key"):
		return emojiPubKey, txt
	case strings.Contains(lower, "ca key"):
		return emojiPubKey, txt
	}
	return emojiNote, txt
}

func stripLevelToken(s string) string {
	// Remove " level=INFO", " level=DEBUG", etc.
	if i := strings.Index(s, " level="); i >= 0 {
		j := i + len(" level=")
		for j < len(s) && ((s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= 'a' && s[j] <= 'z')) {
			j++
		}
		return s[:i] + s[j:]
	}
	return s
}
