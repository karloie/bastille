package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	defaultListenPort = 22222
	defaultSMTPPort   = 587
	defaultRateLimit  = 10
	maxPort           = 65535
)

type Config struct {
	ADDRESS string

	AUTH_KEYS []string

	AUTH_MODE string

	CERT_KEYS []string

	HOST_KEYS []string

	MaxTunnels int

	RateLimit int

	DialTO time.Duration

	LogLevel string

	StrictModes bool

	Testing bool

	Ciphers []string

	KeyExchanges []string

	MACs []string

	SMTPHost     string
	SMTPMail     string
	SMTPPassFile string
	SMTPPort     int
	SMTPUser     string
}

func LoadConfig() Config {
	algos := getSupportedAlgos()

	addr := strings.TrimSpace(envStr("LISTEN", ""))
	if addr == "" {
		addr = fmt.Sprintf(":%d", envInt("LISTEN_PORT", defaultListenPort))
	}

	logLevel := strings.ToUpper(envStr("LOGLEVEL", "INFO"))

	hardened := getHardenedDefaults()
	ciphers := filterToSupported(evalAlgorithms("CIPHERS", hardened.Ciphers), algos.Ciphers)
	kex := filterToSupported(evalAlgorithms("KEXALGORITHMS", hardened.KeyExchanges), algos.KeyExchanges)
	macs := filterToSupported(evalAlgorithms("MACS", hardened.MACs), algos.MACs)

	cfg := Config{
		ADDRESS:      addr,
		AUTH_MODE:    envStr("AUTHMODE", "optional"),
		AUTH_KEYS:    splitList(envStr("AUTH_KEYS", "test/home/{user}/authorized_keys")),
		CERT_KEYS:    splitList(envStr("CERT_KEYS", "/ca")),
		HOST_KEYS:    splitList(envStr("HOST_KEYS", "/hostkeys")),
		MaxTunnels:   envInt("MAX_TUNNELS", 5),
		RateLimit:    envInt("RATE", defaultRateLimit),
		DialTO:       5 * time.Second,
		LogLevel:     logLevel,
		StrictModes:  envBool("STRICTMODES", false),
		Testing:      envBool("TESTING", false),
		Ciphers:      ciphers,
		KeyExchanges: kex,
		MACs:         macs,
		SMTPHost:     envStr("SMTP_HOST", ""),
		SMTPMail:     envStr("SMTP_MAIL", ""),
		SMTPPort:     envInt("SMTP_PORT", defaultSMTPPort),
		SMTPUser:     envStr("SMTP_USER", ""),
		SMTPPassFile: envStr("SMTP_PASS_FILE", "/run/secrets/smtp_pass"),
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	return cfg
}

func (c Config) Validate() error {
	if c.MaxTunnels <= 0 {
		return fmt.Errorf("MAX_TUNNELS must be > 0, got %d", c.MaxTunnels)
	}
	if c.RateLimit <= 0 {
		return fmt.Errorf("RATE must be > 0, got %d", c.RateLimit)
	}
	if c.SMTPPort <= 0 || c.SMTPPort > maxPort {
		return fmt.Errorf("SMTP_PORT must be 1-%d, got %d", maxPort, c.SMTPPort)
	}
	validLevels := []string{"DEBUG", "INFO", "VERBOSE", "WARN", "ERROR"}
	if !slices.Contains(validLevels, c.LogLevel) {
		return fmt.Errorf("LOGLEVEL must be one of %v, got %q", validLevels, c.LogLevel)
	}
	if c.SMTPHost != "" && c.SMTPMail != "" {
		if _, err := os.Stat(c.SMTPPassFile); err != nil && !c.Testing {
			return fmt.Errorf("SMTP enabled but password file not found: %s", c.SMTPPassFile)
		}
	}
	if len(c.Ciphers) == 0 {
		return fmt.Errorf("no supported ciphers after filtering")
	}
	if len(c.KeyExchanges) == 0 {
		return fmt.Errorf("no supported key exchange algorithms after filtering")
	}
	if len(c.MACs) == 0 {
		return fmt.Errorf("no supported MAC algorithms after filtering")
	}

	fixed, patterns := deriveAllowedBases(c.AUTH_KEYS)
	if len(fixed) == 0 && len(patterns) == 0 {
		if c.StrictModes {
			return fmt.Errorf("STRICTMODES enabled but no allowed AUTH_KEYS bases could be derived; check AUTH_KEYS")
		}
		fmt.Fprintf(os.Stderr, "Warning: no allowed AUTH_KEYS bases could be derived; STRICTMODES is disabled so this will not be enforced\n")
	}

	return nil
}

func getSupportedAlgos() (a struct {
	Ciphers, KeyExchanges, MACs []string
}) {
	supported := ssh.SupportedAlgorithms()
	a.Ciphers = supported.Ciphers
	a.KeyExchanges = supported.KeyExchanges
	a.MACs = supported.MACs
	return
}

func getHardenedDefaults() (a struct {
	Ciphers      []string
	KeyExchanges []string
	MACs         []string
}) {
	a.Ciphers = []string{
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes256-ctr",
		"aes192-ctr",
		"aes128-gcm@openssh.com",
		"aes128-ctr",
	}
	a.KeyExchanges = []string{
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256",
		"curve25519-sha256@libssh.org",
		"diffie-hellman-group18-sha512",
		"diffie-hellman-group-exchange-sha256",
		"diffie-hellman-group16-sha512",
	}
	a.MACs = []string{
		"hmac-sha2-512-etm@openssh.com",
		"hmac-sha2-256-etm@openssh.com",
		"umac-128-etm@openssh.com",
	}
	return
}

func filterToSupported(in, supported []string) []string {
	if len(in) == 0 {
		return nil
	}
	var out []string
	for _, v := range in {
		for _, s := range supported {
			if v == s {
				out = append(out, v)
				break
			}
		}
	}
	if len(out) <= 1 {
		return out
	}
	seen := map[string]struct{}{}
	uniq := make([]string, 0, len(out))
	for _, v := range out {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		uniq = append(uniq, v)
	}
	return uniq
}

func evalAlgorithms(env string, defaults []string) []string {
	val := strings.TrimSpace(os.Getenv(env))
	if val == "" {
		return defaults
	}
	val = strings.NewReplacer("\n", ",", " ", "").Replace(val)
	list := strings.Split(val, ",")
	if len(list) == 0 {
		return defaults
	}
	normalized := make([]string, 0, len(list))
	for _, a := range list {
		a = strings.TrimPrefix(strings.TrimPrefix(a, "+"), "-")
		if a != "" {
			normalized = append(normalized, a)
		}
	}
	switch val[0] {
	case '+':
		for _, a := range normalized {
			if !slices.Contains(defaults, a) {
				defaults = append(defaults, a)
			}
		}
		return defaults
	case '-':
		var keep []string
		for _, base := range defaults {
			remove := false
			for _, p := range normalized {
				if p == base || func() bool {
					ok, err := filepath.Match(p, base)
					return err == nil && ok
				}() {
					remove = true
					break
				}
			}
			if !remove {
				keep = append(keep, base)
			}
		}
		return keep
	default:
		return normalized
	}
}

func envStr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envInt(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n != 0 {
			return n
		}
	}
	return d
}

func envBool(k string, d bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	return strings.EqualFold(v, "yes") || strings.EqualFold(v, "true")
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func (c Config) String() string {
	b, _ := json.MarshalIndent(c, "", "  ")
	return string(b)
}
