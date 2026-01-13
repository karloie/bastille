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

type Config struct {
	Address string
	Port    int

	AuthKeys []string
	CertKeys []string
	HostKeys []string

	Ciphers []string
	KEXs    []string
	MACs    []string
	RsaMin  int

	AuthMode    string
	DialTimeout time.Duration
	LogLevel    string
	MaxSessions int
	MaxStartups int
	StrictMode  bool
	Testing     bool

	MetricsAddress string

	SmtpHost   string
	SmtpMail   string
	SmtpSecret string
	SmtpPort   int
	SmtpUser   string
}

const (
	EnvListenAddress     = "ListenAddress"
	EnvListenPort        = "Port"
	EnvListenPortDefault = 22222
	EnvLogLevel          = "LogLevel"

	EnvAuthMode = "AuthMode"

	EnvAuthKeys = "AuthorizedKeysFile"
	EnvCertKeys = "TrustedUserCAKeys"
	EnvHostKeys = "HostKey"

	EnvCiphers = "Ciphers"
	EnvKEXs    = "KexAlgorithms"
	EnvMACs    = "MACs"
	EnvRSAMin  = "RequiredRSASize"

	EnvMaxSessions = "MaxSessions"
	EnvMaxStartups = "PerSourceMaxStartups"
	EnvStrictMode  = "StrictModes"

	EnvMetricsAddress = "MetricsAddress"

	EnvSmtpHost   = "SmtpHost"
	EnvSmtpMail   = "SmtpMail"
	EnvSmtpPort   = "SmtpPort"
	EnvSmtpSecret = "SmtpSecret"
	EnvSmtpUser   = "SmtpUser"
	EnvTesting    = "Testing"

	maxPort = 65535
)

func LoadConfig() Config {
	algos := supportedAlgos()
	hardened := hardenedAlgos()
	cfg := Config{
		Address: strings.TrimSpace(envStr(EnvListenAddress, "")),
		Port:    envInt(EnvListenPort, EnvListenPortDefault),

		AuthKeys: splitList(envStr(EnvAuthKeys, "/home/{user}/.ssh/authorized_keys,/home/{user}")),
		CertKeys: splitList(envStr(EnvCertKeys, "/home/{user}/.ssh/ca.pub,/ca")),
		HostKeys: splitList(envStr(EnvHostKeys, "/hostkeys")),

		Ciphers: supported(parseAlgorithmList(EnvCiphers, hardened.Ciphers), algos.Ciphers),
		KEXs:    supported(parseAlgorithmList(EnvKEXs, hardened.KeyExchanges), algos.KeyExchanges),
		MACs:    supported(parseAlgorithmList(EnvMACs, hardened.MACs), algos.MACs),
		RsaMin:  envInt(EnvRSAMin, 3072),

		AuthMode:    envStr(EnvAuthMode, "optional"),
		DialTimeout: 5 * time.Second,
		LogLevel:    strings.ToUpper(envStr(EnvLogLevel, "INFO")),
		MaxSessions: envInt(EnvMaxSessions, 5),
		MaxStartups: envInt(EnvMaxStartups, 10),
		StrictMode:  envBool(EnvStrictMode, false),

		MetricsAddress: strings.TrimSpace(envStr(EnvMetricsAddress, "")),
		Testing:     envBool(EnvTesting, false),

		SmtpHost:   envStr(EnvSmtpHost, ""),
		SmtpMail:   envStr(EnvSmtpMail, ""),
		SmtpPort:   envInt(EnvSmtpPort, 587),
		SmtpUser:   envStr(EnvSmtpUser, ""),
		SmtpSecret: envStr(EnvSmtpSecret, "/run/secrets/smtp_pass"),
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

func (c Config) Validate() error {
	if c.Port <= 0 || c.Port > maxPort {
		return fmt.Errorf("Port must be 1-%d, got %d", maxPort, c.Port)
	}
	if c.MaxSessions <= 0 {
		return fmt.Errorf("MaxSessions must be > 0, got %d", c.MaxSessions)
	}
	if c.MaxStartups <= 0 {
		return fmt.Errorf("MaxStartups must be > 0, got %d", c.MaxStartups)
	}
	if c.RsaMin != 0 && c.RsaMin < 1024 {
		return fmt.Errorf("MinRsaSize must be 0 or >= 1024, got %d", c.RsaMin)
	}
	if c.SmtpPort <= 0 || c.SmtpPort > maxPort {
		return fmt.Errorf("SmtpPort must be 1-%d, got %d", maxPort, c.SmtpPort)
	}
	validLevels := []string{"DEBUG", "INFO", "VERBOSE", "WARN", "ERROR"}
	if !slices.Contains(validLevels, c.LogLevel) {
		return fmt.Errorf("LogLevel must be one of %v, got %q", validLevels, c.LogLevel)
	}
	if c.SmtpHost != "" && c.SmtpMail != "" {
		if _, err := os.Stat(c.SmtpSecret); err != nil && !c.Testing {
			return fmt.Errorf("Smtp enabled but password file not found: %s", c.SmtpSecret)
		}
	}
	if len(c.Ciphers) == 0 {
		return fmt.Errorf("no supported ciphers after filtering")
	}
	if len(c.KEXs) == 0 {
		return fmt.Errorf("no supported key exchange algorithms after filtering")
	}
	if len(c.MACs) == 0 {
		return fmt.Errorf("no supported MAC algorithms after filtering")
	}

	fixed, patterns := allowedBases(c.AuthKeys)
	if len(fixed) == 0 && len(patterns) == 0 {
		if c.StrictMode {
			return fmt.Errorf("StrictMode enabled but no allowed AuthorizedKeysFile bases could be derived; check AuthorizedKeysFile")
		}
		logEvent("debug", "", nil, "", "no allowed AuthorizedKeysFile bases derived; StrictMode disabled", nil, nil)
	}

	return nil
}

func supportedAlgos() (a struct {
	Ciphers, KeyExchanges, MACs []string
}) {
	supported := ssh.SupportedAlgorithms()
	a.Ciphers = supported.Ciphers
	a.KeyExchanges = supported.KeyExchanges
	a.MACs = supported.MACs
	return
}

func hardenedAlgos() (a struct {
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

func supported(in, supported []string) []string {
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

func parseAlgorithmList(env string, defaults []string) []string {
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
