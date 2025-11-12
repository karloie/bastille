package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Config holds all runtime settings for Bastille
type Config struct {
	Listen       string
	AuthBase     string
	AuthKeys     []string
	AuthMode     string
	CertBase     string
	CertKeys     []string
	HostBase     string
	HostKeys     []string
	MaxTunnels   int
	RateLimit    int
	DialTO       time.Duration
	Debug        bool
	Ciphers      []string
	KeyExchanges []string
	MACs         []string
}

// LoadConfig builds configuration from environment variables or defaults.
func LoadConfig() Config {
	algos := getSupportedAlgos()

	return Config{
		Listen:       envStr("LISTEN", ":22222"),
		AuthBase:     envStr("AUTHBASE", "test/home"),
		AuthKeys:     splitList(envStr("AUTHKEYS", "{user},.ssh/authorized_keys")),
		AuthMode:     envStr("AUTHMODE", "optional"),
		CertBase:     envStr("CERTBASE", "test/ca"),
		CertKeys:     splitList(envStr("CERTKEYS", "ca_ed25519_nani.pub")),
		HostBase:     envStr("HOSTBASE", "test/hostkeys"),
		HostKeys:     splitList(envStr("HOSTKEYS", "ssh_host_ed25519_key,ssh_host_rsa_key")),
		MaxTunnels:   envInt("MAX_TUNNELS", 5),
		RateLimit:    envInt("RATE", 10),
		DialTO:       5 * time.Second,
		Debug:        strings.EqualFold(envStr("DEBUG", "true"), "true"),
		Ciphers:      evalAlgorithms("CIPHERS", algos.Ciphers),
		KeyExchanges: evalAlgorithms("KEXALGORITHMS", algos.KeyExchanges),
		MACs:         evalAlgorithms("MACS", algos.MACs),
	}
}

// getSupportedAlgos wraps ssh.SupportedAlgorithms() for easier testing
func getSupportedAlgos() (a struct {
	Ciphers, KeyExchanges, MACs []string
}) {
	supported := ssh.SupportedAlgorithms()
	a.Ciphers = supported.Ciphers
	a.KeyExchanges = supported.KeyExchanges
	a.MACs = supported.MACs
	return
}

// evalAlgorithms parses environment overrides for SSH crypto algorithms.
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

// ---------- Helpers ----------

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
