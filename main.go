package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// ---------------- main ----------------

var (
	cfg       = Config{}
	rateMu    sync.Mutex
	rateCnt   = map[string]int{}
	rateNext  = time.Now().Add(time.Minute)
	rxPermit  = regexp.MustCompile(`permitopen="?([^"]+)"?`)
	tunnelsMu sync.Mutex
	tunnels   = map[string]int{}
)

func main() {
	cfg = LoadConfig()

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	if cfg.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	srv := &ssh.ServerConfig{Config: ssh.Config{
		Ciphers:      cfg.Ciphers,
		KeyExchanges: cfg.KeyExchanges,
		MACs:         cfg.MACs,
	}}

	loadHostkeys(cfg.HostBase, cfg.HostKeys, srv)
	caPub := loadCertkeys(cfg.CertBase, cfg.CertKeys)
	certChecker := certChecker(caPub, cfg.AuthKeys)
	srv.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if cfg.AuthMode == "certs" {
			if _, ok := key.(*ssh.Certificate); !ok {
				return nil, errors.New("cert required")
			}
		}
		perms, err := certChecker.Authenticate(meta, key)
		if err != nil {
			logEvent("warn", "", meta, "", "auth denied", keyHash(key), err)
			return nil, err
		}
		logEvent("debug", "", meta, "", "auth allowed", keyHash(key), nil)
		return perms, nil
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatal().Err(err).Msg("listen failed")
	}
	log.Info().Msgf("Bastille listening: %s", cfg.String())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serve(ctx, srv, ln)
}

// ---------------- serve ----------------

func serve(ctx context.Context, srv *ssh.ServerConfig, ln net.Listener) {
	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = ln.Close() // unblock Accept on shutdown
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			handleConn(ctx, c, srv)
		}(c)
	}
	wg.Wait()
}

// ---------------- handle connection ----------------

func handleConn(ctx context.Context, c net.Conn, srv *ssh.ServerConfig) {
	defer c.Close()

	ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	var id [8]byte
	_, _ = rand.Read(id[:])
	cid := hex.EncodeToString(id[:])

	rateMu.Lock()
	if time.Now().After(rateNext) {
		rateCnt = map[string]int{}
		rateNext = time.Now().Add(time.Minute)
	}
	rateCnt[ip]++
	block := rateCnt[ip] > cfg.RateLimit
	rateMu.Unlock()
	if block {
		logEvent("debug", cid, nil, ip, "rate limited", nil, nil)
		if !strings.EqualFold(os.Getenv("TESTING"), "yes") {
			return
		}
	}

	c.SetDeadline(time.Now().Add(10 * time.Second))
	s, chans, reqs, err := ssh.NewServerConn(c, srv)
	c.SetDeadline(time.Time{})
	if err != nil {
		logEvent("debug", cid, nil, ip, "handshake failed", nil, err)
		return
	}
	logEvent("debug", cid, s, ip, "handshake", nil, nil)
	defer s.Close()
	go ssh.DiscardRequests(reqs)

	for {
		select {
		case <-ctx.Done():
			logEvent("debug", cid, s, ip, "connection canceled", nil, nil)
			return
		case ch, ok := <-chans:
			if !ok {
				return
			}
			if ch.ChannelType() != "direct-tcpip" {
				_ = ch.Reject(ssh.UnknownChannelType, "direct-tcpip only")
				continue
			}
			var p struct {
				DstHost string
				DstPort uint32
				SrcIP   string
				SrcPort uint32
			}
			_ = ssh.Unmarshal(ch.ExtraData(), &p)
			dst := fmt.Sprintf("%s:%d", p.DstHost, p.DstPort)

			if opts := s.Permissions.Extensions["opts"]; opts != "" {
				okp := false
				for _, o := range strings.Split(opts, ",") {
					if m := rxPermit.FindStringSubmatch(o); len(m) > 1 && m[1] == dst {
						okp = true
						break
					}
				}
				if !okp {
					logEvent("warn", cid, s, dst, "tunnel denied", nil, nil)
					_ = ch.Reject(ssh.ConnectionFailed, "denied")
					continue
				}
			}

			tunnelsMu.Lock()
			tunnels[s.User()]++
			if tunnels[s.User()] > cfg.MaxTunnels {
				tunnels[s.User()]--
				tunnelsMu.Unlock()
				logEvent("warn", cid, s, dst, "too many tunnels", nil, nil)
				_ = ch.Reject(ssh.ResourceShortage, "limit")
				continue
			}
			tunnelsMu.Unlock()

			go proxy(ctx, cid, ch, dst, s)
		}
	}
}

// ---------------- proxy ----------------

func proxy(ctx context.Context, cid string, ch ssh.NewChannel, dst string, s *ssh.ServerConn) {
	defer func() {
		tunnelsMu.Lock()
		if tunnels[s.User()] > 0 {
			tunnels[s.User()]--
		}
		tunnelsMu.Unlock()
	}()

	dstConn, err := net.DialTimeout("tcp", dst, cfg.DialTO)
	if err != nil {
		_ = ch.Reject(ssh.ConnectionFailed, err.Error())
		logEvent("warn", cid, s, dst, "dial failed", nil, err)
		return
	}
	sc, reqs, _ := ch.Accept()
	go ssh.DiscardRequests(reqs)
	logEvent("info", cid, s, dst, "tunnel opened", nil, nil)

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(dstConn, sc); done <- struct{}{} }()
	go func() { _, _ = io.Copy(sc, dstConn); done <- struct{}{} }()

	select {
	case <-ctx.Done():
		_ = dstConn.Close()
		_ = sc.Close()
	case <-done:
		_ = dstConn.Close()
		_ = sc.Close()
	}
	<-done
	logEvent("debug", cid, s, dst, "tunnel closed", nil, nil)
}

// ---------------- auth ----------------

func certChecker(caPub []ssh.PublicKey, authFiles []string) *ssh.CertChecker {
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
			user := regexp.MustCompile(`[^a-zA-Z0-9._-]`).ReplaceAllString(conn.User(), "")
			for _, tmpl := range authFiles {
				path := filepath.Join(cfg.AuthBase, strings.ReplaceAll(tmpl, "{user}", user))
				if perm, ok := evalAuthKeys(path, pubKey); ok {
					return perm, nil
				}
			}
			return nil, errors.New("no key")
		},
	}
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

func evalAuthKeys(path string, key ssh.PublicKey) (*ssh.Permissions, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		pub, _, opts, _, err := ssh.ParseAuthorizedKey(sc.Bytes())
		if err == nil && keysEqual(pub, key) {
			return &ssh.Permissions{Extensions: map[string]string{"opts": strings.Join(opts, ",")}}, true
		}
	}
	return nil, false
}

// ---------------- utils ----------------

func loadHostkeys(base string, hostKeys []string, srvCfg *ssh.ServerConfig) {
	for _, hk := range hostKeys {
		path := filepath.Join(base, hk)
		b, err := os.ReadFile(path)
		if err != nil {
			logEvent("warn", "", nil, path, "Host key read failed", nil, err)
			continue
		}
		s, err := ssh.ParsePrivateKey(b)
		if err != nil {
			logEvent("warn", "", nil, path, "Host key parse failed", nil, err)
			continue
		}
		srvCfg.AddHostKey(s)
		logEvent("info", "", nil, path, "Host key loaded", nil, err)
	}
}

func loadCertkeys(base string, paths []string) []ssh.PublicKey {
	out := make([]ssh.PublicKey, 0, len(paths))
	for _, p := range paths {
		path := filepath.Join(base, p)
		b, err := os.ReadFile(path)
		if err != nil {
			logEvent("warn", "", nil, path, "Cert key read failed", nil, err)
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			logEvent("warn", "", nil, path, "Cert key parse failed", nil, err)
			continue
		}
		out = append(out, pub)
		logEvent("info", "", nil, path, "Cert key loaded", nil, err)
	}
	return out
}

func keyHash(k ssh.PublicKey) string {
	if k == nil {
		return ""
	}
	h := sha256.Sum256(k.Marshal())
	fp := base64.RawStdEncoding.EncodeToString(h[:])
	if len(fp) > 16 {
		fp = fp[:16]
	}
	return fmt.Sprintf("%s:%s", k.Type(), fp)
}

func logEvent(lvl string, cid string, meta ssh.ConnMetadata, dst, msg string, value any, err error) {
	lg := log.With()
	if cid != "" {
		lg = lg.Str("i", cid)
	}
	if meta != nil {
		lg = lg.Str("u", meta.User()).Str("s", meta.RemoteAddr().String())
	}
	if dst != "" {
		lg = lg.Str("t", dst)
	}
	if v, ok := value.(string); ok && strings.HasPrefix(v, "SHA256:") {
		lg = lg.Str("k", v)
	} else if value != nil {
		lg = lg.Interface("v", value)
	}
	e := lg.Logger()
	switch lvl {
	case "debug":
		e.Debug().Err(err).Msg(msg)
	case "warn":
		e.Warn().Err(err).Msg(msg)
	case "err":
		e.Error().Err(err).Msg(msg)
	case "fatal":
		e.Fatal().Err(err).Msg(msg)
	default:
		e.Info().Msg(msg)
	}
}
