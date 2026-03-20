package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/karloie/bastille/pkg/config"
	"github.com/karloie/bastille/pkg/crypto"
	"github.com/karloie/bastille/pkg/metrics"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
)

const (
	handshakeTimeout = 10 * time.Second
	channelTypeTCP   = "direct-tcpip"
)

type Server struct {
	cfg       config.Config
	rateMu    sync.Mutex
	rate      map[string]*rate.Limiter
	tunnelsMu sync.Mutex
	tunnels   map[string]int
	metrics   *metrics.Metrics
}

func (s *Server) Serve(ctx context.Context, srv *ssh.ServerConfig, ln net.Listener) {
	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = ln.Close()
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
			s.handleConn(ctx, c, srv)
		}(c)
	}
	wg.Wait()
}

func (s *Server) handleConn(ctx context.Context, c net.Conn, srv *ssh.ServerConfig) {
	defer c.Close()
	start := time.Now()
	s.metrics.RecordConnection()
	defer func() {
		s.metrics.RecordConnectionClosed()
		s.metrics.RecordConnectionDuration(time.Since(start))
	}()
	ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	var id [8]byte
	_, _ = rand.Read(id[:])
	cid := hex.EncodeToString(id[:])
	if s.cfg.MaxStartups > 0 {
		s.rateMu.Lock()
		lim := s.rate[ip]
		if lim == nil {
			r := rate.Every(time.Minute / time.Duration(s.cfg.MaxStartups))
			lim = rate.NewLimiter(r, s.cfg.MaxStartups)
			s.rate[ip] = lim
		}
		allow := lim.Allow()
		s.rateMu.Unlock()
		if !allow {
			s.metrics.RecordRateLimitHit()
			config.LogEvent("warn", cid, nil, ip, "rate limited", nil, nil)
			return
		}
	}
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	sshConn, chans, reqs, err := ssh.NewServerConn(c, srv)
	_ = c.SetDeadline(time.Time{})
	if err != nil {
		s.metrics.RecordHandshakeFailure()
		s.metrics.RecordConnectionFailed()
		config.LogEvent("debug", cid, nil, ip, "handshake failed", nil, err)
		return
	}
	config.LogEvent("debug", cid, sshConn, ip, "handshake", nil, nil)
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for {
		select {
		case <-ctx.Done():
			config.LogEvent("debug", cid, sshConn, ip, "connection canceled", nil, nil)
			return
		case ch, ok := <-chans:
			if !ok {
				return
			}
			if ch.ChannelType() != channelTypeTCP {
				_ = ch.Reject(ssh.UnknownChannelType, channelTypeTCP+" only")
				continue
			}
			dst := targetAddress(ch.ExtraData())
			if !isTunnelAllowed(sshConn.Permissions, dst) {
				s.metrics.RecordTunnelDenied()
				config.LogEventWithDuration("err", cid, sshConn, dst, "tunnel denied", nil, nil, time.Since(start))
				_ = ch.Reject(ssh.ConnectionFailed, "denied")
				continue
			}
			u := sshConn.User()
			if !s.acquireTunnelSlot(u) {
				config.LogEventWithDuration("warn", cid, sshConn, dst, "too many tunnels", nil, nil, time.Since(start))
				_ = ch.Reject(ssh.ResourceShortage, "limit")
				continue
			}
			go s.proxy(ctx, cid, ch, dst, sshConn, start)
		}
	}
}

func (s *Server) acquireTunnelSlot(user string) bool {
	if user == "" || s.cfg.MaxSessions <= 0 {
		return false
	}
	s.tunnelsMu.Lock()
	defer s.tunnelsMu.Unlock()
	s.tunnels[user]++
	if s.tunnels[user] > s.cfg.MaxSessions {
		s.tunnels[user]--
		return false
	}
	return true
}

func (s *Server) releaseTunnelSlot(user string) {
	if user == "" {
		return
	}
	s.tunnelsMu.Lock()
	if s.tunnels[user] > 0 {
		s.tunnels[user]--
	}
	s.tunnelsMu.Unlock()
}

func New(cfg config.Config, metrics *metrics.Metrics) *Server {
	return &Server{
		cfg:     cfg,
		rate:    make(map[string]*rate.Limiter),
		tunnels: make(map[string]int),
		metrics: metrics,
	}
}

func targetAddress(payload []byte) string {
	var p struct {
		DstHost string
		DstPort uint32
		SrcIP   string
		SrcPort uint32
	}
	_ = ssh.Unmarshal(payload, &p)
	return fmt.Sprintf("%s:%d", p.DstHost, p.DstPort)
}

func isTunnelAllowed(perms *ssh.Permissions, dst string) bool {
	if perms == nil || perms.Extensions == nil {
		return false
	}
	opts := perms.Extensions[crypto.PermissionKey]
	return crypto.IsPermitAllowed(opts, dst)
}

func (s *Server) proxy(ctx context.Context, cid string, ch ssh.NewChannel, dst string, sshConn *ssh.ServerConn, start time.Time) {
	defer s.releaseTunnelSlot(sshConn.User())
	var d net.Dialer
	d.Timeout = s.cfg.DialTimeout
	dstConn, err := d.DialContext(ctx, "tcp", dst)
	if err != nil {
		_ = ch.Reject(ssh.ConnectionFailed, err.Error())
		config.LogEventWithDuration("warn", cid, sshConn, dst, "dial failed", nil, err, time.Since(start))
		return
	}
	sc, reqs, err := ch.Accept()
	if err != nil {
		_ = dstConn.Close()
		config.LogEventWithDuration("warn", cid, sshConn, dst, "channel accept failed", nil, err, time.Since(start))
		return
	}
	go ssh.DiscardRequests(reqs)
	s.metrics.RecordTunnelOpened()
	config.LogEventWithDuration("info", cid, sshConn, dst, "tunnel opened", nil, nil, time.Since(start))
	go sendTunnelNotification(ctx, &s.cfg, sshConn.User(), sshConn.RemoteAddr().String(), dst)
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(dstConn, sc)
		s.metrics.RecordBytesOut(n)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(sc, dstConn)
		s.metrics.RecordBytesIn(n)
		done <- struct{}{}
	}()
	select {
	case <-ctx.Done():
		_ = dstConn.Close()
		_ = sc.Close()
	case <-done:
		_ = dstConn.Close()
		_ = sc.Close()
	}
	<-done
	s.metrics.RecordTunnelClosed()
	config.LogEventWithDuration("debug", cid, sshConn, dst, "tunnel closed", nil, nil, time.Since(start))
}
