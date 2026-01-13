package main

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type Metrics struct {
	enabled bool
	mu      sync.RWMutex

	connectionsTotal       atomic.Int64
	connectionsFailed      atomic.Int64
	connectionsActive      atomic.Int64
	tunnelsActive          atomic.Int64
	rateLimitHits          atomic.Int64
	authDenied             atomic.Int64
	tunnelDenied           atomic.Int64
	bytesTransferredIn     atomic.Int64
	bytesTransferredOut    atomic.Int64
	handshakeFailures      atomic.Int64
	connectionDurations    []time.Duration
	connectionDurationsMu  sync.Mutex
}

func NewMetrics() *Metrics {
	return &Metrics{
		enabled:             false,
		connectionDurations: make([]time.Duration, 0, 1000),
	}
}

func (m *Metrics) Enable() {
	m.mu.Lock()
	m.enabled = true
	m.mu.Unlock()
}

func (m *Metrics) RecordConnection() {
	if !m.enabled {
		return
	}
	m.connectionsTotal.Add(1)
	m.connectionsActive.Add(1)
}

func (m *Metrics) RecordConnectionClosed() {
	if !m.enabled {
		return
	}
	m.connectionsActive.Add(-1)
}

func (m *Metrics) RecordConnectionFailed() {
	if !m.enabled {
		return
	}
	m.connectionsFailed.Add(1)
}

func (m *Metrics) RecordTunnelOpened() {
	if !m.enabled {
		return
	}
	m.tunnelsActive.Add(1)
}

func (m *Metrics) RecordTunnelClosed() {
	if !m.enabled {
		return
	}
	m.tunnelsActive.Add(-1)
}

func (m *Metrics) RecordRateLimitHit() {
	if !m.enabled {
		return
	}
	m.rateLimitHits.Add(1)
}

func (m *Metrics) RecordAuthDenied() {
	if !m.enabled {
		return
	}
	m.authDenied.Add(1)
}

func (m *Metrics) RecordTunnelDenied() {
	if !m.enabled {
		return
	}
	m.tunnelDenied.Add(1)
}

func (m *Metrics) RecordHandshakeFailure() {
	if !m.enabled {
		return
	}
	m.handshakeFailures.Add(1)
}

func (m *Metrics) RecordBytesIn(n int64) {
	if !m.enabled {
		return
	}
	m.bytesTransferredIn.Add(n)
}

func (m *Metrics) RecordBytesOut(n int64) {
	if !m.enabled {
		return
	}
	m.bytesTransferredOut.Add(n)
}

func (m *Metrics) RecordConnectionDuration(d time.Duration) {
	if !m.enabled {
		return
	}
	m.connectionDurationsMu.Lock()
	if len(m.connectionDurations) < 1000 {
		m.connectionDurations = append(m.connectionDurations, d)
	} else {
		m.connectionDurations = append(m.connectionDurations[1:], d)
	}
	m.connectionDurationsMu.Unlock()
}

func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	fmt.Fprintf(w, "# HELP bastille_connections_total Total number of connection attempts\n")
	fmt.Fprintf(w, "# TYPE bastille_connections_total counter\n")
	fmt.Fprintf(w, "bastille_connections_total %d\n", m.connectionsTotal.Load())

	fmt.Fprintf(w, "# HELP bastille_connections_failed_total Total number of failed connections\n")
	fmt.Fprintf(w, "# TYPE bastille_connections_failed_total counter\n")
	fmt.Fprintf(w, "bastille_connections_failed_total %d\n", m.connectionsFailed.Load())

	fmt.Fprintf(w, "# HELP bastille_connections_active Current number of active connections\n")
	fmt.Fprintf(w, "# TYPE bastille_connections_active gauge\n")
	fmt.Fprintf(w, "bastille_connections_active %d\n", m.connectionsActive.Load())

	fmt.Fprintf(w, "# HELP bastille_tunnels_active Current number of active tunnels\n")
	fmt.Fprintf(w, "# TYPE bastille_tunnels_active gauge\n")
	fmt.Fprintf(w, "bastille_tunnels_active %d\n", m.tunnelsActive.Load())

	fmt.Fprintf(w, "# HELP bastille_rate_limit_hits_total Total number of rate limit hits\n")
	fmt.Fprintf(w, "# TYPE bastille_rate_limit_hits_total counter\n")
	fmt.Fprintf(w, "bastille_rate_limit_hits_total %d\n", m.rateLimitHits.Load())

	fmt.Fprintf(w, "# HELP bastille_auth_denied_total Total number of authentication denials\n")
	fmt.Fprintf(w, "# TYPE bastille_auth_denied_total counter\n")
	fmt.Fprintf(w, "bastille_auth_denied_total %d\n", m.authDenied.Load())

	fmt.Fprintf(w, "# HELP bastille_tunnel_denied_total Total number of tunnel denials\n")
	fmt.Fprintf(w, "# TYPE bastille_tunnel_denied_total counter\n")
	fmt.Fprintf(w, "bastille_tunnel_denied_total %d\n", m.tunnelDenied.Load())

	fmt.Fprintf(w, "# HELP bastille_handshake_failures_total Total number of handshake failures\n")
	fmt.Fprintf(w, "# TYPE bastille_handshake_failures_total counter\n")
	fmt.Fprintf(w, "bastille_handshake_failures_total %d\n", m.handshakeFailures.Load())

	fmt.Fprintf(w, "# HELP bastille_bytes_transferred_in_total Total bytes received\n")
	fmt.Fprintf(w, "# TYPE bastille_bytes_transferred_in_total counter\n")
	fmt.Fprintf(w, "bastille_bytes_transferred_in_total %d\n", m.bytesTransferredIn.Load())

	fmt.Fprintf(w, "# HELP bastille_bytes_transferred_out_total Total bytes sent\n")
	fmt.Fprintf(w, "# TYPE bastille_bytes_transferred_out_total counter\n")
	fmt.Fprintf(w, "bastille_bytes_transferred_out_total %d\n", m.bytesTransferredOut.Load())

	m.connectionDurationsMu.Lock()
	durations := make([]time.Duration, len(m.connectionDurations))
	copy(durations, m.connectionDurations)
	m.connectionDurationsMu.Unlock()

	if len(durations) > 0 {
		var sum, count float64
		for _, d := range durations {
			sum += d.Seconds()
			count++
		}
		avg := sum / count

		fmt.Fprintf(w, "# HELP bastille_connection_duration_seconds Connection duration statistics\n")
		fmt.Fprintf(w, "# TYPE bastille_connection_duration_seconds summary\n")
		fmt.Fprintf(w, "bastille_connection_duration_seconds{quantile=\"0.5\"} %.3f\n", avg)
		fmt.Fprintf(w, "bastille_connection_duration_seconds_sum %.3f\n", sum)
		fmt.Fprintf(w, "bastille_connection_duration_seconds_count %.0f\n", count)
	}
}

func (m *Metrics) Handler() http.Handler {
	return m
}