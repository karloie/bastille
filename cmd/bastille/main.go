package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/karloie/bastille/pkg/config"
	"github.com/karloie/bastille/pkg/crypto"
	"github.com/karloie/bastille/pkg/metrics"
	"github.com/karloie/bastille/pkg/server"
)

var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = ""
)

func main() {
	showVersion := flag.Bool("version", false, "Show version information")
	showHelp := flag.Bool("help", false, "Show help")
	flag.Parse()

	if *showHelp {
		fmt.Fprintf(os.Stderr, "Bastille - SSH jump server with hardened cryptographic defaults\n")
		fmt.Fprintf(os.Stderr, "Version: %s (commit: %s", Version, GitCommit)
		if BuildTime != "" {
			fmt.Fprintf(os.Stderr, ", built: %s", BuildTime)
		}
		fmt.Fprintf(os.Stderr, ")\n\n")
		fmt.Fprintf(os.Stderr, "Usage: bastille [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nConfiguration is done via environment variables. See README.md for details.\n")
		os.Exit(0)
	}

	if *showVersion {
		fmt.Println(Version)
		os.Exit(0)
	}

	cfg := config.LoadConfig()
	level := slog.LevelInfo
	if v, ok := map[string]slog.Level{
		"DEBUG":   slog.LevelDebug,
		"VERBOSE": slog.LevelDebug - 1,
		"INFO":    slog.LevelInfo,
		"WARN":    slog.LevelWarn,
		"ERROR":   slog.LevelError,
	}[cfg.LogLevel]; ok {
		level = v
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
	slog.Info("Bastille started", "src", "bastille", "version", Version, "commit", GitCommit, "buildTime", BuildTime)

	metrics := metrics.New()
	if cfg.MetricsAddress != "" {
		metrics.Enable()
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", metrics.Handler())
			mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok\n"))
			})
			slog.Info("Metrics server starting", "src", "bastille", "addr", cfg.MetricsAddress)
			if err := http.ListenAndServe(cfg.MetricsAddress, mux); err != nil {
				slog.Error("metrics server failed", "src", "bastille", "error", err)
			}
		}()
	}

	certOnly := cfg.AuthMode == "certs"
	srv := crypto.NewSSHServerConfig(&cfg, certOnly, metrics)
	if srv == nil {
		slog.Error("no host keys loaded; refusing to start")
		os.Exit(1)
	}
	bind := cfg.Address
	if bind == "" {
		bind = "0.0.0.0"
	}
	addr := net.JoinHostPort(bind, strconv.Itoa(cfg.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("listen failed", "src", "bastille", "error", err)
		os.Exit(1)
	}
	slog.Info(
		"Bastille listening",
		"src", "bastille",
		"addr", ln.Addr().String(),
		"mode", cfg.AuthMode,
		"strict", cfg.StrictMode,
		"ciphers", len(cfg.Ciphers),
		"kexs", len(cfg.KEXs),
		"macs", len(cfg.MACs),
	)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s := server.New(cfg, metrics)
	s.Serve(ctx, srv, ln)
}
