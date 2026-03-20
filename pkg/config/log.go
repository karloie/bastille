package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func LogEvent(lvl string, cid string, meta ssh.ConnMetadata, dst, msg string, value any, err error) {
	attrs := []any{"src", "bastille"}
	if cid != "" {
		attrs = append(attrs, "i", cid)
	}
	if meta != nil {
		attrs = append(attrs, "u", meta.User(), "s", meta.RemoteAddr().String())
	}
	if dst != "" {
		attrs = append(attrs, "t", dst)
	}
	if v, ok := value.(string); ok && strings.HasPrefix(v, "SHA256:") {
		attrs = append(attrs, "k", v)
	} else if value != nil {
		attrs = append(attrs, "v", value)
	}
	if err != nil {
		attrs = append(attrs, "error", err)
	}
	switch lvl {
	case "debug":
		slog.Debug(msg, attrs...)
	case "warn":
		slog.Warn(msg, attrs...)
	case "err":
		slog.Error(msg, attrs...)
	case "fatal":
		slog.Error(msg, attrs...)
		os.Exit(1)
	default:
		slog.Info(msg, attrs...)
	}
}

func LogEventWithDuration(lvl string, cid string, meta ssh.ConnMetadata, dst, msg string, value any, err error, duration time.Duration) {
	attrs := []any{"src", "bastille"}
	if cid != "" {
		attrs = append(attrs, "i", cid)
	}
	if meta != nil {
		attrs = append(attrs, "u", meta.User(), "s", meta.RemoteAddr().String())
	}
	if dst != "" {
		attrs = append(attrs, "t", dst)
	}
	if duration > 0 {
		attrs = append(attrs, "d", fmt.Sprintf("%.0fms", duration.Seconds()*1000))
	}
	if v, ok := value.(string); ok && strings.HasPrefix(v, "SHA256:") {
		attrs = append(attrs, "k", v)
	} else if value != nil {
		attrs = append(attrs, "v", value)
	}
	if err != nil {
		attrs = append(attrs, "error", err)
	}
	switch lvl {
	case "debug":
		slog.Debug(msg, attrs...)
	case "warn":
		slog.Warn(msg, attrs...)
	case "err":
		slog.Error(msg, attrs...)
	case "fatal":
		slog.Error(msg, attrs...)
		os.Exit(1)
	default:
		slog.Info(msg, attrs...)
	}
}
