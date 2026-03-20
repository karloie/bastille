package server

import (
	"context"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/karloie/bastille/pkg/config"
)

const smtpTimeout = 10 * time.Second

var (
	smtpPass     string
	smtpPassOnce sync.Once
	smtpPassErr  error
	sendMail     = smtp.SendMail
)

func resetSmtpState() {
	smtpPass = ""
	smtpPassErr = nil
	smtpPassOnce = sync.Once{}
}

func loadSmtpPassword(cfg *config.Config) (string, error) {
	smtpPassOnce.Do(func() {
		if cfg.SmtpHost == "" || cfg.SmtpMail == "" {
			return
		}
		data, err := os.ReadFile(cfg.SmtpSecret)
		if err != nil {
			smtpPassErr = err
			return
		}
		smtpPass = strings.TrimSpace(string(data))
	})
	return smtpPass, smtpPassErr
}

func sendTunnelNotification(parent context.Context, cfg *config.Config, user, source, target string) {
	if cfg.SmtpHost == "" || cfg.SmtpMail == "" {
		return
	}
	pass, err := loadSmtpPassword(cfg)
	if err != nil {
		config.LogEvent("warn", "", nil, "", "smtp password read failed", nil, err)
		return
	}
	subject := fmt.Sprintf("SSH Jump: %s -> %s", user, target)
	body := fmt.Sprintf("User: %s\nSource: %s\nTarget: %s\nTime: %s\n",
		user, source, target, time.Now().UTC().Format(time.RFC3339))
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		cfg.SmtpMail, cfg.SmtpMail, subject, body)
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, smtpTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.SmtpHost, cfg.SmtpPort)
		auth := smtp.PlainAuth("", cfg.SmtpUser, pass, cfg.SmtpHost)
		done <- sendMail(addr, auth, cfg.SmtpMail, []string{cfg.SmtpMail}, []byte(msg))
	}()
	select {
	case err := <-done:
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				config.LogEvent("warn", "", nil, "", "smtp timeout", nil, err)
			} else {
				config.LogEvent("warn", "", nil, "", "smtp send failed", nil, err)
			}
		}
	case <-ctx.Done():
		config.LogEvent("warn", "", nil, "", "smtp timeout", nil, ctx.Err())
	}
}
