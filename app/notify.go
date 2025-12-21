package main

import (
	"context"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"
)

const smtpTimeout = 10 * time.Second

var (
	smtpPass     string
	smtpPassOnce sync.Once
	smtpPassErr  error
	sendMail     = smtp.SendMail
)

func resetSMTPState() {
	smtpPass = ""
	smtpPassErr = nil
	smtpPassOnce = sync.Once{}
}

func loadSMTPPassword(cfg *Config) (string, error) {
	smtpPassOnce.Do(func() {
		if cfg.SMTPHost == "" || cfg.SMTPMail == "" {
			return
		}
		data, err := os.ReadFile(cfg.SMTPPassFile)
		if err != nil {
			smtpPassErr = err
			return
		}
		smtpPass = strings.TrimSpace(string(data))
	})
	return smtpPass, smtpPassErr
}

func sendTunnelNotification(cfg *Config, user, source, target string) {
	if cfg.SMTPHost == "" || cfg.SMTPMail == "" {
		return
	}

	pass, err := loadSMTPPassword(cfg)
	if err != nil {
		logEvent("warn", "", nil, "", "smtp password read failed", nil, err)
		return
	}

	subject := fmt.Sprintf("SSH Jump: %s -> %s", user, target)
	body := fmt.Sprintf("User: %s\nSource: %s\nTarget: %s\nTime: %s\n",
		user, source, target, time.Now().UTC().Format(time.RFC3339))

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		cfg.SMTPMail, cfg.SMTPMail, subject, body)

	ctx, cancel := context.WithTimeout(context.Background(), smtpTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
		auth := smtp.PlainAuth("", cfg.SMTPUser, pass, cfg.SMTPHost)
		done <- sendMail(addr, auth, cfg.SMTPMail, []string{cfg.SMTPMail}, []byte(msg))
	}()

	select {
	case err := <-done:
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				logEvent("warn", "", nil, "", "smtp timeout", nil, err)
			} else {
				logEvent("warn", "", nil, "", "smtp send failed", nil, err)
			}
		}
	case <-ctx.Done():
		logEvent("warn", "", nil, "", "smtp timeout", nil, ctx.Err())
	}
}
