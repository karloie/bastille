package main

import (
	"errors"
	"net/smtp"
	"os"
	"path/filepath"
	"testing"
)

func TestSendTunnelNotificationDisabled(t *testing.T) {
	cfg := Config{
		SMTPHost: "",
		SMTPMail: "",
	}

	sendTunnelNotification(&cfg, "testuser", "192.0.2.1:12345", "198.51.100.1:22")
}

func TestSendTunnelNotificationMissingPassword(t *testing.T) {
	cfg := Config{
		SMTPHost:     "smtp.example.com",
		SMTPMail:     "test@example.com",
		SMTPPort:     587,
		SMTPUser:     "test@example.com",
		SMTPPassFile: "/nonexistent/smtp_pass",
	}
	sendTunnelNotification(&cfg, "testuser", "192.0.2.1:12345", "198.51.100.1:22")
}

func TestSendTunnelNotificationValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	passFile := filepath.Join(tmpDir, "smtp_pass")
	if err := os.WriteFile(passFile, []byte("testpassword\n"), 0600); err != nil {
		t.Fatalf("failed to write password file: %v", err)
	}
	cfg := Config{
		SMTPHost:     "smtp.example.com",
		SMTPMail:     "test@example.com",
		SMTPPort:     587,
		SMTPUser:     "test@example.com",
		SMTPPassFile: passFile,
	}
	sendTunnelNotification(&cfg, "testuser", "192.0.2.1:12345", "198.51.100.1:22")
}

func TestSendTunnelNotificationMocked(t *testing.T) {
	originalSend := sendMail
	defer func() { sendMail = originalSend; resetSMTPState() }()
	resetSMTPState()

	tmpDir := t.TempDir()
	passFile := filepath.Join(tmpDir, "smtp_pass")
	if err := os.WriteFile(passFile, []byte("secret\n"), 0600); err != nil {
		t.Fatalf("write pass: %v", err)
	}

	calls := 0
	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		calls++
		return nil
	}

	cfg := Config{
		SMTPHost:     "smtp.example.com",
		SMTPMail:     "test@example.com",
		SMTPPort:     587,
		SMTPUser:     "test@example.com",
		SMTPPassFile: passFile,
	}

	sendTunnelNotification(&cfg, "alice", "1.2.3.4:1111", "5.6.7.8:22")
	if calls != 1 {
		t.Fatalf("expected sendMail to be called once, got %d", calls)
	}

	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		calls++
		return errors.New("fail")
	}
	sendTunnelNotification(&cfg, "alice", "1.2.3.4:1111", "5.6.7.8:22")
	if calls != 2 {
		t.Fatalf("expected sendMail to be called twice, got %d", calls)
	}
}
