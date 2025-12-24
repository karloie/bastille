//go:build ignore

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type event struct {
	Time    time.Time `json:"Time"`
	Action  string    `json:"Action"`
	Package string    `json:"Package"`
	Test    string    `json:"Test,omitempty"`
	Elapsed float64   `json:"Elapsed,omitempty"`
	Output  string    `json:"Output,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
}

type logBuffer struct {
	test   string
	msgKey string
	line   string
	count  int
}

func run() error {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	pass := 0
	fail := 0
	skip := 0

	pkgs := map[string]struct{}{}
	failed := false
	var buffered *logBuffer

	flushBuffered := func() {
		if buffered != nil && buffered.count > 0 {
			if buffered.count == 1 {
				fmt.Printf("%s\n", buffered.line)
			} else {
				fmt.Printf("%s count=%d\n", buffered.line, buffered.count)
			}
			buffered = nil
		}
	}

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}

		var e event
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}

		if e.Package != "" {
			pkgs[e.Package] = struct{}{}
		}

		switch e.Action {
		case "output":
			txt := strings.TrimSuffix(e.Output, "\n")
			txt = stripHarnessPrefix(txt)
			if txt == "" || isHarnessNoise(txt) || isRoutineLog(txt) {
				continue
			}

			// Check if this is an expected failure that should be suppressed
			if shouldSuppressExpectedFailure(e.Test, txt) {
				continue
			}

			// Build the output line
			var outputLine string
			if e.Test != "" {
				outputLine = fmt.Sprintf("%s [%s] %s", sourceIcon(txt), e.Test, cleanSrc(txt))
			} else {
				outputLine = fmt.Sprintf("%s %s", sourceIcon(txt), cleanSrc(txt))
			}

			// Try to aggregate duplicate logs
			msgKey := makeLogKey(txt)
			if buffered != nil && buffered.test == e.Test && buffered.msgKey == msgKey {
				buffered.count++
			} else {
				flushBuffered()
				buffered = &logBuffer{
					test:   e.Test,
					msgKey: msgKey,
					line:   outputLine,
					count:  1,
				}
			}

		case "pass":
			flushBuffered()
			if e.Test == "" {
				continue
			}
			pass++
			fmt.Printf("%s %s (%s)\n", passIcon(e.Test), label(e.Package, e.Test), fmtElapsed(e.Elapsed))

		case "fail":
			flushBuffered()
			if e.Test == "" {
				failed = true
				fail++
				fmt.Printf("❌ FAIL package %s (%s)\n", shortPkg(e.Package), fmtElapsed(e.Elapsed))
				continue
			}
			failed = true
			fail++
			fmt.Printf("%s FAIL %s (%s)\n", "❌", label(e.Package, e.Test), fmtElapsed(e.Elapsed))

		case "skip":
			flushBuffered()
			if e.Test == "" {
				skip++
				fmt.Printf("⏭️  SKIP package %s\n", shortPkg(e.Package))
				continue
			}
			skip++
			fmt.Printf("⏭️  SKIP %s\n", label(e.Package, e.Test))
		}
	}

	flushBuffered()

	if err := sc.Err(); err != nil {
		return err
	}

	pkgCount := len(pkgs)
	fmt.Printf("\n✅ PASS %d   ❌ FAIL %d   ⏭️  SKIP %d  in %d 📦(s)\n", pass, fail, skip, pkgCount)

	if failed {
		os.Exit(1)
	}
	return nil
}

func passIcon(testName string) string {
	if isIntegrationTest(testName) {
		return "☑️"
	}
	return "✅"
}

func sourceIcon(line string) string {
	if strings.Contains(line, "src=bastille") {
		if strings.Contains(line, "level=ERROR") {
			return "\033[31m亗\033[0m"
		}
		if strings.Contains(line, "level=WARN") {
			return "\033[33m亗\033[0m"
		}
		if strings.Contains(line, "level=INFO") {
			return "\033[32m亗\033[0m"
		}
		return "亗"
	}
	if strings.Contains(line, "src=target") {
		return "🎯"
	}
	return "💻"
}

func cleanSrc(line string) string {
	line = strings.ReplaceAll(line, " src=bastille", "")
	line = strings.ReplaceAll(line, " src=target", "")

	// Remove time= tags (format: time=2025-12-24T14:28:37.762+01:00)
	if idx := strings.Index(line, "time="); idx != -1 {
		end := idx
		for end < len(line) && line[end] != ' ' {
			end++
		}
		line = line[:idx] + line[end:]
	}

	// Remove level= tags (format: level=WARN, level=INFO, etc.)
	if idx := strings.Index(line, "level="); idx != -1 {
		end := idx
		for end < len(line) && line[end] != ' ' {
			end++
		}
		line = line[:idx] + line[end:]
	}

	// Clean up extra spaces
	line = strings.TrimSpace(line)
	for strings.Contains(line, "  ") {
		line = strings.ReplaceAll(line, "  ", " ")
	}

	return line
}

var sessionIDRegex = regexp.MustCompile(`\b[is]=[a-f0-9:\.\-]+`)
var durationRegex = regexp.MustCompile(`\bd=\d+ms\b`)
var targetRegex = regexp.MustCompile(`\bt=[a-f0-9:\.\-]+`)
var userRegex = regexp.MustCompile(`\bu=[a-zA-Z0-9_\-]+`)

func makeLogKey(line string) string {
	// Extract the message type only, ignoring all variable fields
	// This allows aggregation of similar log messages regardless of user, session, target, etc.
	key := sessionIDRegex.ReplaceAllString(line, "")
	key = durationRegex.ReplaceAllString(key, "")
	key = targetRegex.ReplaceAllString(key, "")
	key = userRegex.ReplaceAllString(key, "")
	// Clean up multiple spaces
	for strings.Contains(key, "  ") {
		key = strings.ReplaceAll(key, "  ", " ")
	}
	return strings.TrimSpace(key)
}

func shouldSuppressExpectedFailure(testName, logLine string) bool {
	// Suppress expected SMTP failures in notification tests
	if strings.Contains(testName, "Notification") &&
		(strings.Contains(logLine, "smtp password read failed") ||
			strings.Contains(logLine, "smtp send failed")) {
		return true
	}
	return false
}

func label(pkg, test string) string {
	_ = pkg
	return test
}

func shortPkg(pkg string) string {
	if pkg == "" {
		return ""
	}
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		return pkg[i+1:]
	}
	return pkg
}

func fmtElapsed(sec float64) string {
	if sec <= 0 {
		return "0s"
	}
	d := time.Duration(sec * float64(time.Second))
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func isHarnessNoise(line string) bool {
	if strings.HasPrefix(line, "=== RUN   ") {
		return true
	}
	if strings.HasPrefix(line, "=== PAUSE ") {
		return true
	}
	if strings.HasPrefix(line, "=== CONT  ") {
		return true
	}
	if strings.HasPrefix(line, "--- PASS: ") {
		return true
	}
	if strings.HasPrefix(line, "--- FAIL: ") {
		return true
	}
	if strings.HasPrefix(line, "--- SKIP: ") {
		return true
	}
	if strings.HasPrefix(line, "ok  ") || strings.HasPrefix(line, "FAIL\t") {
		return true
	}
	return false
}

func stripHarnessPrefix(s string) string {
	j := strings.Index(s, ".go:")
	if j <= 0 {
		return s
	}
	n := j + len(".go:")
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	if n < len(s) && s[n] == ':' {
		n++
		for n < len(s) && s[n] == ' ' {
			n++
		}
		return strings.TrimLeft(s[n:], " ")
	}
	return s
}

func isIntegrationTest(name string) bool {
	return strings.HasPrefix(name, "TestPermitOpenAccess") ||
		strings.HasPrefix(name, "TestCertOnlyMode") ||
		strings.HasPrefix(name, "TestTrustedUserCAKeys") ||
		strings.HasPrefix(name, "TestPerSourceRateLimit") ||
		strings.HasPrefix(name, "TestMaxSessionsLimit") ||
		strings.HasPrefix(name, "TestRejectSessionChannel")
}

func isRoutineLog(line string) bool {
	return strings.Contains(line, "level=DEBUG")
}

func init() {
	_ = filepath.Separator
	_ = regexp.MustCompile("")
}
