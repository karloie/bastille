package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	cancelLogs   context.CancelFunc
	testMode     string
	dockerAction string
	setupOK      bool
	totalTests   int
	failedTests  int
	isCI         bool
)

// ────────────────────────────────
// Test lifecycle: modes
// ────────────────────────────────
func TestMain(m *testing.M) {
	isCI = os.Getenv("GITHUB_ACTIONS") == "true"

	testMode = os.Getenv("TEST_MODE")
	if testMode == "" {
		if dockerIsRunning() {
			testMode = "attach"
		} else {
			testMode = "full"
		}
	}
	testMode = strings.ToLower(testMode)
	log.Printf("🧩 Test mode: %s\n", strings.ToUpper(testMode))
	switch testMode {
	case "setup":
		if err := setup(); err != nil {
			log.Fatalf("❌ setup failed: %v", err)
		}
		log.Println("✅ SSH test environment prepared.")
		setupOK = true
		return

	case "attach":
		log.Println("🔌 Using existing Docker environment.")
		setupOK = true
		code := m.Run()
		printSummary(code)
		os.Exit(code)

	case "full":
		if err := setup(); err != nil {
			log.Fatalf("❌ setup failed: %v", err)
		}
		setupOK = true
		startDocker()
		code := m.Run()
		stopDocker()
		printSummary(code)
		os.Exit(code)

	default:
		log.Fatalf("Unknown TEST_MODE: %s", testMode)
	}
}

// ────────────────────────────────
// Environment Setup
// ────────────────────────────────

func setup() error {
	fmt.Println("🔧 Running setup() — full regeneration with host keys...")

	keys := "test/clientkeys/id_ed25519"
	home := "test/home"
	cadir := "test/ca"

	// ────────────────────────────────
	// 0. Clean directories
	// ────────────────────────────────
	dirs := []string{
		"test/ca", "test/clientkeys", "test/hostkeys",
		"test/target1/.ssh", "test/target2/.ssh", "test/home",
	}
	for _, d := range dirs {
		if err := os.RemoveAll(d); err != nil {
			return fmt.Errorf("cleanup %s: %w", d, err)
		}
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	// ────────────────────────────────
	// 1. Generate client keys
	// ────────────────────────────────
	users := []string{"lilo", "stitch", "nani", "jumba", "wrong"}
	for _, u := range users {
		keyFile := fmt.Sprintf("%s_%s", keys, u)
		cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyFile, "-C", fmt.Sprintf("%s@localhost", u))
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("ssh-keygen %s: %w", u, err)
		}
	}

	// ────────────────────────────────
	// 2. lilo setup
	// ────────────────────────────────
	lineLilo := `permitopen="172.16.4.12:22",permitopen="172.16.4.13:22" `
	pubLilo := readPub(keys + "_lilo.pub")
	if err := os.WriteFile(filepath.Join(home, "lilo"), []byte(lineLilo+pubLilo+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile("test/target1/.ssh/authorized_keys", []byte(pubLilo+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile("test/target2/.ssh/authorized_keys", []byte(pubLilo+"\n"), 0o600); err != nil {
		return err
	}

	// ────────────────────────────────
	// 3. stitch setup
	// ────────────────────────────────
	lineStitch := `permitopen="172.16.4.13:22" `
	pubStitch := readPub(keys + "_stitch.pub")
	if err := os.WriteFile(filepath.Join(home, "stitch"), []byte(lineStitch+pubStitch+"\n"), 0o644); err != nil {
		return err
	}
	f, err := os.OpenFile("test/target2/.ssh/authorized_keys", os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(pubStitch + "\n"); err != nil {
		return err
	}

	// ────────────────────────────────
	// 4. nani CA and cert
	// ────────────────────────────────
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-C", "Nani Pelekai", "-f", filepath.Join(cadir, "ca_ed25519_nani"), "-q")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh-keygen nani CA: %w", err)
	}
	cmd = exec.Command("ssh-keygen", "-q", "-s", filepath.Join(cadir, "ca_ed25519_nani"),
		"-I", "Nani Pelekai",
		"-n", "nani,zone-databases",
		"-V", "+1d",
		"-z", "1",
		"-O", "source-address=172.16.4.0/24",
		keys+"_nani.pub",
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh-keygen nani cert: %w", err)
	}
	exec.Command("ssh-keygen", "-Lf", "test/clientkeys/id_ed25519_nani-cert.pub").Run()

	// ────────────────────────────────
	// 5. jumba CA and cert
	// ────────────────────────────────
	cmd = exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-C", "CA Jumba Jookiba", "-f", filepath.Join(cadir, "ca_ed25519_jumba"), "-q")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh-keygen jumba CA: %w", err)
	}
	cmd = exec.Command("ssh-keygen", "-q", "-s", filepath.Join(cadir, "ca_ed25519_jumba"),
		"-I", "Jumba Jookiba",
		"-n", "jumba,zone-databases",
		"-V", "+1d",
		"-z", "1",
		"-O", "source-address=172.16.4.0/24",
		keys+"_jumba.pub",
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh-keygen jumba cert: %w", err)
	}
	exec.Command("ssh-keygen", "-Lf", "test/clientkeys/id_ed25519_jumba-cert.pub").Run()

	// ────────────────────────────────
	// 6. Generate host keys
	// ────────────────────────────────
	hostKeysDir := "test/hostkeys"
	hostKeys := []struct {
		name string
		args []string
	}{
		{"ssh_host_ed25519_key", []string{"-t", "ed25519", "-N", "", "-f", filepath.Join(hostKeysDir, "ssh_host_ed25519_key"), "-C", "host-ed25519"}},
		{"ssh_host_rsa_key", []string{"-t", "rsa", "-b", "4096", "-N", "", "-f", filepath.Join(hostKeysDir, "ssh_host_rsa_key"), "-C", "host-rsa"}},
	}
	for _, hk := range hostKeys {
		cmd := exec.Command("ssh-keygen", hk.args...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("ssh-keygen %s: %w", hk.name, err)
		}
	}

	fmt.Println("✅ setup() completed — all dirs rebuilt, client + CA + host keys generated fresh")
	return nil
}

func readPub(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func buildAuthorizedKeys(keysDir string) string {
	var b strings.Builder
	add := func(user string) {
		pub, _ := os.ReadFile(filepath.Join(keysDir, "id_ed25519_"+user+".pub"))
		opts := []string{
			`no-agent-forwarding`, `no-port-forwarding`,
			`no-pty`, `no-X11-forwarding`,
			fmt.Sprintf(`command="echo %s access denied"`, user),
		}
		b.WriteString(fmt.Sprintf("%s %s\n", strings.Join(opts, ","), strings.TrimSpace(string(pub))))
	}
	add("lilo")
	add("stitch")
	add("nani")
	add("jumba")
	return b.String()
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

// ────────────────────────────────
// Docker Compose Lifecycle
// ────────────────────────────────
func dockerIsRunning() bool {
	cmd := exec.Command("docker", "compose", "-f", "test/docker-compose.yml", "ps", "--status", "running", "-q")
	out, _ := cmd.Output()
	return len(bytes.TrimSpace(out)) > 0
}

func startDocker() {
	fmt.Println("🚀 Starting Docker environment...")
	cmd := exec.Command("docker", "compose", "-f", "test/docker-compose.yml",
		"up", "-d", "--build", "--remove-orphans")
	out, err := cmd.CombinedOutput()
	if err != nil {
		panic("failed to start docker compose:\n" + string(out))
	}

	startLogStream()
	fmt.Println("🟢 Docker environment up. Waiting for services to stabilize...")
	time.Sleep(4 * time.Second)
	waitForSSH()
}

func stopDocker() {
	fmt.Println("🛑 Shutting down docker environment...")
	stopLogStream()
	exec.Command("docker", "compose", "-f", "test/docker-compose.yml", "down", "--remove-orphans").Run()
}

// ────────────────────────────────
// Live Log Streaming
// ────────────────────────────────

func startLogStream() {
	ctx, cancel := context.WithCancel(context.Background())
	cancelLogs = cancel
	cmd := exec.CommandContext(ctx,
		"docker", "compose", "-f", "test/docker-compose.yml",
		"logs", "-f", "--no-color")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	go func() {
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️ docker log stream ended: %v\n", err)
		}
	}()
}

func stopLogStream() {
	if cancelLogs != nil {
		cancelLogs()
		fmt.Println("🧹 Stopped Docker log stream.")
	}
}

// ────────────────────────────────
// SSH readiness & helpers
// ────────────────────────────────

func waitForSSH() {
	targets := map[string]string{
		"172.16.4.10": "22222",
		"172.16.4.12": "22",
		"172.16.4.13": "22",
	}
	fmt.Println("⏳ Waiting for SSH ports to become available...")
	for name, port := range targets {
		addr := net.JoinHostPort("127.0.0.1", port)
		for i := 0; i < 20; i++ {
			conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				fmt.Printf("✅ %s port %s is ready\n", name, port)
				break
			}
			time.Sleep(500 * time.Millisecond)
			if i == 19 {
				fmt.Printf("⚠️  %s port %s still not ready\n", name, port)
			}
		}
	}
}

func runSSH(args ...string) (out string, code int) {
	cmd := exec.Command("ssh", append([]string{"-F", "test/ssh.config", "-Tn"}, args...)...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	out = buf.String()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	return
}

func checkSSH(t *testing.T, shouldFail bool, args ...string) {
	t.Helper()
	totalTests++
	out, code := runSSH(args...)
	cmd := "ssh " + strings.Join(args, " ")
	if (code == 0) == shouldFail {
		failedTests++
		t.Errorf("❌ %s\n%s", cmd, out)
	}
}

// ────────────────────────────────
// Smoke Tests
// ────────────────────────────────

func TestSmoke(t *testing.T) {
	cases := []struct {
		name string
		fail bool
		args []string
	}{
		{"fail lilo direct login", true, []string{"lilo@bastille-lilo", "pwd"}},
		{"target1 via lilo", false, []string{"root@target1", "-J", "lilo@bastille-lilo", "pwd"}},
		{"target2 via lilo", false, []string{"root@target2", "-J", "lilo@bastille-lilo", "pwd"}},
		{"target2 via stitch", false, []string{"root@target2", "-J", "stitch@bastille-stitch", "pwd"}},
		{"wrong key", true, []string{"root@target1", "-J", "lilo@bastille-wrong", "pwd"}},
		{"unauthorized user", true, []string{"root@target1", "-J", "stitch@bastille-stitch", "pwd"}},
		{"cert user nani ok", false, []string{"root@target1", "-J", "nani@bastille-nani", "pwd"}},
		{"cert user jumba denied", true, []string{"root@target1", "-J", "jumba@bastille-jumba", "pwd"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			checkSSH(t, tc.fail, tc.args...)
		})
	}
}

// ────────────────────────────────
// Access Tests
// ────────────────────────────────

func TestAccess(t *testing.T) {
	cases := []struct {
		name string
		fail bool
		args []string
	}{
		// allowed
		{"target1 via lilo", false, []string{"root@target1", "-J", "lilo@bastille-lilo", "pwd"}},
		{"target2 via lilo", false, []string{"root@target2", "-J", "lilo@bastille-lilo", "pwd"}},
		{"target2 via stitch", false, []string{"root@target2", "-J", "stitch@bastille-stitch", "pwd"}},
		// denied
		{"deny stitch->target1", true, []string{"root@target1", "-J", "stitch@bastille-stitch", "pwd"}},
		{"deny lilo-pass", true, []string{"root@target1", "-J", "lilo@bastille-pass", "pwd"}},
		{"deny root direct", true, []string{"root@target1", "-J", "root@bastille-lilo", "pwd"}},
		{"deny lilo@stitch", true, []string{"root@target1", "-J", "lilo@bastille-stitch", "pwd"}},
		{"deny wrong key t1", true, []string{"root@target1", "-J", "lilo@bastille-wrong", "pwd"}},
		{"deny wrong key t2", true, []string{"root@target2", "-J", "lilo@bastille-wrong", "pwd"}},
		{"deny lilo direct", true, []string{"lilo@bastille-lilo", "pwd"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			checkSSH(t, tc.fail, tc.args...)
		})
	}
}

// ────────────────────────────────
// Algorithm Hardening Tests
// ────────────────────────────────

func TestAlgorithms(t *testing.T) {
	cases := []struct {
		name string
		fail bool
		args []string
	}{
		{"bad cipher", true, []string{"root@target1", "-J", "lilo@bastille-bad-cipher", "pwd"}},
		{"bad kex", true, []string{"root@target1", "-J", "lilo@bastille-bad-kex", "pwd"}},
		{"bad mac", true, []string{"root@target1", "-J", "lilo@bastille-bad-mac", "pwd"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			checkSSH(t, tc.fail, tc.args...)
		})
	}
}

// ────────────────────────────────
// Summary report
// ────────────────────────────────
func printSummary(code int) {
	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("🏁 Test Summary")
	fmt.Printf("Mode: %s\n", strings.ToUpper(testMode))
	if dockerAction == "" {
		dockerAction = "reused (attach)"
	}
	fmt.Printf("Docker: %s\n", dockerAction)
	fmt.Printf("SSH Setup: %v\n", map[bool]string{true: "OK", false: "Skipped"}[setupOK])
	fmt.Printf("Tests Passed: %d / %d\n", totalTests-failedTests, totalTests)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if isCI {
		if failedTests > 0 {
			fmt.Printf("::error title=Test Summary::❌ %d/%d tests failed in %s mode (Docker: %s)\n",
				failedTests, totalTests, strings.ToUpper(testMode), dockerAction)
		} else {
			fmt.Printf("::notice title=Test Summary::✅ All %d tests passed in %s mode (Docker: %s)\n",
				totalTests, strings.ToUpper(testMode), dockerAction)
		}
	}
}
