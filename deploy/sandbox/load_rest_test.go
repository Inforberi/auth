package sandbox_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLoadRestAcceptance(t *testing.T) {
	if os.Getenv("AUTH_SANDBOX_LOAD_REST") != "1" {
		t.Skip("explicit repeated runtime diagnostics; run task sandbox:load:rest")
	}
	api, _ := sandboxClient(t, false)
	transport := api.Transport.(*http.Transport)
	transport.MaxConnsPerHost, transport.MaxIdleConnsPerHost = 16, 16
	assertKeyIDs(t, api, "sandbox-1")
	dir, err := os.MkdirTemp(sandboxDirectory(t), "load-rest-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		redeploySandboxAPI(t, api, "")
		if err := os.RemoveAll(dir); err != nil {
			t.Error("cannot remove generated runtime diagnostic override")
		}
	})
	override := filepath.Join(dir, "compose.json")
	writeJSON(t, override, map[string]any{"services": map[string]any{"api": map[string]any{
		"environment": map[string]string{"GODEBUG": "gctrace=1,schedtrace=15000,scheddetail=1"},
	}}})
	redeploySandboxAPI(t, api, override)
	identity := runtimeIdentity(t)
	admin, user := adminLogin(t), userLogin(t)
	secret, err := os.ReadFile(filepath.Join(sandboxDirectory(t), "jwt/consumer-secret"))
	if err != nil || len(secret) != 43 {
		t.Fatal("missing synthetic introspection credential")
	}
	input := loadInputs{cookie: loadCookie(t, user), adminCookie: loadCookie(t, admin), basic: "Basic " + base64.StdEncoding.EncodeToString(append([]byte("sandbox-consumer:"), secret...))}
	runLoadPhase(t, api, user, input, "warmup", 10, 15*time.Second)
	checkLoadLoginBurst(t, api)
	waitSecurityUntil(t, time.Now().Add(75*time.Second))
	baseRSS, baseScheduler := sampleRuntime(t, identity, "warmed-rest")
	for cycle := 1; cycle <= 2; cycle++ {
		t.Logf("cycle=%d load90s/rest75s; bounded repeated observation, not production soak", cycle)
		checkLoadLoginBurst(t, api)
		runLoadPhase(t, api, user, input, "load-rest", 50, 90*time.Second)
		sampleRuntime(t, identity, "load-end")
		waitSecurityUntil(t, time.Now().Add(75*time.Second))
		rss, scheduler := sampleRuntime(t, identity, "rest-end")
		if rss > baseRSS+64*1024 || rss > 256*1024 || scheduler.Active > baseScheduler.Active+16 {
			t.Fatal("rest observations exceeded the predeclared local RSS/goroutine envelope; investigate before continuing")
		}
		request(t, api, "GET", "/health/ready", nil, nil, 200)
	}
	request(t, user, "GET", "/api/v1/auth/me", nil, nil, 200)
	request(t, admin, "GET", "/api/v1/auth/me", nil, nil, 200)
	assertKeyIDs(t, api, "sandbox-1")
	captureLoadGC(t)
}

func runtimeIdentity(t *testing.T) string {
	t.Helper()
	container := sandboxContainer(t, "api")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	data, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.Id}} {{.State.Running}} {{.RestartCount}}", container).Output()
	identity := strings.TrimSpace(string(data))
	if err != nil || !strings.HasSuffix(identity, " true 0") {
		t.Fatal("sandbox process is unavailable or restarted")
	}
	return identity
}

func sampleRuntime(t *testing.T, identity, phase string) (int, schedulerDiagnostics) {
	t.Helper()
	if runtimeIdentity(t) != identity {
		t.Fatal("refusing runtime comparison across different sandbox processes")
	}
	container := strings.Fields(identity)[0]
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	data, err := exec.CommandContext(ctx, "docker", "top", container, "-eo", "pid,rss").Output()
	fields := strings.Fields(string(data))
	if err != nil || len(fields) != 4 || fields[0] != "PID" || fields[1] != "RSS" {
		t.Fatal("expected one sandbox API process with readable RSS")
	}
	rss, err := strconv.Atoi(fields[3])
	if err != nil || rss <= 0 {
		t.Fatal("invalid API process RSS")
	}
	cmd := exec.CommandContext(ctx, "docker", "logs", container)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal("cannot read runtime diagnostics")
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal("cannot start runtime diagnostics")
	}
	scheduler, readErr := readSchedulerDiagnostics(pipe)
	if readErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if readErr != nil || waitErr != nil {
		t.Fatal("unavailable or bounded runtime diagnostics; raw application logs omitted")
	}
	if runtimeIdentity(t) != identity {
		t.Fatal("sandbox process changed during runtime observation")
	}
	t.Logf("phase=%s RSSKiB=%d schedulerCompleted=%d lastUptimeMS=%d activeDescriptors=%d maxActiveDescriptors=%d; includes runtime G, excludes dead/idle, not runtime.NumGoroutine", phase, rss, scheduler.Snapshots, scheduler.UptimeMS, scheduler.Active, scheduler.MaxActive)
	return rss, scheduler
}
