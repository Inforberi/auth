package sandbox_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestLoadAcceptance(t *testing.T) {
	if os.Getenv("AUTH_SANDBOX_LOAD") != "1" {
		t.Skip("explicit bounded HTTPS baseline; run task sandbox:load")
	}
	api, _ := sandboxClient(t, false)
	transport := api.Transport.(*http.Transport)
	transport.MaxConnsPerHost, transport.MaxIdleConnsPerHost = 16, 16
	assertKeyIDs(t, api, "sandbox-1")
	dir, err := os.MkdirTemp(sandboxDirectory(t), "load-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		redeploySandboxAPI(t, api, "")
		if err := os.RemoveAll(dir); err != nil {
			t.Error("cannot remove generated load override")
		}
	})
	override := filepath.Join(dir, "compose.json")
	writeJSON(t, override, map[string]any{"services": map[string]any{"api": map[string]any{
		"environment": map[string]string{"GODEBUG": "gctrace=1"},
	}}})
	redeploySandboxAPI(t, api, override)
	admin, user := adminLogin(t), userLogin(t)
	secret, err := os.ReadFile(filepath.Join(sandboxDirectory(t), "jwt/consumer-secret"))
	if err != nil || len(secret) != 43 {
		t.Fatal("missing synthetic introspection credential")
	}
	input := loadInputs{cookie: loadCookie(t, user), adminCookie: loadCookie(t, admin), basic: "Basic " + base64.StdEncoding.EncodeToString(append([]byte("sandbox-consumer:"), secret...))}
	runLoadPhase(t, api, user, input, "warmup", 10, 15*time.Second)
	for _, rate := range []int{10, 25, 50} {
		t.Logf("starting bounded mixed HTTP phase: targetRPS=%d", rate)
		runLoadPhase(t, api, user, input, "step", rate, 30*time.Second)
	}
	t.Log("starting 90s stable phase at 50RPS; not a long-duration soak")
	runLoadPhase(t, api, user, input, "stable", 50, 90*time.Second)
	checkLoadLoginBurst(t, api)
	t.Log("load stopped; observing 45s rest without forced GC")
	waitSecurityUntil(t, time.Now().Add(45*time.Second))
	request(t, api, "GET", "/health/ready", nil, nil, 200)
	captureLoadGC(t)
}

func checkLoadLoginBurst(t *testing.T, api *http.Client) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": "ivan@sandbox.example", "password": "Sandbox-Ivan-2026!"})
	call := loadCall{name: "login", method: "POST", path: "/api/v1/auth/login/email", body: string(body), allowBusy: true}
	results := make(chan loadResult, 8)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			<-start
			results <- executeLoad(t.Context(), api, call)
		})
	}
	close(start)
	workers.Wait()
	close(results)
	t.Log("separate 8-login burst: 503 is expected bounded hash admission, not successful throughput")
	reportLoadResults(t, results, false)
}
