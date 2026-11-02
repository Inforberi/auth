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

	loadtest "github.com/Inforberi/financial-intelligence/sandbox/internal/loadtest"
	testsupport "github.com/Inforberi/financial-intelligence/sandbox/internal/testsupport"
)

func TestLoadAcceptance(t *testing.T) {
	if os.Getenv("AUTH_SANDBOX_LOAD") != "1" {
		t.Skip("explicit bounded HTTPS baseline; run task sandbox:load")
	}
	api, _ := testsupport.SandboxClient(t, false)
	transport := api.Transport.(*http.Transport)
	transport.MaxConnsPerHost, transport.MaxIdleConnsPerHost = 16, 16
	testsupport.AssertKeyIDs(t, api, "sandbox-1")
	dir, err := os.MkdirTemp(testsupport.SandboxDirectory(t), "load-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		testsupport.RedeploySandboxAPI(t, api, "")
		if err := os.RemoveAll(dir); err != nil {
			t.Error("cannot remove generated load override")
		}
	})
	override := filepath.Join(dir, "compose.json")
	testsupport.WriteJSON(t, override, map[string]any{"services": map[string]any{"api": map[string]any{
		"environment": map[string]string{"GODEBUG": "gctrace=1"},
	}}})
	testsupport.RedeploySandboxAPI(t, api, override)
	admin, user := testsupport.AdminLogin(t), testsupport.UserLogin(t)
	secret, err := os.ReadFile(filepath.Join(testsupport.SandboxDirectory(t), "jwt/consumer-secret"))
	if err != nil || len(secret) != 43 {
		t.Fatal("missing synthetic introspection credential")
	}
	input := loadtest.LoadInputs{Cookie: loadtest.LoadCookie(t, user), AdminCookie: loadtest.LoadCookie(t, admin), Basic: "Basic " + base64.StdEncoding.EncodeToString(append([]byte("sandbox-consumer:"), secret...))}
	loadtest.RunLoadPhase(t, api, user, input, "warmup", 10, 15*time.Second)
	for _, rate := range []int{10, 25, 50} {
		t.Logf("starting bounded mixed HTTP phase: targetRPS=%d", rate)
		loadtest.RunLoadPhase(t, api, user, input, "step", rate, 30*time.Second)
	}
	t.Log("starting 90s stable phase at 50RPS; not a long-duration soak")
	loadtest.RunLoadPhase(t, api, user, input, "stable", 50, 90*time.Second)
	checkLoadLoginBurst(t, api)
	t.Log("load stopped; observing 45s rest without forced GC")
	testsupport.WaitSecurityUntil(t, time.Now().Add(45*time.Second))
	testsupport.Request(t, api, "GET", "/health/ready", nil, nil, 200)
	captureLoadGC(t)
}

func checkLoadLoginBurst(t *testing.T, api *http.Client) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": "ivan@sandbox.example", "password": "Sandbox-Ivan-2026!"})
	call := loadtest.LoadCall{Name: "login", Method: "POST", Path: "/api/v1/auth/login/email", Body: string(body), AllowBusy: true}
	results := make(chan loadtest.LoadResult, 8)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			<-start
			results <- loadtest.ExecuteLoad(t.Context(), api, call)
		})
	}
	close(start)
	workers.Wait()
	close(results)
	t.Log("separate 8-login burst: 503 is expected bounded hash admission, not successful throughput")
	loadtest.ReportLoadResults(t, results, false)
}
