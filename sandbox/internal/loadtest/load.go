package loadtest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	testsupport "github.com/Inforberi/financial-intelligence/sandbox/internal/testsupport"
)

type LoadCall struct {
	Name, Method, Path, Cookie, Basic, Body string
	AllowBusy                               bool
}

type LoadResult struct {
	name    string
	status  int
	elapsed time.Duration
	failed  bool
}

type LoadInputs struct{ Cookie, AdminCookie, Basic, Token string }

func MixedLoadCall(index int, input LoadInputs) LoadCall {
	call := LoadCall{Name: "me", Method: "GET", Path: "/api/v1/auth/me", Cookie: input.Cookie}
	switch index % 20 {
	case 12, 13, 14, 15, 16:
		call.Name, call.Path = "access", "/api/v1/auth/access"
	case 17, 18:
		call.Name, call.Path, call.Cookie = "roles", "/api/v1/admin/roles", input.AdminCookie
	case 19:
		body, _ := json.Marshal(map[string]string{"token": input.Token})
		call = LoadCall{Name: "introspect", Method: "POST", Path: "/api/v1/internal/auth/token/introspect", Basic: input.Basic, Body: string(body)}
	}
	return call
}

func ExecuteLoad(ctx context.Context, client *http.Client, call LoadCall) LoadResult {
	started := time.Now()
	result := LoadResult{name: call.Name, failed: true}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, call.Method, testsupport.SandboxURL+call.Path, bytes.NewBufferString(call.Body))
	if err != nil {
		return result
	}
	if call.Cookie != "" {
		req.Header.Set("Cookie", call.Cookie)
	}
	if call.Basic != "" {
		req.Header.Set("Authorization", call.Basic)
	}
	if call.Body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if call.Name == "login" {
		req.Header.Set("Origin", testsupport.SandboxURL)
	}
	response, err := client.Do(req)
	if err != nil {
		result.elapsed = time.Since(started)
		return result
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 32769))
	closeErr := response.Body.Close()
	result.status, result.elapsed = response.StatusCode, time.Since(started)
	if readErr != nil || closeErr != nil || len(data) > 32768 || !json.Valid(data) {
		return result
	}
	if result.status != 200 && (!call.AllowBusy || result.status != 503) {
		return result
	}
	if call.Name == "introspect" {
		var state struct{ Active bool }
		if json.Unmarshal(data, &state) != nil || !state.Active {
			return result
		}
	}
	result.failed = false
	return result
}

func LoadCookie(t *testing.T, client *http.Client) string {
	t.Helper()
	u, err := url.Parse(testsupport.SandboxURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range client.Jar.Cookies(u) {
		if cookie.Name == "__Host-session" {
			return cookie.Name + "=" + cookie.Value
		}
	}
	t.Fatal("missing synthetic load session")
	return ""
}

func RunLoadPhase(t *testing.T, api, user *http.Client, input LoadInputs, name string, rate int, duration time.Duration) {
	t.Helper()
	if rate < 1 || rate > 50 || duration < time.Second || duration > 90*time.Second {
		t.Fatal("load profile exceeds the fixed local safety bounds")
	}
	input.Token = testsupport.Exchange(t, user, "sandbox-strict").AccessToken
	jobs := make(chan LoadCall)
	results := make(chan LoadResult, rate*int(duration/time.Second)+16)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for call := range jobs {
				results <- ExecuteLoad(t.Context(), api, call)
			}
		})
	}
	closed := false
	defer func() {
		if !closed {
			close(jobs)
			workers.Wait()
		}
	}()
	started := time.Now()
	ticker := time.NewTicker(time.Second / time.Duration(rate))
	defer ticker.Stop()
	renew := time.NewTicker(25 * time.Second)
	defer renew.Stop()
	stop := time.NewTimer(duration)
	defer stop.Stop()
	offered, dropped := 0, 0
schedule:
	for {
		select {
		case <-ticker.C:
			call := MixedLoadCall(offered, input)
			offered++
			select {
			case jobs <- call:
			default:
				dropped++
			}
		case <-renew.C:
			input.Token = testsupport.Exchange(t, user, "sandbox-strict").AccessToken
		case <-stop.C:
			break schedule
		case <-t.Context().Done():
			break schedule
		}
	}
	close(jobs)
	closed = true
	workers.Wait()
	close(results)
	elapsed := time.Since(started)
	t.Logf("phase=%s offered=%d dropped=%d elapsed=%s completedRPS=%.2f", name, offered, dropped, elapsed.Round(time.Millisecond), float64(offered-dropped)/elapsed.Seconds())
	if dropped != 0 || float64(offered-dropped)/elapsed.Seconds() < float64(rate)*0.98 {
		t.Error("generator could not sustain the bounded offered rate")
	}
	ReportLoadResults(t, results, true)
	testsupport.Request(t, api, "GET", "/health/ready", nil, nil, 200)
	if t.Failed() {
		t.Fatal("stopping load after a failed diagnostic gate")
	}
}

func ReportLoadResults(t *testing.T, results <-chan LoadResult, latencyGate bool) {
	t.Helper()
	latencies := map[string][]time.Duration{}
	statuses := map[string]map[int]int{}
	failed := 0
	for result := range results {
		latencies[result.name] = append(latencies[result.name], result.elapsed)
		if statuses[result.name] == nil {
			statuses[result.name] = map[int]int{}
		}
		statuses[result.name][result.status]++
		if result.failed {
			failed++
		}
	}
	if failed != 0 {
		t.Errorf("unexpected status/transport/semantic failures=%d; response bodies omitted", failed)
	}
	for name, samples := range latencies {
		slices.Sort(samples)
		p95, p99 := LoadPercentile(samples, 95), LoadPercentile(samples, 99)
		t.Logf("route=%s count=%d statuses=%v p50=%s p95=%s p99=%s", name, len(samples), statuses[name], LoadPercentile(samples, 50), p95, p99)
		if latencyGate && (p95 > 250*time.Millisecond || p99 > 500*time.Millisecond) {
			t.Errorf("diagnostic latency gate failed: route=%s", name)
		}
	}
}

func LoadPercentile(sorted []time.Duration, percent int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[(len(sorted)*percent+99)/100-1]
}
