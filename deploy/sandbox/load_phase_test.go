package sandbox_test

import (
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"
)

func runLoadPhase(t *testing.T, api, user *http.Client, input loadInputs, name string, rate int, duration time.Duration) {
	t.Helper()
	if rate < 1 || rate > 50 || duration < time.Second || duration > 90*time.Second {
		t.Fatal("load profile exceeds the fixed local safety bounds")
	}
	input.token = exchange(t, user, "sandbox-strict").AccessToken
	jobs := make(chan loadCall)
	results := make(chan loadResult, rate*int(duration/time.Second)+16)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for call := range jobs {
				results <- executeLoad(t.Context(), api, call)
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
			call := mixedLoadCall(offered, input)
			offered++
			select {
			case jobs <- call:
			default:
				dropped++
			}
		case <-renew.C:
			input.token = exchange(t, user, "sandbox-strict").AccessToken
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
	reportLoadResults(t, results, true)
	request(t, api, "GET", "/health/ready", nil, nil, 200)
	if t.Failed() {
		t.Fatal("stopping load after a failed diagnostic gate")
	}
}

func reportLoadResults(t *testing.T, results <-chan loadResult, latencyGate bool) {
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
		p95, p99 := loadPercentile(samples, 95), loadPercentile(samples, 99)
		t.Logf("route=%s count=%d statuses=%v p50=%s p95=%s p99=%s", name, len(samples), statuses[name], loadPercentile(samples, 50), p95, p99)
		if latencyGate && (p95 > 250*time.Millisecond || p99 > 500*time.Millisecond) {
			t.Errorf("diagnostic latency gate failed: route=%s", name)
		}
	}
}

func loadPercentile(sorted []time.Duration, percent int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[(len(sorted)*percent+99)/100-1]
}

func TestLoadPercentile(t *testing.T) {
	for _, count := range []int{1, 20, 100} {
		samples := make([]time.Duration, count)
		for i := range samples {
			samples[i] = time.Duration(i + 1)
		}
		if got := loadPercentile(samples, 99); got != time.Duration((count*99+99)/100) {
			t.Fatal("incorrect nearest-rank percentile")
		}
	}
}
