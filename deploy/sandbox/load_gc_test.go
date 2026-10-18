package sandbox_test

import (
	"bufio"
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func captureLoadGC(t *testing.T) {
	t.Helper()
	container := sandboxContainer(t, "api")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "logs", container)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal("cannot read sandbox GC diagnostics")
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal("cannot start sandbox GC diagnostics")
	}
	heap := regexp.MustCompile(`(\d+)->(\d+)->(\d+) MB`)
	clock := regexp.MustCompile(`: ([0-9.]+)\+([0-9.]+)\+([0-9.]+) ms clock`)
	cycles, maxLive, lastLive := 0, 0, 0
	maxSTW := 0.0
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "gc ") {
			continue // Application logs can contain sensitive data; never emit them.
		}
		if parts := heap.FindStringSubmatch(line); len(parts) == 4 {
			cycles++
			lastLive, _ = strconv.Atoi(parts[3])
			maxLive = max(maxLive, lastLive)
		}
		if parts := clock.FindStringSubmatch(line); len(parts) == 4 {
			start, _ := strconv.ParseFloat(parts[1], 64)
			end, _ := strconv.ParseFloat(parts[3], 64)
			maxSTW = max(maxSTW, start+end)
		}
	}
	readErr, waitErr := scanner.Err(), cmd.Wait()
	if readErr != nil || waitErr != nil || cycles == 0 {
		t.Fatal("missing or unreadable sandbox GC observations")
	}
	t.Logf("GC observations: cycles=%d maxLiveHeapMB=%d lastLiveHeapMB=%d maxCombinedSTWms=%.3f; not RSS, not goroutine/leak proof", cycles, maxLive, lastLive, maxSTW)
}
