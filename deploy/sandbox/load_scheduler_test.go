package sandbox_test

import (
	"bufio"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type schedulerDiagnostics struct {
	Snapshots, Active, MaxActive int
	UptimeMS                     int64
}

func readSchedulerDiagnostics(reader io.Reader) (schedulerDiagnostics, error) {
	header := regexp.MustCompile(`^SCHED (\d+)ms:`)
	goroutine := regexp.MustCompile(`^  G\d+: status=(\d+)\(`)
	var result, pending schedulerDiagnostics
	seen, size := false, 0
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		size += len(line) + 1
		if size > 4<<20 {
			return result, errors.New("runtime diagnostics exceeded 4MiB safety bound")
		}
		if match := header.FindStringSubmatch(line); match != nil {
			// Only a following header establishes that the preceding snapshot finished.
			if seen {
				result.Snapshots++
				result.Active, result.UptimeMS = pending.Active, pending.UptimeMS
				result.MaxActive = max(result.MaxActive, pending.Active)
			}
			pending = schedulerDiagnostics{}
			pending.UptimeMS, _ = strconv.ParseInt(match[1], 10, 64)
			seen = false
			continue
		}
		if match := goroutine.FindStringSubmatch(line); match != nil {
			status, _ := strconv.Atoi(match[1])
			// Go1.27.2 runtime2.go: ignore scan bit, idle and reusable dead descriptors.
			status &^= 0x1000
			if status != 0 && status != 6 && status != 11 {
				pending.Active++
			}
			seen = true
		}
	}
	if err := scanner.Err(); err != nil {
		return result, errors.New("unreadable runtime diagnostics")
	}
	if result.Snapshots == 0 {
		return result, errors.New("no completed scheduler snapshots")
	}
	return result, nil
}

func TestSchedulerDiagnostics(t *testing.T) {
	input := "SCHED 0ms: threads=3\n" +
		"  G1: status=2() m=0\n  G2: status=6() m=nil\n" +
		"private application log must not be returned\n" +
		"SCHED 15000ms: threads=5\n" +
		"  G1: status=4100(select) m=nil\n  G2: status=4(IO wait) m=nil\n" +
		"  G3: status=0() m=nil\n  G4: status=4107() m=nil\n" +
		"SCHED 30000ms: threads=5\n  G1: status=4(select) m=nil\n"
	got, err := readSchedulerDiagnostics(strings.NewReader(input))
	if err != nil || got.Snapshots != 2 || got.Active != 2 || got.MaxActive != 2 || got.UptimeMS != 15000 {
		t.Fatalf("unexpected completed scheduler observations: %+v, %v", got, err)
	}
	for _, invalid := range []string{"application log only", "SCHED 0ms:\n  G1: status=2() m=0\n", strings.Repeat("safe log\n", 600000)} {
		if _, err := readSchedulerDiagnostics(strings.NewReader(invalid)); err == nil {
			t.Fatal("accepted incomplete or oversized runtime observations")
		}
	}
}
