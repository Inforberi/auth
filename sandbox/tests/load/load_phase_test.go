package sandbox_test

import (
	"testing"
	"time"

	loadtest "github.com/Inforberi/financial-intelligence/sandbox/internal/loadtest"
)

func TestLoadPercentile(t *testing.T) {
	for _, count := range []int{1, 20, 100} {
		samples := make([]time.Duration, count)
		for i := range samples {
			samples[i] = time.Duration(i + 1)
		}
		if got := loadtest.LoadPercentile(samples, 99); got != time.Duration((count*99+99)/100) {
			t.Fatal("incorrect nearest-rank percentile")
		}
	}
}
