package sandbox_test

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type cleanupTracker struct {
	last                                    cleanupCounts
	samples, maxSessions, maxAudit          int
	sessionsDrainedAfter, auditDrainedAfter time.Duration
	err                                     error
}

func startCleanupObserver(t *testing.T, container, owner string, initial cleanupCounts) (*cleanupTracker, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	state := &cleanupTracker{last: initial}
	started := time.Now()
	go func() {
		defer close(done)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		previousAt := started
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			next, err := readCleanupCounts(ctx, container, owner)
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				err = validateCleanupStep(state.last, next)
			}
			observed := time.Now()
			if observed.Sub(previousAt) > 30*time.Second && err == nil {
				err = fmt.Errorf("observation gap too large to bound one-minute worker batches")
			}
			if err != nil {
				state.err = err
				return
			}
			state.samples++
			state.maxSessions = max(state.maxSessions, state.last.Expired-next.Expired)
			state.maxAudit = max(state.maxAudit, state.last.OldAudit-next.OldAudit)
			if next.Expired == 0 && state.sessionsDrainedAfter == 0 {
				state.sessionsDrainedAfter = observed.Sub(started)
			}
			if next.OldAudit == 0 && state.auditDrainedAfter == 0 {
				state.auditDrainedAfter = observed.Sub(started)
			}
			if next != state.last {
				t.Logf("worker snapshot after %s: expired=%d oldAudit=%d controls=%d/%d/%d families=%d youngAudit=%d", observed.Sub(started).Round(time.Millisecond), next.Expired, next.OldAudit, next.Young, next.Live, next.Held, next.Families, next.YoungAudit)
			}
			state.last, previousAt = next, observed
		}
	}()
	return state, func() { cancel(); <-done }
}

func validateCleanupStep(previous, next cleanupCounts) error {
	if next.Young != 12 || next.Live != 12 || next.Held != 12 || next.Families != 12 || next.YoungAudit != 12 {
		return fmt.Errorf("retention removed a fresh/unexpired/held-reference fixture control")
	}
	if sessions, audit := previous.Expired-next.Expired, previous.OldAudit-next.OldAudit; sessions < 0 || audit < 0 || sessions > 200 || audit > 200 {
		return fmt.Errorf("retention count rose or exceeded the 200-candidate observed batch bound")
	}
	return nil
}

func TestCleanupObservationBounds(t *testing.T) {
	previous := cleanupCounts{Expired: 450, Young: 12, Live: 12, Held: 12, Families: 12, OldAudit: 450, YoungAudit: 12}
	next := previous
	next.Expired, next.OldAudit = 262, 250
	if err := validateCleanupStep(previous, next); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*cleanupCounts){
		func(c *cleanupCounts) { c.Expired = 249 },
		func(c *cleanupCounts) { c.OldAudit = 451 },
		func(c *cleanupCounts) { c.Live = 11 },
		func(c *cleanupCounts) { c.Families = 11 },
	} {
		invalid := previous
		change(&invalid)
		if validateCleanupStep(previous, invalid) == nil {
			t.Fatal("unsafe cleanup transition accepted")
		}
	}
}
