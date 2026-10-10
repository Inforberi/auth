package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

type retentionStub struct {
	config RetentionConfig
	err    error
}

func (r *retentionStub) PurgeRetention(ctx context.Context, cfg RetentionConfig) (int64, error) {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 5*time.Second {
		return 0, errors.New("missing bounded deadline")
	}
	r.config = cfg
	if r.err != nil {
		return 0, r.err
	}
	return 7, nil
}

func TestRetentionPurge(t *testing.T) {
	cfg := RetentionConfig{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 180}
	repo := &retentionStub{}
	svc := NewRetention(repo, cfg)
	if count, err := svc.Purge(t.Context()); err != nil || count != 7 || repo.config != cfg {
		t.Fatal(count, err, repo.config)
	}
	repo.err = errors.New("database unavailable")
	if count, err := svc.Purge(t.Context()); count != 0 || !errors.Is(err, repo.err) {
		t.Fatal(count, err)
	}
}

func TestRetentionWorkerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		NewRetention(&retentionStub{}, RetentionConfig{}).RunRetention(ctx, func(error) { t.Error("unexpected report") })
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
}
