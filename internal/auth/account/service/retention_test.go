package service

import (
	"context"
	"errors"
	"testing"
	"time"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type retentionStub struct {
	config RetentionConfig
	err    error
	calls  int
}

func (r *retentionStub) PurgeRetention(ctx context.Context, cfg RetentionConfig) (int64, error) {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 5*time.Second {
		return 0, errors.New("missing bounded deadline")
	}
	r.config = cfg
	r.calls++
	if r.err != nil {
		return 0, r.err
	}
	return 7, nil
}

type retentionSettingsStub struct {
	policy settingsdomain.RetentionPolicy
	err    error
}

func (s *retentionSettingsStub) Current(ctx context.Context) (settingsdomain.RetentionPolicy, error) {
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 5*time.Second {
		return settingsdomain.RetentionPolicy{}, errors.New("missing shared batch deadline")
	}
	return s.policy, s.err
}

func TestRetentionLiveSettings(t *testing.T) {
	repo := &retentionStub{}
	settings := &retentionSettingsStub{policy: settingsdomain.RetentionPolicy{EmailReservationDays: 7, SessionDays: 60, SecurityAuditDays: 365}}
	cfg := RetentionConfig{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 180, BatchSize: 12, Interval: time.Minute}
	svc := NewRetention(repo, cfg).WithSettings(settings)
	if _, err := svc.Purge(t.Context()); err != nil || repo.config.SessionDays != 60 || repo.config.BatchSize != 12 || repo.config.Interval != time.Minute {
		t.Fatal(repo.config, err)
	}
	settings.policy.SessionDays = 90
	if _, err := svc.Purge(t.Context()); err != nil || repo.config.SessionDays != 90 || svc.cfg != cfg {
		t.Fatal("stale or mutated config", err)
	}
	settings.err = errors.New("missing settings")
	if count, err := svc.Purge(t.Context()); !errors.Is(err, settings.err) || count != 0 || repo.calls != 2 {
		t.Fatal("cleanup used ENV fallback", count, err)
	}
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
