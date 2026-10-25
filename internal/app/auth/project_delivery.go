package auth

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Inforberi/financial-intelligence/internal/config"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

type ProjectDeliveryConfig struct {
	Parallelism        int
	PageSize           int
	Interval           time.Duration
	SMTPAllowedTargets []string
}

type ProjectDelivery struct {
	cfg     ProjectDeliveryConfig
	deps    ProjectSMTPDependencies
	running atomic.Bool
}

func NewProjectDelivery(cfg ProjectDeliveryConfig, deps ProjectSMTPDependencies) (*ProjectDelivery, error) {
	if deps.Registry == nil || deps.Reader == nil || deps.Redis == nil || cfg.Parallelism < 1 || cfg.Parallelism > projectruntime.StateBatchSize || cfg.PageSize < cfg.Parallelism || cfg.PageSize > projectruntime.StateBatchSize || cfg.Interval < time.Second || cfg.Interval > time.Minute || len(cfg.SMTPAllowedTargets) < 1 || len(cfg.SMTPAllowedTargets) > 16 {
		return nil, errors.New("invalid project delivery configuration")
	}
	cfg.SMTPAllowedTargets = slices.Clone(cfg.SMTPAllowedTargets)
	return &ProjectDelivery{cfg: cfg, deps: deps}, nil
}

// Run is opt-in lifecycle work. Its owner runs one scheduler and drains it before shared dependencies.
func (d *ProjectDelivery) Run(ctx context.Context, report func(error)) error {
	if report == nil || !d.running.CompareAndSwap(false, true) {
		return errors.New("project delivery already running or reporter missing")
	}
	defer d.running.Store(false)
	var cursor projectpostgres.RuntimeCursor
	for ctx.Err() == nil {
		keys, next, err := d.deps.Reader.PageRuntimes(ctx, cursor, d.cfg.PageSize)
		if err != nil {
			if ctx.Err() == nil {
				report(err)
			}
		} else {
			deliverProjectPage(ctx, keys, d.cfg.Parallelism, d.deliverProject, report)
			cursor = next
		}
		timer := time.NewTimer(d.cfg.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return ctx.Err()
}

func deliverProjectPage(ctx context.Context, keys []projectruntime.Key, parallelism int, process func(context.Context, projectruntime.Key) error, report func(error)) {
	var workers sync.WaitGroup
	var next atomic.Int64
	failures := make(chan error, len(keys))
	for range min(parallelism, len(keys)) {
		workers.Go(func() {
			for ctx.Err() == nil {
				index := next.Add(1) - 1
				if index >= int64(len(keys)) {
					return
				}
				if err := process(ctx, keys[index]); err != nil && ctx.Err() == nil {
					failures <- err
				}
			}
		})
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		report(err)
	}
}

func (d *ProjectDelivery) deliverProject(ctx context.Context, key projectruntime.Key) error {
	configuration, err := d.deps.Reader.LoadAuthConfiguration(ctx, key, d.deps.Registry)
	if err != nil {
		return err
	}
	runtime, err := newProjectEmailRuntime(key, configuration.EncryptionKey(), d.cfg.SMTPAllowedTargets, d.deps)
	if err != nil {
		return err
	}
	// Missing/invalid SMTP must not claim jobs and consume their retry allowance.
	if _, err := runtime.smtp.credentials(ctx); err != nil {
		return err
	}
	verificationErr := runtime.deliver(ctx, true)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	resetErr := runtime.deliver(ctx, false)
	return errors.Join(verificationErr, resetErr)
}

func assembleProjectDelivery(cfg config.PlatformConfig, runtime *projectRuntime, rdb *redis.Client) (*ProjectDelivery, error) {
	if !cfg.Delivery.Enabled {
		return nil, nil
	}
	if runtime == nil {
		return nil, errors.New("project delivery requires project runtime")
	}
	c := cfg.Delivery
	return NewProjectDelivery(ProjectDeliveryConfig{Parallelism: c.Parallelism, PageSize: c.PageSize, Interval: c.Interval, SMTPAllowedTargets: c.Targets()}, ProjectSMTPDependencies{Registry: runtime.registry, Reader: runtime.reader, Redis: rdb})
}

func (d *ProjectDelivery) RunDelivery(ctx context.Context, report func(error)) {
	if err := d.Run(ctx, report); err != nil && ctx.Err() == nil {
		report(err)
	}
}
