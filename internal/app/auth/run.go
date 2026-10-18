package auth

import (
	"context"
	"errors"
	"sync"

	"go.uber.org/zap"

	accessapp "github.com/Inforberi/financial-intelligence/internal/app/access"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type App struct {
	Access             *accessapp.App
	Provisioning       *accountservice.ProvisionService
	TemporaryPasswords *passwordservice.TemporaryPasswordService
	serve              func(context.Context) error
	resources          *resources
}

func (a *App) Run(ctx context.Context) error {
	defer a.Close()
	return a.serve(ctx)
}

// Close is idempotent. Normally Run closes the application; callers that do not
// start it must call Close themselves. Do not close it while Run is active.
func (a *App) Close() {
	a.resources.close()
}

type resources struct {
	once    sync.Once
	closers []func()
}

func (r *resources) add(close func()) {
	if close != nil {
		r.closers = append(r.closers, close)
	}
}

func (r *resources) close() {
	r.once.Do(func() {
		for i := len(r.closers) - 1; i >= 0; i-- {
			r.closers[i]()
		}
	})
}

type deliveryWorker interface {
	RunDelivery(context.Context, func(error))
}

func realmDeliveryWorkers(recovery *passwordservice.RecoveryService, account *accountservice.Service, mfa *mfaservice.RecoveryDelivery, email *otpservice.Delivery) []deliveryWorker {
	var workers []deliveryWorker
	// Check concrete pointers before conversion: a typed nil is a non-nil interface.
	if recovery != nil {
		workers = append(workers, recovery)
	}
	if account != nil {
		workers = append(workers, account)
	}
	if mfa != nil {
		workers = append(workers, mfa)
	}
	if email != nil {
		workers = append(workers, email)
	}
	return workers
}

func startDelivery(ctx context.Context, service deliveryWorker, log *zap.Logger,
) func() {
	return startBackground(ctx, func(ctx context.Context) {
		service.RunDelivery(ctx, func(err error) {
			if errors.Is(err, mfadomain.ErrRecoveryDelivery) {
				log.Error("MFA security notification delivery failed; inspect durable queue")
				return
			}
			log.Warn("email delivery processing failed")
		})
	})
}

func startBackground(ctx context.Context, run func(context.Context)) func() {
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		run(workerCtx)
	}()
	return func() { cancel(); <-done }
}

func runWithDelivery(ctx context.Context, log *zap.Logger, serve func(context.Context) error, workers ...deliveryWorker,
) error {
	for _, worker := range workers {
		stop := startDelivery(ctx, worker, log)
		defer stop()
	}
	return serve(ctx)
}

type retentionWorker interface {
	RunRetention(context.Context, func(error))
}

func (r *realm) run(ctx context.Context, log *zap.Logger, serve func(context.Context) error) error {
	active := make([]deliveryWorker, 0, len(r.workers))
	for _, worker := range r.workers {
		if worker != nil {
			active = append(active, worker)
		}
	}
	stopRetention := startBackground(ctx, func(ctx context.Context) {
		r.retention.RunRetention(ctx, func(error) { log.Warn("retention processing failed") })
	})
	defer stopRetention()
	return runWithDelivery(ctx, log, serve, active...)
}
