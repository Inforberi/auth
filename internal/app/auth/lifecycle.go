package auth

import (
	"context"
	"errors"

	"go.uber.org/zap"

	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	passwordrecovery "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/service"
	mfadelivery "github.com/Inforberi/financial-intelligence/internal/auth/mfa/delivery/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	projectdelivery "github.com/Inforberi/financial-intelligence/internal/auth/project/delivery"
)

type DeliveryWorker interface {
	RunDelivery(context.Context, func(error))
}

func DeliveryWorkers(recovery *passwordrecovery.RecoveryService, account *accountemail.Verification, mfa *mfadelivery.SecurityDelivery, email *otpservice.Delivery, projects ...*projectdelivery.ProjectDelivery) []DeliveryWorker {
	var workers []DeliveryWorker
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
	for _, project := range projects {
		if project != nil {
			workers = append(workers, project)
		}
	}
	return workers
}

func startDelivery(ctx context.Context, service DeliveryWorker, log *zap.Logger,
) func() {
	return startBackground(ctx, func(ctx context.Context) {
		service.RunDelivery(ctx, func(err error) {
			if errors.Is(err, domain.ErrSecurityDelivery) {
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

func runWithDelivery(ctx context.Context, log *zap.Logger, serve func(context.Context) error, workers ...DeliveryWorker,
) error {
	for _, worker := range workers {
		stop := startDelivery(ctx, worker, log)
		defer stop()
	}
	return serve(ctx)
}

type RetentionWorker interface {
	RunRetention(context.Context, func(error))
}

func (r *Runtime) Run(ctx context.Context, log *zap.Logger, serve func(context.Context) error) error {
	active := make([]DeliveryWorker, 0, len(r.workers))
	for _, worker := range r.workers {
		if worker != nil {
			active = append(active, worker)
		}
	}
	stopRetention := startBackground(ctx, func(ctx context.Context) {
		r.retention.RunRetention(ctx, func(error) { log.Warn("retention processing failed") })
	})
	defer stopRetention()
	return runWithDelivery(ctx, log, func(ctx context.Context) error {
		if r.drainHTTP != nil {
			defer r.drainHTTP()
		}
		return serve(ctx)
	}, active...)
}
