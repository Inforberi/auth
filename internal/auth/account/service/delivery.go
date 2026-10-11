package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/delivery"
)

func (s *Service) DeliverOne(ctx context.Context) error {
	_, err := s.deliverOne(ctx)
	return err
}

func (s *Service) deliverOne(ctx context.Context) (bool, error) {
	claimCtx, stopClaim := context.WithTimeout(ctx, 5*time.Second)
	job, err := s.repo.ClaimDelivery(claimCtx)
	stopClaim()
	if err != nil || job == nil {
		return false, err
	}
	deliveryCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	err = s.send(deliveryCtx, job.Payload)
	cancel()
	cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	if finishErr := s.repo.FinishDelivery(cleanup, *job, err == nil); finishErr != nil {
		return true, finishErr
	}
	return true, err
}

func (s *Service) RunDelivery(ctx context.Context, report func(error)) {
	delivery.Run(ctx, s.deliverOne, report)
}
