package service

import (
	"context"
	"encoding/json"
	"time"
)

func (r *RecoveryService) DeliverOne(ctx context.Context) (bool, error) {
	claimCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	job, err := r.repo.ClaimResetDelivery(claimCtx)
	stop()
	if err != nil || job == nil {
		return false, err
	}
	deliveryCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	err = r.deliver(deliveryCtx, job.Payload)
	cancel()
	finishCtx, finish := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer finish()
	if finishErr := r.repo.FinishResetDelivery(finishCtx, *job, err == nil); finishErr != nil {
		return true, finishErr
	}
	return true, err
}

func (r *RecoveryService) deliver(ctx context.Context, payload []byte) error {
	plain, err := r.cipher.Open(payload)
	if err != nil {
		return err
	}
	var message resetMail
	if err := json.Unmarshal(plain, &message); err != nil {
		return err
	}
	return r.mail.SendContext(ctx, message.To, "Сброс пароля", message.Body)
}

func (r *RecoveryService) RunDelivery(ctx context.Context, report func(error)) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for range 10 {
				processed, err := r.DeliverOne(ctx)
				if err != nil && ctx.Err() == nil {
					report(err)
				}
				if !processed || ctx.Err() != nil {
					break
				}
			}
		}
	}
}
