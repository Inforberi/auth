package service

import (
	"context"
	"encoding/json"
	"html"
	"time"
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
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for range 10 {
				processed, err := s.deliverOne(ctx)
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

func (s *Service) send(ctx context.Context, payload []byte) error {
	plain, err := s.cipher.Open(payload)
	if err != nil {
		return err
	}
	var message verificationMail
	if err := json.Unmarshal(plain, &message); err != nil {
		return err
	}
	body := `<p>Подтвердите email: <a href="` + html.EscapeString(message.Link) + `">подтвердить адрес</a>.</p>`
	return s.mail.SendContext(ctx, message.To, "Подтверждение email", body)
}
