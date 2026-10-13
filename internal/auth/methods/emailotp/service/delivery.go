package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/delivery"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
)

type deliveryRepository interface {
	ClaimDelivery(context.Context) (*domain.Delivery, error)
	FinishDelivery(context.Context, domain.Delivery, bool) error
}

type mailer interface {
	SendContext(context.Context, string, string, string) error
}

type Delivery struct {
	repo   deliveryRepository
	cipher cipher
	mail   mailer
}

func NewDelivery(repo deliveryRepository, cipher cipher, mail mailer) *Delivery {
	return &Delivery{repo: repo, cipher: cipher, mail: mail}
}

func (d *Delivery) DeliverOne(ctx context.Context) (bool, error) {
	claimCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	job, err := d.repo.ClaimDelivery(claimCtx)
	stop()
	if err != nil || job == nil {
		return false, err
	}
	deliveryCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	err = d.send(deliveryCtx, job.Payload)
	cancel()
	finishCtx, finish := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer finish()
	if finishErr := d.repo.FinishDelivery(finishCtx, *job, err == nil); finishErr != nil {
		return true, finishErr
	}
	return true, err
}

func (d *Delivery) send(ctx context.Context, payload []byte) error {
	plain, err := d.cipher.Open(payload)
	if err != nil {
		return err
	}
	var message codeMail
	if err := json.Unmarshal(plain, &message); err != nil {
		return err
	}
	if message.Subject == "" {
		message.Subject = "Код для входа"
	} // Existing queued login payloads have no subject.
	return d.mail.SendContext(ctx, message.To, message.Subject, message.Body)
}

func (d *Delivery) RunDelivery(ctx context.Context, report func(error)) {
	delivery.Run(ctx, d.DeliverOne, report)
}
