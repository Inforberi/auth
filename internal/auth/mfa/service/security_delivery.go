package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/delivery"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type SecurityDeliveryRepository interface {
	ClaimSecurityDelivery(context.Context) (*domain.SecurityDelivery, error)
	FinishSecurityDelivery(context.Context, domain.SecurityDelivery, bool) error
}

type SecurityMailer interface {
	SendContext(context.Context, string, string, string) error
}

type SecurityDelivery struct {
	repo   SecurityDeliveryRepository
	cipher Cipher
	mail   SecurityMailer
}

func NewSecurityDelivery(repo SecurityDeliveryRepository, cipher Cipher, mail SecurityMailer) (*SecurityDelivery, error) {
	if repo == nil || cipher == nil || mail == nil {
		return nil, errors.New("invalid MFA security delivery dependencies")
	}
	return &SecurityDelivery{repo: repo, cipher: cipher, mail: mail}, nil
}

func (s *SecurityDelivery) DeliverOne(ctx context.Context) (bool, error) {
	claimCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	job, err := s.repo.ClaimSecurityDelivery(claimCtx)
	stop()
	if err != nil || job == nil {
		return false, err
	}
	err = domain.ErrSecurityDelivery
	if !job.Exhausted {
		deliveryCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err = s.send(deliveryCtx, job.Payload)
		cancel()
	}
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if finishErr := s.repo.FinishSecurityDelivery(finishCtx, *job, err == nil); finishErr != nil {
		return true, finishErr
	}
	return true, err
}

func (s *SecurityDelivery) send(ctx context.Context, payload []byte) error {
	plain, err := s.cipher.Open(payload)
	if err != nil {
		return domain.ErrSecurityDelivery
	}
	defer clear(plain)
	var notice securityNotice
	if err := json.Unmarshal(plain, &notice); err != nil {
		return domain.ErrSecurityDelivery
	}
	body, err := securityNoticeBody(notice)
	if err != nil {
		return err
	}
	if err := s.mail.SendContext(ctx, notice.To, "Изменение второго фактора", body); err != nil {
		return domain.ErrSecurityDelivery
	}
	return nil
}

func (s *SecurityDelivery) RunDelivery(ctx context.Context, report func(error)) {
	delivery.Run(ctx, s.DeliverOne, func(error) { report(domain.ErrSecurityDelivery) })
}
