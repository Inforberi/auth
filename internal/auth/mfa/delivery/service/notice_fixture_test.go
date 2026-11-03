package service

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type recoveryDeliveryStub struct {
	job       *domain.SecurityDelivery
	finished  bool
	sent      bool
	finishErr error
}

func (s *recoveryDeliveryStub) ClaimSecurityDelivery(context.Context) (*domain.SecurityDelivery, error) {
	return s.job, nil
}

func (s *recoveryDeliveryStub) FinishSecurityDelivery(_ context.Context, _ domain.SecurityDelivery, sent bool) error {
	s.finished, s.sent = true, sent
	return s.finishErr
}

type recoveryMailStub struct {
	to, subject, body string
	err               error
	calls             int
}

func (m *recoveryMailStub) SendContext(_ context.Context, to, subject, body string) error {
	m.to, m.subject, m.body = to, subject, body
	m.calls++
	return m.err
}
