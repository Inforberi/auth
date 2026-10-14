package service

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type recoveryDeliveryStub struct {
	job       *domain.RecoveryDelivery
	finished  bool
	sent      bool
	finishErr error
}

func (s *recoveryDeliveryStub) ClaimRecoveryDelivery(context.Context) (*domain.RecoveryDelivery, error) {
	return s.job, nil
}

func (s *recoveryDeliveryStub) FinishRecoveryDelivery(_ context.Context, _ domain.RecoveryDelivery, sent bool) error {
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

func TestRecoveryDeliveryContract(t *testing.T) {
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := sealRecoveryNotice(cipher, "owner@example.com", "22222222-2222-4222-8222-222222222222", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repo := &recoveryDeliveryStub{job: &domain.RecoveryDelivery{Payload: payload, Attempts: 1}}
	mail := &recoveryMailStub{}
	worker, err := NewRecoveryDelivery(repo, cipher, mail)
	if err != nil {
		t.Fatal(err)
	}
	if processed, err := worker.DeliverOne(context.Background()); err != nil || !processed || !repo.sent || mail.to != "owner@example.com" || strings.Contains(mail.body, "href=") {
		t.Fatal("delivery", processed, err)
	}
	mail.err = errors.New("SMTP secret payload")
	if processed, err := worker.DeliverOne(context.Background()); !processed || !errors.Is(err, domain.ErrRecoveryDelivery) || repo.sent || strings.Contains(err.Error(), "secret payload") {
		t.Fatal("sanitized SMTP failure", err)
	}
	repo.job.Exhausted = true
	before := mail.calls
	if _, err := worker.DeliverOne(context.Background()); !errors.Is(err, domain.ErrRecoveryDelivery) || mail.calls != before || !repo.finished {
		t.Fatal("exhausted lease sent again", err)
	}
	repo.job.Exhausted = false
	repo.job.Payload = []byte("corrupt")
	if _, err := worker.DeliverOne(context.Background()); !errors.Is(err, domain.ErrRecoveryDelivery) || mail.calls != before {
		t.Fatal("corrupt mail sent", err)
	}
	repo.finishErr = errors.New("acknowledgement failed")
	if _, err := worker.DeliverOne(context.Background()); !errors.Is(err, repo.finishErr) {
		t.Fatal("lost finish error", err)
	}
}
