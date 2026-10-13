package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
)

type mailFixture struct {
	job      *domain.Delivery
	sent     bool
	finished int
	mails    int
	fail     error
	subject  string
}

func (f *mailFixture) ClaimDelivery(context.Context) (*domain.Delivery, error) { return f.job, nil }
func (f *mailFixture) FinishDelivery(_ context.Context, _ domain.Delivery, sent bool) error {
	f.finished++
	f.sent = sent
	return nil
}

func (f *mailFixture) SendContext(_ context.Context, to, subject, body string) error {
	f.mails++
	expected := f.subject
	if expected == "" {
		expected = "Код для входа"
	}
	if to != "user@example.test" || subject != expected || body != "code body" {
		return errors.New("wrong mail")
	}
	return f.fail
}

func TestDeliveryEncryptedAndAcknowledged(t *testing.T) {
	_, _, c := otpFixture(t)
	plain, err := json.Marshal(codeMail{To: "user@example.test", Body: "code body"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := c.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		payload   []byte
		fail      error
		wantSent  bool
		wantMails int
	}{
		{payload, nil, true, 1}, {payload, errors.New("SMTP unavailable"), false, 1}, {[]byte("tampered"), nil, false, 0},
	} {
		f := &mailFixture{job: &domain.Delivery{Payload: tc.payload}, fail: tc.fail}
		processed, err := NewDelivery(f, c, f).DeliverOne(context.Background())
		if !processed || f.finished != 1 || f.sent != tc.wantSent || f.mails != tc.wantMails || (err == nil) != tc.wantSent {
			t.Fatal(tc, processed, err, f)
		}
	}
	f := &mailFixture{}
	processed, err := NewDelivery(f, c, f).DeliverOne(context.Background())
	if processed || err != nil || f.finished != 0 || f.mails != 0 {
		t.Fatal("empty queue", err)
	}
}

func TestReauthenticationDeliverySubject(t *testing.T) {
	_, _, c := otpFixture(t)
	subject := "Код для подтверждения управления MFA"
	plain, err := json.Marshal(codeMail{To: "user@example.test", Body: "code body", Subject: subject})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := c.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	f := &mailFixture{job: &domain.Delivery{Payload: payload}, subject: subject}
	if processed, err := NewDelivery(f, c, f).DeliverOne(t.Context()); err != nil || !processed || !f.sent || f.mails != 1 {
		t.Fatal(processed, err, f)
	}
}
