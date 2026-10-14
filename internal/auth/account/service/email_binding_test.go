package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type bindingRepository struct {
	command                       service.EmailBindingCommand
	proof                         mfaservice.Proof
	verifier                      string
	issued, confirmed, preflights int
	permissionErr, failure        error
}

func (r *bindingRepository) CanRequestEmailBinding(context.Context, accessservice.Principal) error {
	r.preflights++
	return r.permissionErr
}

func (r *bindingRepository) IssueEmailBinding(_ context.Context, c service.EmailBindingCommand) (time.Time, error) {
	r.issued++
	r.command = c
	return time.Now().Add(c.TTL), r.failure
}

func (r *bindingRepository) ConfirmEmailBinding(_ context.Context, p mfaservice.Proof, verifier string) error {
	r.confirmed++
	r.proof = p
	r.verifier = verifier
	return r.failure
}

func TestEmailBindingCodeAndAuthority(t *testing.T) {
	_, _, limit, _, cipher := fixture(t)
	r := &bindingRepository{}
	svc := service.NewEmailBinding(r, limit, cipher, service.EmailBindingConfig{Enabled: true, TTL: 5 * time.Minute, RequestsPerMinute: 100, ConfirmationsPerMinute: 1000})
	input := service.EmailBindingInput{Actor: accessservice.Principal{UserID: "00000000-0000-0000-0000-000000000001", TokenHash: strings.Repeat("a", 64)}, UserID: "00000000-0000-0000-0000-000000000002", Email: " User@example.test ", IP: "192.0.2.1"}
	if _, err := svc.Request(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	if r.command.Actor != input.Actor || r.command.UserID != input.UserID || r.command.Email != "user@example.test" || r.preflights != 1 || r.issued != 1 || len(limit.keys) != 4 {
		t.Fatal(r, limit)
	}
	plain, err := cipher.Open(r.command.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var mail struct{ To, Subject, Body string }
	if err := json.Unmarshal(plain, &mail); err != nil {
		t.Fatal(err)
	}
	start := strings.Index(mail.Body, "<strong>") + len("<strong>")
	code := mail.Body[start : start+8]
	if !domain.ValidEmailBindingCode(code) || mail.To != r.command.Email || mail.Subject != "Привязка почты к аккаунту" || strings.Contains(string(r.command.Payload), code) {
		t.Fatal("unsafe or ambiguous mail")
	}
	proof := mfaservice.Proof{UserID: input.UserID, TokenHash: strings.Repeat("b", 64), AuthVersion: 7}
	if err := svc.Confirm(t.Context(), proof, code, input.IP); err != nil || r.proof != proof || r.verifier != r.command.Verifier {
		t.Fatal(err, r)
	}
	for _, key := range limit.keys {
		if strings.Contains(key, string(input.UserID)) || strings.Contains(key, input.IP) {
			t.Fatal("PII in counter key")
		}
	}
}

func TestBindingPreflightProtectsTargetBudget(t *testing.T) {
	_, _, limit, _, cipher := fixture(t)
	r := &bindingRepository{permissionErr: accessdomain.ErrForbidden}
	svc := service.NewEmailBinding(r, limit, cipher, service.EmailBindingConfig{Enabled: true, TTL: 5 * time.Minute, RequestsPerMinute: 100})
	input := service.EmailBindingInput{Actor: accessservice.Principal{UserID: "00000000-0000-0000-0000-000000000001", TokenHash: strings.Repeat("a", 64)}, UserID: "00000000-0000-0000-0000-000000000002", Email: "user@example.test"}
	if _, err := svc.Request(t.Context(), input); !errors.Is(err, accessdomain.ErrForbidden) || r.issued != 0 || len(limit.keys) != 3 {
		t.Fatal(err, r, limit)
	}
	for _, key := range limit.keys {
		if key == cipher.Digest("email-binding:request:user:"+string(input.UserID)) {
			t.Fatal("unauthorized caller depleted target budget")
		}
	}
	limit.keys = nil
	if err := svc.Confirm(t.Context(), mfaservice.Proof{}, "12345678", ""); err == nil || r.confirmed != 0 || len(limit.keys) != 0 {
		t.Fatal("invalid owner admitted", err)
	}
}
