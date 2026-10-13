package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (f *loginFixture) IssueReauthentication(ctx context.Context, proof mfaservice.Proof, email string, c domain.Challenge) error {
	f.reauthProof = proof
	return f.Issue(ctx, email, c)
}

func (f *loginFixture) ConfirmReauthentication(_ context.Context, proof mfaservice.Proof, digest, verifier, replacement string) (*ReauthenticatedSession, error) {
	if proof != f.reauthProof {
		return nil, mfadomain.ErrProofRequired
	}
	f.replacement = replacement
	f.consumed++
	if f.fail != nil {
		return nil, f.fail
	}
	if digest != f.challenge.Digest || verifier != f.challenge.Verifier || len(replacement) != 64 {
		return nil, domain.ErrInvalidCode
	}
	return &ReauthenticatedSession{VerifiedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestEmailReauthentication(t *testing.T) {
	s, f, cipher := otpFixture(t)
	s.cfg.Enabled, s.cfg.ReauthenticationEnabled = false, true
	proof := mfaservice.Proof{UserID: "00000000-0000-0000-0000-000000000001", TokenHash: strings.Repeat("a", 64), AuthVersion: 7}
	result, err := s.RequestReauthentication(t.Context(), proof, " USER@example.test ", "192.0.2.1")
	if err != nil || f.email != "user@example.test" || f.issued != 1 || len(f.keys) != 5 {
		t.Fatal(result, err, f)
	}
	plain, err := cipher.Open(f.challenge.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var mail codeMail
	if err := json.Unmarshal(plain, &mail); err != nil {
		t.Fatal(err)
	}
	if mail.Subject != "Код для подтверждения управления MFA" {
		t.Fatal("ambiguous mail purpose", mail.Subject)
	}
	index := strings.Index(mail.Body, "<strong>") + len("<strong>")
	code := mail.Body[index : index+8]
	if f.challenge.Digest == cipher.Digest("binding:"+result.Binding) || f.challenge.Verifier == cipher.Digest("code:"+result.Binding+":"+code) {
		t.Fatal("login and reauthentication share a purpose")
	}
	confirmed, err := s.ConfirmReauthentication(t.Context(), ReauthenticationInput{Proof: proof, Binding: result.Binding, Code: code, IP: "192.0.2.1"})
	if err != nil || !domain.ValidBinding(confirmed.Token) || confirmed.VerifiedAt.IsZero() || f.sessionCalls != 0 {
		t.Fatal(confirmed, err, f)
	}
	if f.reauthProof != proof || f.replacement != s.tokens.Hash(confirmed.Token) {
		t.Fatal("owner/version/session proof or replacement hash lost")
	}
	encoded, _ := json.Marshal(confirmed)
	if strings.Contains(string(encoded), confirmed.Token) {
		t.Fatal("raw token serialized")
	}
}

func TestReauthenticationAdmission(t *testing.T) {
	for _, scenario := range []string{"disabled", "proof", "email", "limited", "dependency", "bad-code"} {
		t.Run(scenario, func(t *testing.T) {
			s, f, _ := otpFixture(t)
			s.cfg.ReauthenticationEnabled = true
			proof := mfaservice.Proof{UserID: "00000000-0000-0000-0000-000000000001", TokenHash: strings.Repeat("a", 64), AuthVersion: 1}
			email := "user@example.test"
			switch scenario {
			case "disabled":
				s.cfg.ReauthenticationEnabled = false
			case "proof":
				proof.AuthVersion = 0
			case "email":
				email = "invalid"
			case "limited":
				f.allowed = false
			case "dependency":
				f.fail = errors.New("redis unavailable")
			case "bad-code":
				_, err := s.ConfirmReauthentication(t.Context(), ReauthenticationInput{Proof: proof, Binding: strings.Repeat("A", 43), Code: "invalid"})
				if !errors.Is(err, domain.ErrInvalidCode) || len(f.keys) != 0 || f.consumed != 0 {
					t.Fatal(err, f)
				}
				return
			}
			_, err := s.RequestReauthentication(t.Context(), proof, email, "192.0.2.1")
			if err == nil || f.issued != 0 || f.sessionCalls != 0 {
				t.Fatal(err, f)
			}
			if scenario == "proof" && !errors.Is(err, mfadomain.ErrProofRequired) {
				t.Fatal(err)
			}
		})
	}
}
