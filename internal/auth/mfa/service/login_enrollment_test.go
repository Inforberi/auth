package service

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func TestRequiredEnrollmentAdmission(t *testing.T) {
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		allowed    bool
		dependency error
		want       error
	}{
		{"limited", false, nil, domain.ErrLimited},
		{"unavailable", true, errors.New("private dependency error"), domain.ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limits := &limitStub{allowed: tc.allowed, err: tc.dependency}
			svc, err := NewLogin(&loginRepoStub{}, cipher, totp.Authenticator{}, limits, tokengenerate.New(), loginTestConfig())
			if err != nil {
				t.Fatal(err)
			}
			input := LoginEnrollmentInput{Challenge: strings.Repeat("A", 43), Binding: strings.Repeat("A", 43)}
			if _, err := svc.StartRequiredEnrollment(context.Background(), input); !errors.Is(err, tc.want) {
				t.Fatal("start ignored admission", err)
			}
			if _, err := svc.ConfirmRequiredEnrollment(context.Background(), ConfirmLoginEnrollmentInput{LoginEnrollmentInput: input, Token: strings.Repeat("A", 43), Code: "123456"}); !errors.Is(err, tc.want) {
				t.Fatal("confirmation ignored admission", err)
			}
			before := limits.calls
			input.Binding = ""
			if _, err := svc.StartRequiredEnrollment(context.Background(), input); !errors.Is(err, domain.ErrInvalidCode) || limits.calls != before {
				t.Fatal("missing binding reached dependencies", err)
			}
		})
	}
}

func TestEnrollmentSecretReplacementDoesNotResetGuessingBudget(t *testing.T) {
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	limits := &limitStub{allowed: true}
	repo := &loginRepoStub{proof: PrimaryProof{UserID: "11111111-1111-4111-8111-111111111111"}}
	svc, err := NewLogin(repo, cipher, totp.Authenticator{}, limits, tokengenerate.New(), loginTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	input := ConfirmLoginEnrollmentInput{LoginEnrollmentInput: LoginEnrollmentInput{Challenge: strings.Repeat("A", 43), Binding: strings.Repeat("A", 43)}, Token: strings.Repeat("A", 43), Code: "123456"}
	if _, err := svc.ConfirmRequiredEnrollment(context.Background(), input); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatal("repository error not propagated", err)
	}
	input.Token, err = randomLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConfirmRequiredEnrollment(context.Background(), input); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatal("replacement bypassed repository", err)
	}
	if len(limits.keys) != 10 || !slices.Equal(limits.keys[:5], limits.keys[5:]) || limits.counts[4] != 5 || limits.counts[9] != 5 {
		t.Fatal("replacement changed the flow/user guessing counters", limits.counts)
	}
	input.Challenge, err = randomLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConfirmRequiredEnrollment(context.Background(), input); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatal(err)
	}
	if len(limits.keys) != 15 || !slices.Equal(limits.keys[3:5], limits.keys[13:15]) {
		t.Fatal("new primary reset the shared user guessing cap")
	}
}
