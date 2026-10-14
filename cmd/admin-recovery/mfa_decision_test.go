package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type mfaOperatorStub struct {
	decision domain.RecoveryDecision
	err      error
	calls    int
}

func (s *mfaOperatorStub) Preview(context.Context, accountdomain.UserID, string) (*mfaservice.RecoveryTarget, error) {
	return &mfaservice.RecoveryTarget{Database: "auth", Operator: "operator", AuthVersion: 7, State: "pending", ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func (s *mfaOperatorStub) Decide(_ context.Context, r domain.RecoveryDecision) error {
	s.calls++
	s.decision = r
	return s.err
}

func TestMFADecisionCLI(t *testing.T) {
	for _, action := range []string{"mfa-approve", "mfa-cancel"} {
		t.Run(action, func(t *testing.T) {
			opts, err := parseMFAOptions([]string{action, "-user", "11111111-1111-4111-8111-111111111111", "-request", "22222222-2222-4222-8222-222222222222", "-environment", "test", "-reason", "INC-42"})
			if err != nil {
				t.Fatal(err)
			}
			svc := &mfaOperatorStub{}
			var output bytes.Buffer
			if err := executeMFA(context.Background(), opts, "localhost:5432", svc, strings.NewReader("yes\n"), &output); err == nil || svc.calls != 0 {
				t.Fatal("implicit confirmation", err)
			}
			confirmation := strings.ToUpper(action) + " test localhost:5432/auth " + string(opts.UserID) + " " + opts.RequestID + " v7\n"
			if err := executeMFA(context.Background(), opts, "localhost:5432", svc, strings.NewReader(confirmation), &output); err != nil || svc.calls != 1 || svc.decision.ExpectedVersion != 7 || svc.decision.Approve != (action == "mfa-approve") {
				t.Fatal("decision", err)
			}
			svc.err = errors.New("postgres://secret:password@db")
			if err := executeMFA(context.Background(), opts, "localhost:5432", svc, strings.NewReader(confirmation), &output); err == nil || strings.Contains(err.Error(), "password@") {
				t.Fatal("secret error leaked", err)
			}
		})
	}
	for _, reason := range []string{"", strings.Repeat("x", 501)} {
		if _, err := parseMFAOptions([]string{"mfa-approve", "-user", "11111111-1111-4111-8111-111111111111", "-request", "22222222-2222-4222-8222-222222222222", "-environment", "test", "-reason", reason}); !errors.Is(err, domain.ErrRecoveryOperatorInput) {
			t.Fatal("reason accepted", err)
		}
	}
}
