package service

import (
	"context"
	"errors"
	"testing"
	"time"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type factorLoginRepoStub struct {
	emailLoginRepository
	reads int
}

func (r *factorLoginRepoStub) EmailLoginChannel(context.Context, mfaservice.PrimaryProof) (EmailLoginChannel, error) {
	r.reads++
	return EmailLoginChannel{}, mfadomain.ErrUnavailable
}

type factorLoginLimit struct {
	allowed bool
	err     error
}

func (l *factorLoginLimit) Allow(context.Context, string, int, time.Duration) (bool, error) {
	return l.allowed, l.err
}

func (l *factorLoginLimit) AllowAll(context.Context, []mfaservice.Budget) (bool, error) {
	return l.allowed, l.err
}

func TestEmailFactorLoginAdmission(t *testing.T) {
	box, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	repo, limits := &factorLoginRepoStub{}, &factorLoginLimit{}
	svc, err := NewEmailLogin(repo, box, box, limits, tokengenerate.New(), mfaservice.LoginConfig{
		ChallengeTTL: time.Minute, SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour,
		UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	proof := mfaservice.PrimaryProof{UserID: "11111111-1111-4111-8111-111111111111", AuthVersion: 1, Method: "password", Reference: "verified-hash", VerifiedAt: time.Now()}
	if _, err := svc.Start(context.Background(), proof, "192.0.2.1"); !errors.Is(err, mfadomain.ErrLimited) {
		t.Fatal(err)
	}
	limits.err = errors.New("Redis unavailable")
	if _, err := svc.Start(context.Background(), proof, "192.0.2.1"); !errors.Is(err, mfadomain.ErrUnavailable) {
		t.Fatal(err)
	}
	limits.allowed, limits.err = true, nil
	for _, method := range []string{"emailotp", "oidc"} {
		proof.Method = method
		if _, err := svc.Start(context.Background(), proof, "192.0.2.1"); !errors.Is(err, mfadomain.ErrProofRequired) {
			t.Fatal("dependent primary accepted", err)
		}
	}
	proof.Method, proof.Administrative = "password", true
	if _, err := svc.Start(context.Background(), proof, "192.0.2.1"); !errors.Is(err, mfadomain.ErrProofRequired) {
		t.Fatal("administrative primary accepted by the ordinary email flow", err)
	}
	if repo.reads != 0 {
		t.Fatal("admission or invalid primary reached storage")
	}
}
