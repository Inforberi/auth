package service_test

import (
	"context"
	"errors"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type limitStub struct {
	calls   int
	allowed bool
	err     error
	keys    []string
	counts  []int
}

func (l *limitStub) Allow(_ context.Context, key string, count int, _ time.Duration) (bool, error) {
	l.calls++
	l.keys = append(l.keys, key)
	l.counts = append(l.counts, count)
	return l.allowed, l.err
}

func (l *limitStub) AllowAll(_ context.Context, budgets []mfaservice.Budget) (bool, error) {
	for _, budget := range budgets {
		l.calls++
		l.keys = append(l.keys, budget.Key)
		l.counts = append(l.counts, budget.Count)
	}
	return l.allowed, l.err
}

type loginRepoStub struct {
	err       error
	calls     int
	proof     mfaservice.PrimaryProof
	digest    string
	binding   string
	completed mfalogin.LoginCompletion
	recovery  string
	target    mfaservice.NativeTarget
}

func (r *loginRepoStub) FindLoginOwner(context.Context, string, string) (accountdomain.UserID, error) {
	return r.proof.UserID, r.err
}

func (r *loginRepoStub) FindNativeLoginOwner(ctx context.Context, digest, binding string) (accountdomain.UserID, error) {
	return r.FindLoginOwner(ctx, digest, binding)
}

func (r *loginRepoStub) SaveNativeLoginChallenge(ctx context.Context, p mfaservice.PrimaryProof, target mfaservice.NativeTarget, digest, binding string, ttl time.Duration) (*mfalogin.LoginChallengeState, error) {
	r.target = target
	return r.SaveLoginChallenge(ctx, p, digest, binding, ttl)
}

func (r *loginRepoStub) SaveLoginChallenge(_ context.Context, proof mfaservice.PrimaryProof, digest, binding string, ttl time.Duration) (*mfalogin.LoginChallengeState, error) {
	r.calls++
	r.proof, r.digest, r.binding = proof, digest, binding
	return &mfalogin.LoginChallengeState{ExpiresAt: time.Now().Add(ttl)}, r.err
}

func (r *loginRepoStub) SaveLoginEnrollment(context.Context, mfalogin.LoginEnrollmentParams) (time.Time, error) {
	return time.Time{}, errors.New("unexpected enrollment call")
}

func (r *loginRepoStub) ConfirmLoginEnrollment(context.Context, mfalogin.LoginEnrollmentParams, mfaservice.Check, []string) error {
	return domain.ErrUnavailable
}

func (r *loginRepoStub) CompleteLogin(_ context.Context, input mfalogin.LoginCompletion, factor mfalogin.LoginFactor) (*mfalogin.LoginCommit, error) {
	r.calls++
	r.completed = input
	_, r.recovery = factor(r.proof.UserID)
	if r.err != nil {
		return nil, r.err
	}
	return &mfalogin.LoginCommit{UserID: r.proof.UserID, ExpiresAt: time.Now().Add(time.Hour), MFAVerified: time.Now()}, nil
}

func loginTestConfig() mfaservice.LoginConfig {
	return mfaservice.LoginConfig{
		ChallengeTTL: 5 * time.Minute, SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour,
		UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 500,
	}
}
