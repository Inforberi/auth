package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type confirmationStub struct {
	calls  int
	err    error
	expiry time.Time
}

func (s *confirmationStub) ConfirmPassword(ctx context.Context, user accountdomain.UserID, current, expected string, version int64, replacement string) (*sessiondomain.PasswordConfirmation, error) {
	s.calls++
	if _, ok := ctx.Deadline(); !ok || !accountdomain.ValidUserID(user) || current != strings.Repeat("a", 64) || expected != "expected" || version != 2 || replacement == current || len(replacement) != 64 {
		panic("unexpected confirmation inputs")
	}
	return &sessiondomain.PasswordConfirmation{VerifiedAt: now, ExpiresAt: s.expiry}, s.err
}

type reauthenticationLimitStub struct {
	err   error
	calls int
}

func (s *reauthenticationLimitStub) AllowUser(context.Context, accountdomain.UserID, string) error {
	s.calls++
	return s.err
}

func TestPasswordReauthentication(t *testing.T) {
	user := accountdomain.UserID("11111111-1111-4111-8111-111111111111")
	for _, tc := range []struct {
		name                            string
		readErr, compareErr, confirmErr error
	}{
		{"success", nil, nil, nil},
		{"no password method", domain.ErrNotFound, nil, nil},
		{"SQL read failure", errors.New("SQL"), nil, nil},
		{"wrong password", nil, errors.New("wrong"), nil},
		{"hash busy", nil, domain.ErrHashBusy, nil},
		{"cancelled", nil, context.Canceled, nil},
		{"stale confirmation", nil, nil, sessiondomain.ErrSessionNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, hash := &mockPasswordRepo{}, &mockHasher{}
			repo.On("FindUserByUserID", mock.Anything, user).Return(&domain.Credential{PasswordHash: "expected", AuthVersion: 2}, tc.readErr)
			if tc.readErr == nil {
				hash.On("Compare", "current", "expected").Return(tc.compareErr)
			}
			ledger := &confirmationStub{err: tc.confirmErr, expiry: now.Add(time.Minute)}
			s := NewReauthentication(repo, ledger, hash, &reauthenticationLimitStub{}, tokengenerate.New(), 5*time.Minute)
			result, err := s.Confirm(t.Context(), user, strings.Repeat("a", 64), "current", "ip")
			if tc.readErr == nil && tc.compareErr == nil && tc.confirmErr == nil {
				if err != nil || result == nil || !result.ValidUntil.Equal(ledger.expiry) || len(result.Token) != 43 {
					t.Fatal(result, err)
				}
				encoded, _ := json.Marshal(result)
				if strings.Contains(string(encoded), result.Token) {
					t.Fatal("serialized raw token")
				}
			} else if err == nil || result != nil {
				t.Fatal("failure exposed proof", result, err)
			}
			if tc.readErr != nil || tc.compareErr != nil {
				if ledger.calls != 0 {
					t.Fatal("invalid proof mutated session")
				}
			}
			repo.AssertExpectations(t)
			hash.AssertExpectations(t)
		})
	}
}

func TestReauthenticationBoundsAndLimitsBeforeDependencies(t *testing.T) {
	limit := &reauthenticationLimitStub{}
	s := NewReauthentication(nil, nil, nil, limit, nil, time.Minute)
	user := accountdomain.UserID("11111111-1111-4111-8111-111111111111")
	for _, password := range []string{"", strings.Repeat("x", 1025)} {
		if _, err := s.Confirm(t.Context(), user, strings.Repeat("a", 64), password, "ip"); !errors.Is(err, accountdomain.ErrFreshAuthRequired) || limit.calls != 0 {
			t.Fatal(err)
		}
	}
	for _, failure := range []error{domain.ErrLoginLimited, domain.ErrLoginUnavailable} {
		limit.err = failure
		if _, err := s.Confirm(t.Context(), user, strings.Repeat("a", 64), "password", "ip"); !errors.Is(err, failure) {
			t.Fatal(err)
		}
	}
}
