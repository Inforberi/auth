package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"

	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

func TestSessionExpiryEquality(t *testing.T) {
	for _, absolute := range []bool{false, true} {
		repo := &mockRepo{}
		token := &mockTokenHash{}
		clock := &mockClock{}
		session := &sessiondomain.Session{UserID: "user", CreatedAt: now, ExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(time.Hour)}
		if absolute {
			session.AbsoluteExpiresAt = now
		} else {
			session.ExpiresAt = now
		}
		repo.On("FindSession", mock.Anything, "hash").Return(session, nil)
		token.On("Hash", "raw").Return("hash")
		clock.On("NowUTC").Return(now)
		_, err := New(clock, repo, token, cfg).ValidateSession(context.Background(), "raw")
		if !errors.Is(err, sessiondomain.ErrSessionExpired) {
			t.Fatal("boundary expiry accepted", err)
		}
	}
}

func TestSessionRefreshClamped(t *testing.T) {
	repo := &mockRepo{}
	token := &mockTokenHash{}
	clock := &mockClock{}
	absolute := now.Add(time.Hour)
	session := &sessiondomain.Session{UserID: "user", CreatedAt: now, ExpiresAt: now.Add(time.Minute), AbsoluteExpiresAt: absolute}
	repo.On("FindSession", mock.Anything, "hash").Return(session, nil)
	repo.On("RefreshSession", mock.Anything, "hash", mock.MatchedBy(func(s *sessiondomain.Session) bool { return s.ExpiresAt.Equal(absolute) }), session.ExpiresAt).Return(true, nil)
	token.On("Hash", "raw").Return("hash")
	clock.On("NowUTC").Return(now)
	result, err := New(clock, repo, token, cfg).ValidateSession(context.Background(), "raw")
	if err != nil || !result.Extended || !result.ExpiresAt.Equal(absolute) {
		t.Fatal("refresh exceeded absolute deadline", err)
	}
	repo.AssertExpectations(t)
}

func TestAdministrativeReadsDoNotRefresh(t *testing.T) {
	for _, refresh := range []bool{true, false} {
		repo, token, clock := &mockRepo{}, &mockTokenHash{}, &mockClock{}
		proof := now.Add(-time.Minute)
		session := &sessiondomain.Session{
			UserID: "user", CreatedAt: now.Add(-time.Hour),
			ExpiresAt: now.Add(time.Second), AbsoluteExpiresAt: now.Add(time.Hour), IdleTimeoutSeconds: 1800,
			PrimaryVerifiedAt: &proof, MFAVerifiedAt: &proof,
		}
		repo.On("FindSession", mock.Anything, "hash").Return(session, nil)
		token.On("Hash", "raw").Return("hash")
		clock.On("NowUTC").Return(now)
		result, err := New(clock, repo, token, cfg).validateSession(t.Context(), "raw", refresh)
		if err != nil || result.Extended || !result.ExpiresAt.Equal(session.ExpiresAt) ||
			!result.PrimaryVerifiedAt.Equal(proof) || !result.MFAVerifiedAt.Equal(proof) {
			t.Fatal("background read renewed administrative session/proof", result, err)
		}
		repo.AssertNotCalled(t, "RefreshSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	}
}

func TestAbsoluteExpiryDoesNotWrite(t *testing.T) {
	repo, token, clock := &mockRepo{}, &mockTokenHash{}, &mockClock{}
	absolute := now.Add(time.Hour)
	session := &sessiondomain.Session{UserID: "user", CreatedAt: now.Add(-time.Hour), ExpiresAt: absolute, AbsoluteExpiresAt: absolute}
	repo.On("FindSession", mock.Anything, "hash").Return(session, nil)
	token.On("Hash", "raw").Return("hash")
	clock.On("NowUTC").Return(now)
	result, err := New(clock, repo, token, cfg).ValidateSession(t.Context(), "raw")
	if err != nil || result.Extended || !result.ExpiresAt.Equal(absolute) {
		t.Fatal(result, err)
	}
	repo.AssertNotCalled(t, "RefreshSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestValidationWithoutRefreshDoesNotWrite(t *testing.T) {
	repo, token, clock := &mockRepo{}, &mockTokenHash{}, &mockClock{}
	expiry := now.Add(time.Minute)
	session := &sessiondomain.Session{UserID: "user", CreatedAt: now, ExpiresAt: expiry, AbsoluteExpiresAt: now.Add(time.Hour)}
	repo.On("FindSession", mock.Anything, "hash").Return(session, nil)
	token.On("Hash", "raw").Return("hash")
	clock.On("NowUTC").Return(now)
	result, err := New(clock, repo, token, cfg).ValidateSessionWithoutRefresh(t.Context(), "raw")
	if err != nil || result.Extended || !result.ExpiresAt.Equal(expiry) {
		t.Fatal(result, err)
	}
	repo.AssertNotCalled(t, "RefreshSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestSessionRefreshUsesPersistedAbsoluteDeadline(t *testing.T) {
	for _, test := range []struct {
		name     string
		config   Config
		expected time.Time
	}{
		{"shorter defaults do not expire an issued session", Config{SessionTTL: 30 * time.Minute, AbsoluteSessionTTL: time.Hour, SessionRefreshThreshold: 10 * time.Minute}, now.Add(30 * time.Minute)},
		{"longer defaults do not extend its absolute deadline", Config{SessionTTL: 24 * time.Hour, AbsoluteSessionTTL: 48 * time.Hour, SessionRefreshThreshold: time.Hour}, now.Add(2 * time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo, token, clock := &mockRepo{}, &mockTokenHash{}, &mockClock{}
			proof := now.Add(-10 * time.Minute)
			session := &sessiondomain.Session{
				UserID: "user", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(time.Minute),
				AbsoluteExpiresAt: now.Add(2 * time.Hour), PrimaryMethod: "password",
				PrimaryVerifiedAt: &proof, MFAVerifiedAt: &proof,
			}
			repo.On("FindSession", mock.Anything, "hash").Return(session, nil)
			repo.On("RefreshSession", mock.Anything, "hash", mock.MatchedBy(func(s *sessiondomain.Session) bool {
				return s.ExpiresAt.Equal(test.expected) && s.AbsoluteExpiresAt.Equal(now.Add(2*time.Hour)) &&
					s.PrimaryVerifiedAt.Equal(proof) && s.MFAVerifiedAt.Equal(proof)
			}), session.ExpiresAt).Return(true, nil)
			token.On("Hash", "raw").Return("hash")
			clock.On("NowUTC").Return(now)
			result, err := New(clock, repo, token, test.config).ValidateSession(t.Context(), "raw")
			if err != nil || !result.Extended || !result.ExpiresAt.Equal(test.expected) ||
				!result.PrimaryVerifiedAt.Equal(proof) || !result.MFAVerifiedAt.Equal(proof) {
				t.Fatal("refresh changed lifetime or authentication proof", result, err)
			}
			repo.AssertExpectations(t)
		})
	}
}
