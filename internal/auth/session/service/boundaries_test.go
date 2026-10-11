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
