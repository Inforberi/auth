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
	repo.On("UpdateSession", mock.Anything, "hash", mock.MatchedBy(func(s *sessiondomain.Session) bool { return s.ExpiresAt.Equal(absolute) }), time.Hour).Return(nil)
	token.On("Hash", "raw").Return("hash")
	clock.On("NowUTC").Return(now)
	result, err := New(clock, repo, token, cfg).ValidateSession(context.Background(), "raw")
	if err != nil || !result.Extended || !result.ExpiresAt.Equal(absolute) {
		t.Fatal("refresh exceeded absolute deadline", err)
	}
	repo.AssertExpectations(t)
}
