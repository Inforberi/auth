package session_service

import (
	"context"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/config"
	session_redis "github.com/Inforberi/financial-intelligence/internal/featers/session/repo/redis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestCreateSession(t *testing.T) {
	userAgent := "mobile"
	ip := "12345"
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	cfg := config.SessionConfig{
		SessionTTL:              7 * 24 * time.Hour,
		SessionRefreshThreshold: 24 * time.Hour,
		AbsoluteSessionTTL:      14 * 24 * time.Hour,
	}

	tests := []struct {
		name       string
		setupMocks func(repo *mockRepo, token *mockTokenHash, clock *mockClock)
		wantErr    error
	}{
		{
			name: "Позитивное создание сессии",
			setupMocks: func(repo *mockRepo, token *mockTokenHash, clock *mockClock) {
				token.
					On("GenerateSessionToken").
					Return("RawToken", nil)

				token.
					On("Hash", "RawToken").
					Return("HashedToken", nil)

				expected := session_redis.CreateSessionParams{
					UserID:    "user-1",
					CreatedAt: now,
					ExpiresAt: now.Add(cfg.SessionTTL),
					TokenHash: "HashedToken",
					UserAgent: userAgent,
					IPAddress: ip,
				}

				clock.
					On("NowUTC").
					Return(now)

				repo.
					On(
						"CreateSession",
						mock.Anything,
						expected,
					).
					Return(nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockRepo{}
			token := &mockTokenHash{}
			clock := &mockClock{}

			tt.setupMocks(repo, token, clock)

			svc := New(clock, repo, token, cfg)

			session, err := svc.CreateSession(
				context.Background(),
				"user-1",
				userAgent,
				ip,
			)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				return

			}

			assert.Equal(t, "RawToken", session.RawToken)

			assert.Equal(
				t,
				now.Add(cfg.SessionTTL),
				session.ExpiresAt,
			)

			assert.NoError(t, err)
			assert.NotNil(t, session)
		})
	}
}
