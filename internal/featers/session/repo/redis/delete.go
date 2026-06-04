package session_redis

import (
	"context"
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
)

func (s *SessionRepo) DeleteSession(ctx context.Context, tokenHash string, userID domain.UserID) error {
	sessionKey := sessionKey(tokenHash)
	userSessionsKey := userSessionsKey(userID)

	pipe := s.db.TxPipeline()

	pipe.Del(ctx, sessionKey)

	pipe.SRem(ctx, userSessionsKey, sessionKey)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("Err delete session in redis %w", err)
	}

	return nil
}

func (s *SessionRepo) DeleteAllSessions(ctx context.Context, userID domain.UserID) error {
	userSessionsKey := userSessionsKey(userID)

	sessions, err := s.db.SMembers(ctx, userSessionsKey).Result()
	if err != nil {
		return fmt.Errorf("get user sessions: %w", err)
	}

	pipe := s.db.TxPipeline()

	if len(sessions) > 0 {
		pipe.Del(ctx, sessions...)
	}

	pipe.Del(ctx, userSessionsKey)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("delete all session err %w", err)
	}

	return nil
}

func (s *SessionRepo) DeleteAllSessionsExcept(ctx context.Context, userID domain.UserID, tokenHash string) error {
	userSessionsKey := userSessionsKey(userID)

	sessions, err := s.db.SMembers(
		ctx,
		userSessionsKey,
	).Result()
	if err != nil {
		return fmt.Errorf("get user sessions: %w", err)
	}

	currentSessionKey := sessionKey(tokenHash)

	members := make([]string, 0, len(sessions))

	for _, session := range sessions {
		if session == currentSessionKey {
			continue
		}

		members = append(
			members,
			session,
		)
	}

	pipe := s.db.TxPipeline()

	if len(members) > 0 {
		pipe.Del(
			ctx,
			members...,
		)

		values := make([]interface{}, 0, len(members))

		for _, member := range members {
			values = append(values, member)
		}

		pipe.SRem(
			ctx,
			userSessionsKey,
			values...,
		)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf(
			"delete all sessions except: %w",
			err,
		)
	}

	return nil
}
