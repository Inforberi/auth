package service

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (s *Service) Confirm(ctx context.Context, token, ip string) error {
	if len(token) > 128 {
		return domain.ErrInvalidVerification
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.limit(ctx, "confirm-ip:"+ip, 20, time.Minute); err != nil {
		return err
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return domain.ErrInvalidVerification
	}
	return s.repo.Confirm(ctx, tokenDigest(token))
}
