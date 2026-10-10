package service

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func (r *RecoveryService) Reset(ctx context.Context, token, password, confirmation, ip string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := r.limit(ctx, "reset-ip:"+ip, 10, time.Minute); err != nil {
		return err
	}
	if err := r.limit(ctx, "reset-global", 100, time.Minute); err != nil {
		return err
	}
	if len(token) != 43 {
		return domain.ErrInvalidReset
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return domain.ErrInvalidReset
	}
	if password != confirmation {
		return domain.ErrPasswordConfirmation
	}
	if err := domain.ValidatePassword(password); err != nil {
		return err
	}
	select {
	case r.hashSlots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	hash, err := r.hash.GenerateHash([]byte(password))
	<-r.hashSlots
	if err != nil {
		return err
	}
	return r.repo.ConsumeReset(ctx, resetDigest(token), hash)
}
