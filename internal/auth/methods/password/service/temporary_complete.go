package service

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func (s *TemporaryPasswordService) Complete(ctx context.Context, token, password, confirmation, ip string) error {
	if !s.cfg.Enabled {
		return domain.ErrTemporaryPasswordDisabled
	}
	if len(token) != 43 {
		return domain.ErrInvalidTemporaryPassword
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return domain.ErrInvalidTemporaryPassword
	}
	if password != confirmation {
		return domain.ErrPasswordConfirmation
	}
	if err := domain.ValidatePassword(password); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.limit(ctx, "temporary-password-setup-ip:"+ip, 10); err != nil {
		return err
	}
	if err := s.limit(ctx, "temporary-password-setup-project", s.cfg.SetupProjectAttemptsPerMinute); err != nil {
		return err
	}
	credential, err := s.repo.CheckTemporarySetup(ctx, resetDigest(token))
	if err != nil {
		return err
	}
	// Only server-generated 256-bit secrets use this fingerprint, never user passwords.
	// It survives key rotation and rejects reuse without a second Argon2 computation.
	digest := resetDigest("temporary-password-secret:v1:" + password)
	if subtle.ConstantTimeCompare([]byte(digest), []byte(credential.SecretDigest)) == 1 {
		return domain.ErrTemporaryPasswordReuse
	}
	hash, err := s.hash.GenerateHash(ctx, []byte(password))
	if err != nil {
		return err
	}
	return s.repo.CompleteTemporary(ctx, resetDigest(token), hash)
}
