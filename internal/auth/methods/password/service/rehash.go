package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func (l *PasswordService) rehash(ctx context.Context, credential *domain.Credential, password string) error {
	if !l.hash.NeedsRehash(credential.PasswordHash) {
		return nil
	}
	hash, err := l.hash.GenerateHash(ctx, []byte(password))
	if errors.Is(err, domain.ErrHashBusy) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("generate replacement hash: %w", err)
	}
	if err := l.repo.RehashPassword(ctx, credential.UserID, credential.AuthVersion, credential.PasswordHash, hash); err != nil {
		return fmt.Errorf("rehash password: %w", err)
	}
	return nil
}
