package service

import (
	"context"
	"errors"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type ProviderUpdateInput struct {
	Actor              accessservice.Principal
	Provider, ClientID string
	ExpectedVersion    int64
	Secret             *string `json:"-"`
}

func (s *Providers) Update(ctx context.Context, input ProviderUpdateInput) (domain.ProviderSnapshot, error) {
	if input.Actor.Validate() != nil {
		return domain.ProviderSnapshot{}, accessdomain.ErrForbidden
	}
	update, err := s.PrepareUpdate(input)
	if err != nil {
		return domain.ProviderSnapshot{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.UpdateProvider(ctx, update)
}

func (s *Providers) PrepareUpdate(input ProviderUpdateInput) (ProviderUpdate, error) {
	if !domain.ValidProvider(input.Provider) || input.ExpectedVersion < 1 || input.ClientID != "" && !domain.ValidProviderClientID(input.Provider, input.ClientID) {
		return ProviderUpdate{}, domain.ErrInvalidProvider
	}
	update := ProviderUpdate{Actor: input.Actor, Provider: input.Provider, ClientID: input.ClientID, ExpectedVersion: input.ExpectedVersion}
	if input.Secret != nil {
		if !domain.ValidProviderSecret(*input.Secret) {
			return ProviderUpdate{}, domain.ErrInvalidProvider
		}
		var err error
		update.Secret, err = s.ciphers[input.Provider].Seal([]byte(*input.Secret))
		if err != nil {
			return ProviderUpdate{}, errors.New("provider secret encryption unavailable")
		}
		update.SecretSet = *input.Secret != ""
	}
	return update, nil
}

// Replacement resolves encrypted credentials against the current locked snapshot.
// A nil Secret preserves credentials only for the same client.
func (input ProviderUpdate) Replacement(before ProviderStored, enabled bool) ([]byte, bool, error) {
	secret, set := input.Secret, input.SecretSet
	if secret == nil {
		if before.ClientID != input.ClientID {
			return nil, false, domain.ErrInvalidProvider
		}
		secret, set = before.Secret, before.SecretSet
	}
	if enabled && (!set || input.ClientID == "" || before.ClientID != input.ClientID) {
		return nil, false, domain.ErrMethodNotReady
	}
	if set && input.ClientID == "" {
		return nil, false, domain.ErrInvalidProvider
	}
	return secret, set, nil
}
