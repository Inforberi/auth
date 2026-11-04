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
	if !domain.ValidProvider(input.Provider) || input.ExpectedVersion < 1 || input.ClientID != "" && !domain.ValidProviderClientID(input.Provider, input.ClientID) {
		return domain.ProviderSnapshot{}, domain.ErrInvalidProvider
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	update := ProviderUpdate{Actor: input.Actor, Provider: input.Provider, ClientID: input.ClientID, ExpectedVersion: input.ExpectedVersion}
	if input.Secret != nil {
		if !domain.ValidProviderSecret(*input.Secret) {
			return domain.ProviderSnapshot{}, domain.ErrInvalidProvider
		}
		var err error
		update.Secret, err = s.ciphers[input.Provider].Seal([]byte(*input.Secret))
		if err != nil {
			return domain.ProviderSnapshot{}, errors.New("provider secret encryption unavailable")
		}
		update.SecretSet = *input.Secret != ""
	}
	return s.repo.UpdateProvider(ctx, update)
}
