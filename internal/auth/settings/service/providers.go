package service

import (
	"context"
	"errors"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type ProviderStored struct {
	domain.ProviderSnapshot
	Secret []byte `json:"-"`
}

type ProviderUpdate struct {
	Actor              accessservice.Principal
	Provider, ClientID string
	ExpectedVersion    int64
	Secret             []byte `json:"-"`
	SecretSet          bool
}

type ProviderRepository interface {
	LoadProvider(context.Context, string) (ProviderStored, error)
	InitializeProvider(context.Context, ProviderStored) (ProviderStored, error)
	ReadProvider(context.Context, accessservice.Principal, string) (domain.ProviderSnapshot, error)
	UpdateProvider(context.Context, ProviderUpdate) (domain.ProviderSnapshot, error)
}

type ProviderCipher interface {
	Seal([]byte) ([]byte, error)
	Open([]byte) ([]byte, error)
}

type Providers struct {
	repo    ProviderRepository
	ciphers map[string]ProviderCipher
}

func NewProviders(repo ProviderRepository, google, telegram ProviderCipher) *Providers {
	return &Providers{repo: repo, ciphers: map[string]ProviderCipher{"google": google, "telegram": telegram}}
}

func (s *Providers) Initialize(ctx context.Context, name, clientID, secret string, required bool) error {
	if !domain.ValidProvider(name) {
		return domain.ErrInvalidProvider
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stored, err := s.repo.LoadProvider(ctx, name)
	if errors.Is(err, domain.ErrNotInitialized) {
		if required && (clientID == "" || secret == "") {
			return domain.ErrMethodNotReady
		}
		if clientID != "" && !domain.ValidProviderClientID(name, clientID) || !domain.ValidProviderSecret(secret) || secret != "" && clientID == "" {
			return domain.ErrInvalidProvider
		}
		encrypted, err := s.ciphers[name].Seal([]byte(secret))
		if err != nil {
			return errors.New("provider secret encryption unavailable")
		}
		stored, err = s.repo.InitializeProvider(ctx, ProviderStored{ProviderSnapshot: domain.ProviderSnapshot{Provider: name, ClientID: clientID, SecretSet: secret != ""}, Secret: encrypted})
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	_, err = s.open(stored)
	return err
}

func (s *Providers) open(stored ProviderStored) (string, error) {
	if !domain.ValidProvider(stored.Provider) {
		return "", domain.ErrInvalidProvider
	}
	plain, err := s.ciphers[stored.Provider].Open(stored.Secret)
	if err != nil {
		return "", errors.New("provider secret cannot be decrypted")
	}
	defer clear(plain)
	secret := string(plain)
	if !domain.ValidProviderSecret(secret) || stored.SecretSet != (secret != "") || stored.ClientID != "" && !domain.ValidProviderClientID(stored.Provider, stored.ClientID) || stored.SecretSet && stored.ClientID == "" {
		return "", domain.ErrInvalidProvider
	}
	return secret, nil
}

// Credentials returns a per-operation snapshot for trusted adapters, not HTTP.
func (s *Providers) Credentials(ctx context.Context, name string) (domain.ProviderSnapshot, string, error) {
	if !domain.ValidProvider(name) {
		return domain.ProviderSnapshot{}, "", domain.ErrInvalidProvider
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stored, err := s.repo.LoadProvider(ctx, name)
	if err != nil {
		return domain.ProviderSnapshot{}, "", err
	}
	secret, err := s.open(stored)
	if err != nil {
		return domain.ProviderSnapshot{}, "", err
	}
	return stored.ProviderSnapshot, secret, nil
}

func (s *Providers) Read(ctx context.Context, actor accessservice.Principal, name string) (domain.ProviderSnapshot, error) {
	if actor.Validate() != nil {
		return domain.ProviderSnapshot{}, accessdomain.ErrForbidden
	}
	if !domain.ValidProvider(name) {
		return domain.ProviderSnapshot{}, domain.ErrInvalidProvider
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.ReadProvider(ctx, actor, name)
}
