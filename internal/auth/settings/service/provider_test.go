package service

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type providerRepoStub struct {
	ProviderRepository
	stored          ProviderStored
	update          ProviderUpdate
	initializations int
	err             error
}

func (r *providerRepoStub) LoadProvider(context.Context, string) (ProviderStored, error) {
	return r.stored, r.err
}

func (r *providerRepoStub) InitializeProvider(_ context.Context, stored ProviderStored) (ProviderStored, error) {
	r.initializations++
	r.stored = stored
	return stored, nil
}

func (r *providerRepoStub) UpdateProvider(_ context.Context, input ProviderUpdate) (domain.ProviderSnapshot, error) {
	r.update = input
	return r.stored.ProviderSnapshot, r.err
}

func TestProviderSecretBoundaries(t *testing.T) {
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	google, err := secretbox.NewScoped(root, "provider-google:v1")
	if err != nil {
		t.Fatal(err)
	}
	telegram, err := secretbox.NewScoped(root, "provider-telegram:v1")
	if err != nil {
		t.Fatal(err)
	}
	repo := &providerRepoStub{err: domain.ErrNotInitialized}
	s := NewProviders(repo, google, telegram)
	if err := s.Initialize(t.Context(), "google", "", "", true); !errors.Is(err, domain.ErrMethodNotReady) || repo.initializations != 0 {
		t.Fatal("unready enabled seed was persisted", err)
	}
	if err := s.Initialize(t.Context(), "google", "fixture.apps.googleusercontent.com", "synthetic", true); err != nil || repo.initializations != 1 {
		t.Fatal(err)
	}
	repo.err = nil
	if _, secret, err := s.Credentials(t.Context(), "google"); err != nil || secret != "synthetic" {
		t.Fatal("encrypted credential read", err)
	}
	repo.stored.Provider = "telegram"
	repo.stored.ClientID = "123"
	if _, _, err := s.Credentials(t.Context(), "telegram"); err == nil {
		t.Fatal("ciphertext accepted under another provider purpose")
	}
	password := "new-secret"
	input := ProviderUpdateInput{Actor: smtpActor, Provider: "google", ClientID: "fixture.apps.googleusercontent.com", ExpectedVersion: 1, Secret: &password}
	if _, err := s.Update(t.Context(), input); err != nil || string(repo.update.Secret) == password || !repo.update.SecretSet {
		t.Fatal("plaintext secret sent to storage", err)
	}
	for _, name := range []string{"", "github", "Google", "../google"} {
		if _, _, err := s.Credentials(t.Context(), name); !errors.Is(err, domain.ErrInvalidProvider) {
			t.Fatal("unsupported provider accepted", name, err)
		}
	}
	for _, secret := range []string{"bad\r\nsecret", "bad\x00secret"} {
		input.Secret = &secret
		if _, err := s.Update(t.Context(), input); !errors.Is(err, domain.ErrInvalidProvider) {
			t.Fatal("invalid secret accepted", err)
		}
	}
}
