package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	providers "github.com/Inforberi/financial-intelligence/internal/auth/settings/providers/service"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	smtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
)

type Lease interface {
	Close()
	Check(context.Context) error
}

type Repository interface {
	StartConfiguration(context.Context, Prepared) (Lease, error)
}

type ProviderInput struct {
	Name, ClientID string
	Secret         string `json:"-"`
}

type Input struct {
	ConfirmRetentionShortening bool
	Mode                       domain.SourceMode
	Policy                     domain.Policy
	Retention                  domain.RetentionPolicy
	SMTP                       domain.SMTPConfig
	SMTPPassword               string `json:"-"`
	Providers                  [2]ProviderInput
	AllowedSMTP                []string
	RequireTLS                 bool
}

type Prepared struct {
	ConfirmRetentionShortening bool
	Mode                       domain.SourceMode
	KeyBinding                 []byte            `json:"-"`
	Fingerprint                []byte            `json:"-"`
	ComponentHashes            map[string]string `json:"-"`
	Policy                     domain.Policy
	Retention                  domain.RetentionPolicy
	SMTP                       smtp.SMTPStored
	Providers                  [2]providers.ProviderStored
}

func Start(ctx context.Context, repo Repository, input Input, root string, smtpCipher settings.ProviderCipher, providerCiphers map[string]settings.ProviderCipher) (Lease, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := input.Mode.Validate(); err != nil {
		return nil, err
	}
	prepared := Prepared{Mode: input.Mode.Effective(), ComponentHashes: make(map[string]string)}
	if prepared.Mode == domain.SourceAPI {
		return repo.StartConfiguration(ctx, prepared)
	}
	if err := input.Policy.Validate(); err != nil {
		return nil, err
	}
	if err := input.Retention.Validate(); err != nil {
		return nil, err
	}
	if root == "" {
		return nil, domain.ErrSourceConflict
	}
	var err error
	prepared.Policy, prepared.Retention = input.Policy, input.Retention
	prepared.ConfirmRetentionShortening = input.ConfirmRetentionShortening
	prepared.SMTP, err = smtp.NewSMTPSeed(input.SMTP, input.SMTPPassword, input.AllowedSMTP, input.RequireTLS, smtpCipher)
	if err != nil {
		return nil, err
	}
	prepared.Providers, err = prepareProviders(input, providerCiphers)
	if err != nil {
		return nil, err
	}
	// A keyed fingerprint detects fleet disagreement without storing secret hashes for offline guessing.
	payload, err := json.Marshal([]any{
		input.Policy, input.Retention, input.SMTP, input.SMTPPassword,
		input.Providers[0].ClientID, input.Providers[0].Secret, input.Providers[1].ClientID, input.Providers[1].Secret,
	})
	if err != nil {
		return nil, domain.ErrSourceConflict
	}
	defer clear(payload)
	mac := hmac.New(sha256.New, []byte(root))
	_, _ = mac.Write([]byte("auth-settings-source-key:v1"))
	prepared.KeyBinding = mac.Sum(nil)
	mac.Reset()
	_, _ = mac.Write(payload)
	prepared.Fingerprint = mac.Sum(nil)
	prepared.ComponentHashes = make(map[string]string)
	components := map[string]any{"policy": input.Policy, "retention": input.Retention, "smtp": []any{input.SMTP, input.SMTPPassword}}
	for _, p := range input.Providers {
		components[p.Name] = []string{p.ClientID, p.Secret}
	}
	for name, value := range components {
		data, err := json.Marshal(value)
		if err != nil {
			return nil, domain.ErrSourceConflict
		}
		mac.Reset()
		_, _ = mac.Write(data)
		clear(data)
		prepared.ComponentHashes[name] = hex.EncodeToString(mac.Sum(nil))
	}
	return repo.StartConfiguration(ctx, prepared)
}

type sourceContextKey struct{}

// WithSourceMode is for trusted server composition, never a request-supplied override.
func WithSourceMode(ctx context.Context, mode domain.SourceMode) context.Context {
	return context.WithValue(ctx, sourceContextKey{}, mode.Effective())
}

func EnvironmentOwned(ctx context.Context) bool {
	mode, _ := ctx.Value(sourceContextKey{}).(domain.SourceMode)
	return mode == domain.SourceENV
}

func prepareProviders(input Input, providerCiphers map[string]settings.ProviderCipher) ([2]providers.ProviderStored, error) {
	var result [2]providers.ProviderStored
	for i, p := range input.Providers {
		if p.Name != [2]string{"google", "telegram"}[i] {
			return result, domain.ErrInvalidProvider
		}
		if providerCiphers[p.Name] == nil || !domain.ValidProviderSecret(p.Secret) ||
			p.ClientID != "" && !domain.ValidProviderClientID(p.Name, p.ClientID) || p.Secret != "" && p.ClientID == "" {
			return result, domain.ErrInvalidProvider
		}
		enabled := p.Name == "google" && input.Policy.Methods.Google || p.Name == "telegram" && input.Policy.Methods.Telegram
		if enabled && (p.ClientID == "" || p.Secret == "") {
			return result, domain.ErrMethodNotReady
		}
		plain := []byte(p.Secret)
		sealed, sealErr := providerCiphers[p.Name].Seal(plain)
		clear(plain)
		if sealErr != nil {
			return result, domain.ErrInvalidProvider
		}
		result[i] = providers.ProviderStored{ProviderSnapshot: domain.ProviderSnapshot{Provider: p.Name, ClientID: p.ClientID, SecretSet: p.Secret != ""}, Secret: sealed}
	}
	return result, nil
}
