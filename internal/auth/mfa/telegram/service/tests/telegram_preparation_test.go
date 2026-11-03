package service_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatelegram "github.com/Inforberi/financial-intelligence/internal/auth/mfa/telegram/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type telegramRepoStub struct {
	calls        int
	intent       mfatelegram.TelegramIntent
	candidate    mfatelegram.TelegramCandidate
	confirmation mfatelegram.TelegramConfirmation
	payload      []byte
}

func (r *telegramRepoStub) IssueTelegramPreparation(_ context.Context, _ mfaservice.Proof, input mfatelegram.TelegramIntent) (time.Time, error) {
	r.calls++
	r.intent = input
	return time.Now().Add(input.TTL), nil
}

func (r *telegramRepoStub) ReceiveTelegramPreparation(_ context.Context, input mfatelegram.TelegramCandidate) (*mfatelegram.TelegramEnvelope, error) {
	r.calls++
	r.candidate = input
	payload := input.Payload
	if r.payload != nil {
		payload = r.payload
	}
	return &mfatelegram.TelegramEnvelope{TelegramID: input.TelegramID, Payload: payload, ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func (r *telegramRepoStub) ConfirmTelegramPreparation(_ context.Context, _ mfaservice.Proof, input mfatelegram.TelegramConfirmation) (*mfatelegram.TelegramPrepared, error) {
	r.calls++
	r.confirmation = input
	return &mfatelegram.TelegramPrepared{BotID: input.Bot.ID, TelegramID: r.candidate.TelegramID, ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func telegramConfig() mfatelegram.TelegramPreparationConfig {
	return mfatelegram.TelegramPreparationConfig{
		Bot:                    domain.TelegramBotBinding{ID: 123456789, PolicyVersion: 1},
		TTL:                    3 * time.Minute,
		RequestsPerMinute:      100,
		UpdatesPerMinute:       500,
		ConfirmationsPerMinute: 1000,
	}
}

func telegramTestService(t *testing.T, repo *telegramRepoStub, limits *limitStub, purpose string) *mfatelegram.TelegramPreparation {
	t.Helper()
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), purpose)
	require.NoError(t, err)
	svc, err := mfatelegram.NewTelegramPreparation(repo, cipher, limits, tokengenerate.New(), telegramConfig())
	require.NoError(t, err)
	return svc
}

func telegramProof() mfaservice.Proof {
	return mfaservice.Proof{UserID: "d8800000-0000-4000-8000-000000000088", TokenHash: tokengenerate.New().Hash("source-session"), AuthVersion: 1}
}

func TestTelegramPreparationContracts(t *testing.T) {
	repo, limits := &telegramRepoStub{}, &limitStub{allowed: true}
	svc := telegramTestService(t, repo, limits, "telegram-channel:project-a:v1")
	started, err := svc.Request(t.Context(), telegramProof(), "192.0.2.1")
	require.NoError(t, err)
	require.NotEqual(t, started.Binding, repo.intent.Digest)
	delivery, err := svc.Receive(t.Context(), mfatelegram.TelegramStart{BotID: 123456789, TelegramID: 1 << 40, UpdateID: 1, Binding: started.Binding})
	require.NoError(t, err)
	require.True(t, domain.ValidTelegramCode(delivery.Code))
	require.Equal(t, repo.intent.Digest, repo.candidate.Digest)
	require.NotEqual(t, delivery.Code, repo.candidate.Verifier)
	encoded, err := json.Marshal(delivery)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), delivery.Code)
	prepared, err := svc.Confirm(t.Context(), mfatelegram.ConfirmTelegramChannel{Proof: telegramProof(), Binding: started.Binding, Code: delivery.Code, IP: "192.0.2.1"})
	require.NoError(t, err)
	require.Equal(t, repo.candidate.Verifier, repo.confirmation.Verifier)
	require.Equal(t, tokengenerate.New().Hash(prepared.Token), repo.confirmation.SessionHash)
	require.NotEqual(t, telegramProof().TokenHash, repo.confirmation.SessionHash)
}

func TestTelegramPreparationAdmission(t *testing.T) {
	binding := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, fail := range []struct {
		name    string
		allowed bool
		err     error
		want    error
	}{{"limited", false, nil, domain.ErrLimited}, {"redis failure", true, errors.New("synthetic Redis error"), domain.ErrUnavailable}} {
		t.Run(fail.name, func(t *testing.T) {
			repo, limits := &telegramRepoStub{}, &limitStub{allowed: fail.allowed, err: fail.err}
			svc := telegramTestService(t, repo, limits, "telegram-channel:test:v1")
			_, err := svc.Request(t.Context(), telegramProof(), "192.0.2.1")
			require.ErrorIs(t, err, fail.want)
			_, err = svc.Receive(t.Context(), mfatelegram.TelegramStart{BotID: 123456789, TelegramID: 1, UpdateID: 1, Binding: binding})
			require.ErrorIs(t, err, fail.want)
			_, err = svc.Confirm(t.Context(), mfatelegram.ConfirmTelegramChannel{Proof: telegramProof(), Binding: binding, Code: "12345678", IP: "192.0.2.1"})
			require.ErrorIs(t, err, fail.want)
			require.Zero(t, repo.calls, "admission failure must precede all SQL work")
		})
	}
}

func TestTelegramPreparationScopeAndInput(t *testing.T) {
	repo, limits := &telegramRepoStub{}, &limitStub{allowed: true}
	svc := telegramTestService(t, repo, limits, "telegram-channel:project-a:v1")
	binding := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, input := range []mfatelegram.TelegramStart{
		{BotID: 2, TelegramID: 1, Binding: binding},
		{BotID: 123456789, TelegramID: 0, Binding: binding},
		{BotID: 123456789, TelegramID: 1 << 52, Binding: binding},
		{BotID: 123456789, TelegramID: 1, UpdateID: -1, Binding: binding},
		{BotID: 123456789, TelegramID: 1, Binding: "short"},
	} {
		_, err := svc.Receive(t.Context(), input)
		require.ErrorIs(t, err, domain.ErrInvalidTelegramPreparation)
	}
	_, err := svc.Request(t.Context(), mfaservice.Proof{}, "192.0.2.1")
	require.ErrorIs(t, err, domain.ErrProofRequired)
	_, err = svc.Request(t.Context(), telegramProof(), "invalid IP")
	require.ErrorIs(t, err, domain.ErrInvalidTelegramPreparation)
	require.Zero(t, repo.calls)
	input := mfatelegram.TelegramStart{BotID: 123456789, TelegramID: 1, Binding: binding}
	_, err = svc.Receive(t.Context(), input)
	require.NoError(t, err)
	repo.payload = repo.candidate.Payload
	foreign := telegramTestService(t, repo, limits, "telegram-channel:project-b:v1")
	_, err = foreign.Receive(t.Context(), input)
	require.ErrorIs(t, err, domain.ErrUnavailable, "another project must not decrypt a channel's delivery payload")
}

func TestTelegramPreparationConfiguration(t *testing.T) {
	for _, change := range []func(*mfatelegram.TelegramPreparationConfig){
		func(c *mfatelegram.TelegramPreparationConfig) { c.Bot.ID = 0 },
		func(c *mfatelegram.TelegramPreparationConfig) { c.Bot.PolicyVersion = 0 },
		func(c *mfatelegram.TelegramPreparationConfig) { c.TTL = 30 * time.Second },
		func(c *mfatelegram.TelegramPreparationConfig) { c.TTL = 6 * time.Minute },
		func(c *mfatelegram.TelegramPreparationConfig) { c.RequestsPerMinute = 0 },
		func(c *mfatelegram.TelegramPreparationConfig) { c.UpdatesPerMinute = 0 },
		func(c *mfatelegram.TelegramPreparationConfig) { c.ConfirmationsPerMinute = 0 },
	} {
		cfg := telegramConfig()
		change(&cfg)
		require.ErrorIs(t, cfg.Validate(), domain.ErrUnavailable)
	}
}
