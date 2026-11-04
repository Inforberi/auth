package service_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingssmtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type failedSMTPSeedCipher struct{}

func (failedSMTPSeedCipher) Seal([]byte) ([]byte, error) {
	return nil, errors.New("private cipher details")
}

func (failedSMTPSeedCipher) Open([]byte) ([]byte, error) { return nil, errors.New("not used") }

func TestSMTPSeed(t *testing.T) {
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "project-fixture:smtp-settings:v1")
	require.NoError(t, err)
	config := domain.SMTPConfig{Host: "smtp.example.test", Port: 587, Username: "fixture", From: "auth@example.test", Domain: "example.test", RequireTLS: true}
	seed, err := settingssmtp.NewSMTPSeed(config, "fixture-password", []string{"smtp.example.test:587"}, true, cipher)
	require.NoError(t, err)
	require.Equal(t, config, seed.Config)
	require.Zero(t, seed.Version, "SQL chooses the initial version")
	require.True(t, seed.PasswordSet)
	require.NotContains(t, string(seed.Password), "fixture-password")
	plain, err := cipher.Open(seed.Password)
	require.NoError(t, err)
	require.Equal(t, "fixture-password", string(plain))
	clear(plain)
	for _, password := range []string{"", "unsafe\r\npassword", strings.Repeat("x", 4097)} {
		_, err := settingssmtp.NewSMTPSeed(config, password, []string{"smtp.example.test:587"}, true, cipher)
		require.ErrorIs(t, err, domain.ErrInvalidSMTP)
	}
	for _, targets := range [][]string{nil, {"other.example.test:587"}, {"https://smtp.example.test:587"}, make([]string, 17)} {
		_, err := settingssmtp.NewSMTPSeed(config, "fixture-password", targets, true, cipher)
		require.ErrorIs(t, err, domain.ErrInvalidSMTP)
	}
	insecure := config
	insecure.RequireTLS = false
	_, err = settingssmtp.NewSMTPSeed(insecure, "fixture-password", []string{"smtp.example.test:587"}, true, cipher)
	require.ErrorIs(t, err, domain.ErrInvalidSMTP)
	_, err = settingssmtp.NewSMTPSeed(config, "fixture-password", []string{"smtp.example.test:587"}, true, nil)
	require.ErrorIs(t, err, domain.ErrInvalidSMTP)
	_, err = settingssmtp.NewSMTPSeed(config, "fixture-password", []string{"smtp.example.test:587"}, true, failedSMTPSeedCipher{})
	require.ErrorIs(t, err, domain.ErrInvalidSMTP)
	require.NotContains(t, err.Error(), "private cipher details")
	relay := config
	relay.Username = ""
	seed, err = settingssmtp.NewSMTPSeed(relay, "", []string{"smtp.example.test:587"}, true, cipher)
	require.NoError(t, err)
	require.False(t, seed.PasswordSet)
}
