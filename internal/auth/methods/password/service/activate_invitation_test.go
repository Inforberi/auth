package service

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type activationRepo struct {
	checked, consumed    string
	checkErr, consumeErr error
}

func (r *activationRepo) CheckInvitation(_ context.Context, digest string) error {
	r.checked = digest
	return r.checkErr
}

func (r *activationRepo) ActivateInvitation(_ context.Context, digest, hash string) error {
	r.consumed = digest + ":" + hash
	return r.consumeErr
}

type activationHash struct {
	calls int
	err   error
}

func (h *activationHash) GenerateHash(context.Context, []byte) (string, error) {
	h.calls++
	return "activation-hash", h.err
}

func (*activationHash) Compare(context.Context, string, string) error {
	panic("activation must not compare a password")
}

func TestActivationOrderAndFailures(t *testing.T) {
	validToken := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct {
		name, token, password, confirmation string
		enabled, allow                      bool
		checkErr, hashErr, consumeErr, want error
		hashes                              int
	}{
		{name: "disabled", want: accountdomain.ErrProvisionDisabled},
		{name: "bad token", enabled: true, token: strings.Repeat("x", 1024), want: accountdomain.ErrInvalidInvitation},
		{name: "noncanonical", enabled: true, token: strings.Repeat("B", 43), want: accountdomain.ErrInvalidInvitation},
		{name: "mismatch", enabled: true, token: validToken, password: "ExamplePass2", confirmation: "other", want: domain.ErrPasswordConfirmation},
		{name: "policy", enabled: true, token: validToken, password: "short", confirmation: "short", want: domain.ErrPasswordTooShort},
		{name: "limited", enabled: true, token: validToken, password: "ExamplePass2", confirmation: "ExamplePass2", want: domain.ErrRecoveryLimited},
		{name: "invalid authority", enabled: true, allow: true, token: validToken, password: "ExamplePass2", confirmation: "ExamplePass2", checkErr: accountdomain.ErrInvalidInvitation, want: accountdomain.ErrInvalidInvitation},
		{name: "hash busy", enabled: true, allow: true, token: validToken, password: "ExamplePass2", confirmation: "ExamplePass2", hashErr: domain.ErrHashBusy, want: domain.ErrHashBusy, hashes: 1},
		{name: "stale after hash", enabled: true, allow: true, token: validToken, password: "ExamplePass2", confirmation: "ExamplePass2", consumeErr: accountdomain.ErrInvalidInvitation, want: accountdomain.ErrInvalidInvitation, hashes: 1},
		{name: "success", enabled: true, allow: true, token: validToken, password: "ExamplePass2", confirmation: "ExamplePass2", hashes: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cipher, err := secretbox.New("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
			if err != nil {
				t.Fatal(err)
			}
			repo := &activationRepo{checkErr: tc.checkErr, consumeErr: tc.consumeErr}
			hash := &activationHash{err: tc.hashErr}
			r := NewRecovery(nil, cipher, &recoveryLimit{allow: tc.allow}, nil, hash, Config{})
			s := NewActivation(repo, r, accountservice.InvitationConfig{Enabled: tc.enabled, ActivationGlobalLimit: 100})
			if err := s.Activate(context.Background(), tc.token, tc.password, tc.confirmation, "ip"); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
			if hash.calls != tc.hashes {
				t.Fatal("unexpected hashing", hash.calls)
			}
			if tc.name == "success" && (len(repo.checked) != 64 || repo.consumed != repo.checked+":activation-hash") {
				t.Fatal("unexpected consumption")
			}
			if tc.name == "limited" && repo.checked != "" {
				t.Fatal("rate-limited request reached SQL")
			}
		})
	}
}
