package service

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func TestTemporaryLoginAuthority(t *testing.T) {
	s, repo, hash, _ := temporaryFixture(t)
	raw := "ExampleTemporaryPass123"
	repo.credential.PasswordHash, _ = hash.GenerateHash(context.Background(), []byte(raw))
	result, err := s.Login(context.Background(), "user@example.com", raw, "ip")
	if err != nil || len(result.Token) != 43 || repo.begun != 1 || hash.compared != 1 {
		t.Fatal("invalid setup authority", result, err)
	}
	if _, err := s.Login(context.Background(), "user@example.com", "wrong", "ip"); !errors.Is(err, domain.ErrInvalidTemporaryPassword) || repo.begun != 1 {
		t.Fatal("incorrect password issued authority", err)
	}
	hash.err = domain.ErrHashBusy
	if _, err := s.Login(context.Background(), "user@example.com", raw, "ip"); !errors.Is(err, domain.ErrHashBusy) || repo.begun != 1 {
		t.Fatal("hash overload issued authority", err)
	}
	s.loginLimit = denyLogin{err: domain.ErrLoginLimited}
	before := repo.found
	if _, err := s.Login(context.Background(), "user@example.com", raw, "ip"); !errors.Is(err, domain.ErrLoginLimited) || repo.found != before {
		t.Fatal("login limiter reached SQL", err)
	}
}

func TestTemporaryCompletionOrder(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct {
		name, token, password, confirmation string
		allow, same                         bool
		repoErr, hashErr, completeErr, want error
		hashes                              int
	}{
		{name: "oversize", token: strings.Repeat("x", 10000), want: domain.ErrInvalidTemporaryPassword},
		{name: "noncanonical", token: strings.Repeat("B", 43), want: domain.ErrInvalidTemporaryPassword},
		{name: "mismatch", token: token, password: "ExamplePass2", confirmation: "wrong", want: domain.ErrPasswordConfirmation},
		{name: "policy", token: token, password: "short", confirmation: "short", want: domain.ErrPasswordTooShort},
		{name: "limit", token: token, password: "ExamplePass2", confirmation: "ExamplePass2", want: domain.ErrRecoveryLimited},
		{name: "invalid authority", token: token, password: "ExamplePass2", confirmation: "ExamplePass2", allow: true, repoErr: domain.ErrInvalidTemporaryPassword, want: domain.ErrInvalidTemporaryPassword},
		{name: "same password", token: token, password: "ExamplePass2", confirmation: "ExamplePass2", allow: true, same: true, want: domain.ErrTemporaryPasswordReuse},
		{name: "hash busy", token: token, password: "ExamplePass2", confirmation: "ExamplePass2", allow: true, hashErr: domain.ErrHashBusy, want: domain.ErrHashBusy, hashes: 1},
		{name: "changed after hash", token: token, password: "ExamplePass2", confirmation: "ExamplePass2", allow: true, completeErr: domain.ErrInvalidTemporaryPassword, want: domain.ErrInvalidTemporaryPassword, hashes: 1},
		{name: "success", token: token, password: "ExamplePass2", confirmation: "ExamplePass2", allow: true, hashes: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, repo, hash, limit := temporaryFixture(t)
			limit.allow, repo.err, hash.err, repo.completeErr = tc.allow, tc.repoErr, tc.hashErr, tc.completeErr
			if tc.same {
				repo.credential.SecretDigest = resetDigest("temporary-password-secret:v1:" + tc.password)
			}
			if err := s.Complete(context.Background(), tc.token, tc.password, tc.confirmation, "ip"); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
			if hash.generated != tc.hashes || hash.compared != 0 {
				t.Fatal("unexpected hash work", hash.generated, hash.compared)
			}
			if tc.hashes == 0 && repo.completed != 0 {
				t.Fatal("invalid input reached mutation")
			}
		})
	}
}
