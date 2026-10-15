package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type temporaryTestHash struct {
	generated, compared int
	err                 error
}

func (h *temporaryTestHash) GenerateHash(_ context.Context, raw []byte) (string, error) {
	h.generated++
	digest := sha256.Sum256(raw)
	return "test-hash:" + hex.EncodeToString(digest[:]), h.err
}

func (h *temporaryTestHash) Compare(_ context.Context, raw, hash string) error {
	h.compared++
	if h.err != nil {
		return h.err
	}
	digest := sha256.Sum256([]byte(raw))
	if hash != "test-hash:"+hex.EncodeToString(digest[:]) {
		return errors.New("incorrect password")
	}
	return nil
}

type temporaryTestRepo struct {
	credential                               domain.TemporaryCredential
	command                                  accountservice.ProvisionCommand
	issued, found, begun, checked, completed int
	reused                                   bool
	err, completeErr                         error
	lookupErr                                error
}

func (r *temporaryTestRepo) FindTemporaryProvision(context.Context, accountservice.ProvisionCommand) (*TemporaryIssueResult, error) {
	if r.lookupErr != nil {
		return nil, r.lookupErr
	}
	if r.reused {
		return &TemporaryIssueResult{UserID: "00000000-0000-4000-8000-000000000002", Reused: true}, nil
	}
	return nil, nil
}

func (r *temporaryTestRepo) FindTemporaryReissue(_ context.Context, input TemporaryReissueInput) (*TemporaryIssueResult, error) {
	if r.lookupErr != nil {
		return nil, r.lookupErr
	}
	if r.reused {
		return &TemporaryIssueResult{UserID: input.UserID, Reused: true}, nil
	}
	return nil, nil
}

func (r *temporaryTestRepo) ProvisionTemporary(_ context.Context, command accountservice.ProvisionCommand, credential domain.TemporaryCredential, _ time.Duration) (*TemporaryIssueResult, error) {
	r.command, r.credential = command, credential
	r.issued++
	return &TemporaryIssueResult{UserID: "00000000-0000-4000-8000-000000000002", Reused: r.reused, ExpiresAt: time.Now().Add(time.Hour)}, r.err
}

func (r *temporaryTestRepo) ReissueTemporary(_ context.Context, input TemporaryReissueInput, credential domain.TemporaryCredential, _, _ time.Duration) (*TemporaryIssueResult, error) {
	r.credential = credential
	r.issued++
	return &TemporaryIssueResult{UserID: input.UserID, Reused: r.reused}, r.err
}

func (r *temporaryTestRepo) FindTemporary(context.Context, string) (*domain.TemporaryCredential, error) {
	r.found++
	return &r.credential, r.err
}

func (r *temporaryTestRepo) BeginTemporary(context.Context, domain.TemporaryCredential, string, time.Duration) (time.Time, error) {
	r.begun++
	return time.Now().Add(time.Minute), r.err
}

func (r *temporaryTestRepo) CheckTemporarySetup(context.Context, string) (*domain.TemporaryCredential, error) {
	r.checked++
	return &r.credential, r.err
}

func (r *temporaryTestRepo) CompleteTemporary(context.Context, string, string) error {
	r.completed++
	return r.completeErr
}

func temporaryFixture(t *testing.T) (*TemporaryPasswordService, *temporaryTestRepo, *temporaryTestHash, *recoveryLimit) {
	t.Helper()
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "password-reset:v1")
	if err != nil {
		t.Fatal(err)
	}
	repo, hash, limit := &temporaryTestRepo{}, &temporaryTestHash{}, &recoveryLimit{allow: true}
	cfg := TemporaryPasswordConfig{Enabled: true, TTL: time.Hour, SetupTTL: 5 * time.Minute, ReissueCooldown: time.Minute, IssueActorAttemptsPerMinute: 30, IssueProjectAttemptsPerMinute: 100, SetupProjectAttemptsPerMinute: 100}
	return NewTemporaryPassword(repo, hash, limit, cipher.Digest, denyLogin{}, cfg), repo, hash, limit
}

func TestTemporarySecretIssuedOnce(t *testing.T) {
	s, repo, hash, _ := temporaryFixture(t)
	input := TemporaryProvisionInput{Actor: temporaryActor(), IdempotencyKey: "00000000-0000-4000-8000-000000000003", Email: " USER@example.com "}
	first, err := s.Provision(context.Background(), input)
	if err != nil || len(first.Password) != 43 || repo.command.Input.Email != "user@example.com" || repo.command.Input.Invite {
		t.Fatal("invalid creation", first, err)
	}
	if repo.credential.PasswordHash == first.Password || len(repo.credential.SecretDigest) != 64 || hash.generated != 1 {
		t.Fatal("plaintext credential or extra hash")
	}
	encoded, err := json.Marshal(first)
	if err != nil || strings.Contains(string(encoded), first.Password) {
		t.Fatal("automatic serialization revealed temporary secret")
	}
	fingerprint := repo.command.Fingerprint
	repo.reused = true
	second, err := s.Provision(context.Background(), input)
	if err != nil || second.Password != "" || second.UserID != first.UserID || repo.command.Fingerprint != fingerprint {
		t.Fatal("replay exposed secret", err)
	}
	reissued, err := s.Reissue(context.Background(), TemporaryReissueInput{Actor: input.Actor, UserID: first.UserID, IdempotencyKey: input.IdempotencyKey})
	if err != nil || reissued.Password != "" {
		t.Fatal("reissue replay exposed secret", err)
	}
	if hash.generated != 1 || repo.issued != 1 {
		t.Fatal("committed retry repeated expensive hash or mutation")
	}
}

func TestTemporaryIssueValidationAndLimits(t *testing.T) {
	s, repo, hash, limit := temporaryFixture(t)
	if _, err := s.Provision(context.Background(), TemporaryProvisionInput{}); !errors.Is(err, accountdomain.ErrProvisionConflict) || hash.generated != 0 {
		t.Fatal("invalid identifiers reached hash", err)
	}
	input := TemporaryProvisionInput{Actor: temporaryActor(), IdempotencyKey: "00000000-0000-4000-8000-000000000003", Email: "user@example.com"}
	limit.allow = false
	if _, err := s.Provision(context.Background(), input); !errors.Is(err, domain.ErrRecoveryLimited) || repo.issued != 0 || hash.generated != 0 {
		t.Fatal("quota bypass", err)
	}
	limit.allow = true
	limit.err = errors.New("redis failed")
	if _, err := s.Provision(context.Background(), input); !errors.Is(err, limit.err) || hash.generated != 0 {
		t.Fatal("limiter failure reached hash", err)
	}
	s.cfg.Enabled = false
	if _, err := s.Provision(context.Background(), input); !errors.Is(err, domain.ErrTemporaryPasswordDisabled) {
		t.Fatal(err)
	}
}

func temporaryActor() accessservice.Principal {
	return accessservice.Principal{UserID: "00000000-0000-4000-8000-000000000001", TokenHash: strings.Repeat("a", 64)}
}

func TestTemporaryUnauthorizedPreflightDoesNotHash(t *testing.T) {
	s, repo, hash, _ := temporaryFixture(t)
	repo.lookupErr = accessdomain.ErrForbidden
	input := TemporaryProvisionInput{Actor: temporaryActor(), IdempotencyKey: "00000000-0000-4000-8000-000000000003", Email: "user@example.com"}
	if _, err := s.Provision(context.Background(), input); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatal(err)
	}
	if _, err := s.Reissue(context.Background(), TemporaryReissueInput{Actor: input.Actor, UserID: "00000000-0000-4000-8000-000000000002", IdempotencyKey: input.IdempotencyKey}); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatal(err)
	}
	if hash.generated != 0 || repo.issued != 0 {
		t.Fatal("unauthorized lookup reached Argon2 or mutation")
	}
}
