package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type protectedRepo struct {
	reads, writes          int
	digest, expected, hash string
	err                    error
}

func (r *protectedRepo) ProtectedRecoveryHash(_ context.Context, digest string) (string, error) {
	r.reads++
	r.digest = digest
	return "compromised-hash", r.err
}

func (r *protectedRepo) RecoverProtectedAccount(ctx context.Context, digest, expected, hash string) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("missing deadline")
	}
	r.writes++
	r.digest, r.expected, r.hash = digest, expected, hash
	return r.err
}

type protectedHash struct {
	compares, hashes    int
	compareErr, hashErr error
}

func (h *protectedHash) Compare(_, _ string) error { h.compares++; return h.compareErr }
func (h *protectedHash) GenerateHash(_ []byte) (string, error) {
	h.hashes++
	return "replacement-hash", h.hashErr
}

func TestProtectedRecovery(t *testing.T) {
	for _, tc := range []struct {
		name, token, password, confirmation          string
		allow                                        bool
		limitErr, repoErr, compareErr, hashErr, want error
		reads, compares, hashes, writes              int
	}{
		{"success", strings.Repeat("A", 43), "ExamplePass2", "ExamplePass2", true, nil, nil, domain.ErrPasswordHashMismatch, nil, nil, 1, 1, 1, 1},
		{"token bounds", strings.Repeat("A", 129), "ExamplePass2", "ExamplePass2", true, nil, nil, nil, nil, accountdomain.ErrInvalidAccountRecovery, 0, 0, 0, 0},
		{"noncanonical", strings.Repeat("A", 42) + "B", "ExamplePass2", "ExamplePass2", true, nil, nil, nil, nil, accountdomain.ErrInvalidAccountRecovery, 0, 0, 0, 0},
		{"password policy", strings.Repeat("A", 43), "weak", "weak", true, nil, nil, nil, nil, domain.ErrPasswordTooShort, 0, 0, 0, 0},
		{"confirmation", strings.Repeat("A", 43), "ExamplePass2", "ExamplePass3", true, nil, nil, nil, nil, domain.ErrPasswordConfirmation, 0, 0, 0, 0},
		{"limited", strings.Repeat("A", 43), "ExamplePass2", "ExamplePass2", false, nil, nil, nil, nil, domain.ErrRecoveryLimited, 0, 0, 0, 0},
		{"redis failure", strings.Repeat("A", 43), "ExamplePass2", "ExamplePass2", true, context.DeadlineExceeded, nil, nil, nil, context.DeadlineExceeded, 0, 0, 0, 0},
		{"invalid proof before hashing", strings.Repeat("A", 43), "ExamplePass2", "ExamplePass2", true, nil, accountdomain.ErrInvalidAccountRecovery, nil, nil, accountdomain.ErrInvalidAccountRecovery, 1, 0, 0, 0},
		{"same compromised password", strings.Repeat("A", 43), "ExamplePass2", "ExamplePass2", true, nil, nil, nil, nil, domain.ErrSamePassword, 1, 1, 0, 0},
		{"malformed hash fails closed", strings.Repeat("A", 43), "ExamplePass2", "ExamplePass2", true, nil, nil, domain.ErrHashFormat, nil, domain.ErrHashFormat, 1, 1, 0, 0},
		{"hash failure", strings.Repeat("A", 43), "ExamplePass2", "ExamplePass2", true, nil, nil, domain.ErrPasswordHashMismatch, context.Canceled, context.Canceled, 1, 1, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "password-reset:v1")
			if err != nil {
				t.Fatal(err)
			}
			repo := &protectedRepo{err: tc.repoErr}
			hash := &protectedHash{compareErr: tc.compareErr, hashErr: tc.hashErr}
			recovery := NewRecovery(nil, cipher, &recoveryLimit{allow: tc.allow, err: tc.limitErr}, nil, hash, Config{})
			err = NewProtectedRecovery(repo, recovery).Recover(context.Background(), tc.token, tc.password, tc.confirmation, "ip")
			if !errors.Is(err, tc.want) || repo.reads != tc.reads || hash.compares != tc.compares || hash.hashes != tc.hashes || repo.writes != tc.writes {
				t.Fatal(err, repo, hash)
			}
			if repo.writes > 0 && (repo.digest != resetDigest(tc.token) || repo.expected != "compromised-hash" || repo.hash != "replacement-hash") {
				t.Fatal("wrong transactional handoff", repo)
			}
			if len(recovery.hashSlots) != 0 {
				t.Fatal("hash slot leaked")
			}
		})
	}
}

func TestProtectedRecoverySharesHashBudget(t *testing.T) {
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "password-reset:v1")
	if err != nil {
		t.Fatal(err)
	}
	hash := &protectedHash{}
	r := NewRecovery(nil, cipher, &recoveryLimit{allow: true}, nil, hash, Config{})
	r.hashSlots <- struct{}{}
	r.hashSlots <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err = NewProtectedRecovery(&protectedRepo{}, r).Recover(ctx, strings.Repeat("A", 43), "ExamplePass2", "ExamplePass2", "ip")
	if !errors.Is(err, context.DeadlineExceeded) || hash.compares != 0 || hash.hashes != 0 || len(r.hashSlots) != 2 {
		t.Fatal("independent unbounded hash pool", err)
	}
}
