package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type limitStub struct {
	calls   int
	allowed bool
	err     error
	keys    []string
	counts  []int
}

func (l *limitStub) Allow(_ context.Context, key string, count int, _ time.Duration) (bool, error) {
	l.calls++
	l.keys = append(l.keys, key)
	l.counts = append(l.counts, count)
	return l.allowed, l.err
}

func (l *limitStub) AllowAll(_ context.Context, budgets []Budget) (bool, error) {
	for _, budget := range budgets {
		l.calls++
		l.keys = append(l.keys, budget.Key)
		l.counts = append(l.counts, budget.Count)
	}
	return l.allowed, l.err
}

type repositoryStub struct {
	Repository
	proof     Proof
	digest    string
	encrypted []byte
	err       error
}

func (r *repositoryStub) SaveEnrollment(_ context.Context, proof Proof, digest string, encrypted []byte) (time.Time, error) {
	r.proof, r.digest, r.encrypted = proof, digest, encrypted
	return time.Now().Add(10 * time.Minute), r.err
}

func (r *repositoryStub) ConfirmEnrollment(_ context.Context, _ Proof, _ string, _ Check, digests []string) error {
	if len(digests) != domain.RecoveryCodeCount {
		panic("recovery count")
	}
	return r.err
}

func TestEnrollmentBoundaries(t *testing.T) {
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	repo := &repositoryStub{}
	limit := &limitStub{allowed: true}
	svc := New(repo, cipher, totp.Authenticator{}, limit, "Auth")
	proof := Proof{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64), AuthVersion: 1}
	enrollment, err := svc.StartEnrollment(context.Background(), proof)
	if err != nil || len(enrollment.Token) != 43 || repo.proof != proof || len(repo.digest) != 64 {
		t.Fatal(enrollment, err)
	}
	if strings.Contains(string(repo.encrypted), enrollment.Secret) {
		t.Fatal("plaintext stored")
	}
	if _, err := svc.check(accountdomain.UserID("22222222-2222-4222-8222-222222222222"), "123456")(repo.encrypted, -1, time.Now()); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatal("cross-user secret accepted", err)
	}
	encoded, err := json.Marshal(enrollment)
	if err != nil || strings.Contains(string(encoded), enrollment.Secret) || strings.Contains(string(encoded), enrollment.Token) || strings.Contains(string(encoded), "otpauth") {
		t.Fatal("secret serialization", err)
	}
	input := ConfirmInput{Proof: proof, Token: enrollment.Token, Code: "123456"}
	codes, err := svc.ConfirmEnrollment(context.Background(), input)
	if err != nil || len(codes.Codes) != 10 {
		t.Fatal(codes, err)
	}
	seen := make(map[string]bool)
	for _, code := range codes.Codes {
		if !domain.ValidRecoveryCode(code) || seen[code] {
			t.Fatal("invalid/duplicate recovery")
		}
		seen[code] = true
	}
	encoded, err = json.Marshal(codes)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("recovery serialization", err)
	}
	repo.err = domain.ErrConflict
	if codes, err := svc.ConfirmEnrollment(context.Background(), input); codes != nil || !errors.Is(err, domain.ErrConflict) {
		t.Fatal("codes leaked before commit", err)
	}
	limit.allowed = false
	if _, err := svc.StartEnrollment(context.Background(), proof); !errors.Is(err, domain.ErrLimited) {
		t.Fatal("limit bypass", err)
	}
	limit.allowed = true
	limit.err = errors.New("Redis down")
	if _, err := svc.StartEnrollment(context.Background(), proof); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatal("dependency fail-open", err)
	}
	before := limit.calls
	if _, err := svc.StartEnrollment(context.Background(), Proof{}); !errors.Is(err, domain.ErrProofRequired) || limit.calls != before {
		t.Fatal("invalid proof order", err)
	}
}
