package service

import (
	"context"
	"errors"
	"testing"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

type operatorRecoveryFixture struct {
	version                  int64
	previews, hashes, resets int
	err                      error
	request                  domain.OperatorRecovery
	hash                     string
}

func (f *operatorRecoveryFixture) OperatorRecoveryTarget(context.Context, accountdomain.UserID) (*OperatorRecoveryTarget, error) {
	f.previews++
	return &OperatorRecoveryTarget{AuthVersion: f.version}, f.err
}

func (f *operatorRecoveryFixture) ResetAdministratorPassword(_ context.Context, request domain.OperatorRecovery, hash string) (int64, error) {
	f.resets++
	f.request, f.hash = request, hash
	return f.version + 1, nil
}

func (f *operatorRecoveryFixture) GenerateHash(context.Context, []byte) (string, error) {
	f.hashes++
	return "synthetic-hash", nil
}
func (*operatorRecoveryFixture) Compare(context.Context, string, string) error { return nil }

func operatorRequest() domain.OperatorRecovery {
	return domain.OperatorRecovery{UserID: "11111111-1111-4111-8111-111111111111", ExpectedVersion: 3, Environment: "test", Reason: "INC-123"}
}

func TestOperatorRecoveryService(t *testing.T) {
	for _, mode := range []string{"ok", "user", "version", "environment", "reason", "control", "password", "denied", "stale"} {
		t.Run(mode, func(t *testing.T) {
			f := &operatorRecoveryFixture{version: 3}
			s := NewOperatorRecovery(f, f)
			request := operatorRequest()
			password := []byte("Validpassword1")
			want := domain.ErrOperatorRecoveryInput
			switch mode {
			case "ok":
				want = nil
			case "user":
				request.UserID = "bad"
			case "version":
				request.ExpectedVersion = 0
			case "environment":
				request.Environment = "wrong"
			case "reason":
				request.Reason = " "
			case "control":
				request.Reason = "INC-123\nextra"
			case "password":
				password = []byte("short")
				want = domain.ErrOperatorPasswordPolicy
			case "denied":
				f.err = domain.ErrOperatorRecoveryDenied
				want = f.err
			case "stale":
				f.version = 4
				want = domain.ErrOperatorRecoveryConflict
			}
			version, err := s.Reset(context.Background(), request, password)
			if !errors.Is(err, want) {
				t.Fatal(err, want)
			}
			if mode == "ok" {
				if version != 4 || f.hashes != 1 || f.resets != 1 || f.hash != "synthetic-hash" || f.request != request {
					t.Fatal("wrong reset")
				}
			} else if f.hashes != 0 || f.resets != 0 {
				t.Fatal("work before admission/validation")
			}
		})
	}
	if _, err := NewOperatorRecovery(nil, nil).Preview(context.Background(), "bad"); !errors.Is(err, domain.ErrOperatorRecoveryInput) {
		t.Fatal(err)
	}
}
