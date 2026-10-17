package service

import (
	"context"
	"errors"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type logoutRepo struct {
	refreshRepo
	logoutCalls int
	verifier    string
	bound       RefreshBinding
	logoutErr   error
}

func (r *logoutRepo) LogoutRefresh(_ context.Context, binding RefreshBinding, verifier string) error {
	r.logoutCalls++
	r.bound, r.verifier = binding, verifier
	return r.logoutErr
}

func TestNativeLogoutBoundary(t *testing.T) {
	for _, mode := range []string{"valid", "unknown", "removed after lookup", "malformed", "IP", "lookup budget", "owner budget", "dependency", "commit", "busy", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			svc, base, _, limiter, input := refreshServiceFixture(t)
			repo := &logoutRepo{refreshRepo: *base}
			svc.repo = repo
			ctx := t.Context()
			var want error
			calls := 1
			switch mode {
			case "unknown":
				repo.lookupErr = domain.ErrInvalidRefresh
				calls = 0
			case "removed after lookup":
				repo.logoutErr = domain.ErrInvalidRefresh
			case "malformed":
				input.Token = "jwt-not-refresh"
				want = domain.ErrInvalidRefresh
				calls = 0
			case "IP":
				input.IP = "invalid"
				want = domain.ErrInvalidRequest
				calls = 0
			case "lookup budget":
				limiter.lookupErr = domain.ErrRateLimited
				want = domain.ErrRateLimited
				calls = 0
			case "owner budget":
				limiter.err = domain.ErrRateLimited
				want = domain.ErrRateLimited
				calls = 0
			case "dependency":
				repo.lookupErr = domain.ErrUnavailable
				want = domain.ErrUnavailable
				calls = 0
			case "commit":
				repo.logoutErr = domain.ErrUnavailable
				want = domain.ErrUnavailable
			case "busy":
				for range cap(svc.admission) {
					svc.admission <- struct{}{}
				}
				want = authjwt.ErrBusy
				calls = 0
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
				calls = 0
			}
			if err := svc.Logout(ctx, input); !errors.Is(err, want) || repo.logoutCalls != calls || repo.rotations != 0 {
				t.Fatal("wrong logout outcome", err, repo.logoutCalls)
			}
			if mode == "valid" {
				verifier, err := domain.RefreshVerifier(input.Token)
				if err != nil || repo.verifier != verifier || repo.verifier == input.Token || repo.bound != repo.binding {
					t.Fatal("raw secret or caller-selected owner reached repository")
				}
			}
		})
	}
}
