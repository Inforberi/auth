package service_test

import (
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func nativeMFATestFixture(t *testing.T) (*mfalogin.Login, *loginRepoStub, *limitStub, mfaservice.PrimaryProof, mfaservice.Cipher) {
	t.Helper()
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	proof := mfaservice.PrimaryProof{UserID: "11111111-1111-4111-8111-111111111111", AuthVersion: 1, Method: "password", Reference: "verified hash", VerifiedAt: time.Now().UTC()}
	repo, limits := &loginRepoStub{proof: proof}, &limitStub{allowed: true}
	login, err := mfalogin.NewLogin(repo, cipher, totp.Authenticator{}, limits, tokengenerate.New(), loginTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	return login, repo, limits, proof, cipher
}

func TestNativeTargetAndSharedFactorBudgets(t *testing.T) {
	login, repo, limits, proof, cipher := nativeMFATestFixture(t)
	scope := []accessdomain.PermissionKey{"orders.write", "orders.read"}
	challenge, err := login.StartNative(t.Context(), proof, mfaservice.NativeTarget{Audience: "orders", Scope: scope}, "::ffff:192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(repo.target.Scope, []accessdomain.PermissionKey{"orders.read", "orders.write"}) || scope[0] != "orders.write" || repo.digest == cipher.Digest("login:"+challenge.Token) || repo.binding == cipher.Digest("browser:"+challenge.Binding) {
		t.Fatal("unbound target or namespace collision")
	}
	scope[0] = "changed.permission"
	if repo.target.Scope[1] != "orders.write" {
		t.Fatal("mutable caller target retained")
	}
	input := mfalogin.CompleteLoginInput{Token: challenge.Token, Binding: challenge.Binding, Recovery: true, Code: strings.Repeat("0", 32), IP: "192.0.2.1"}
	attempt, err := login.PrepareNativeCompletion(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	check, recovery := attempt.Factor(proof.UserID)
	if attempt.UserID != proof.UserID || attempt.Digest != repo.digest || attempt.BindingHash != repo.binding || check == nil || recovery != cipher.Digest("recovery:"+string(proof.UserID)+":"+input.Code) {
		t.Fatal("native factor material not server-bound")
	}
	if _, err := login.Complete(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	if len(limits.keys) != 13 || !slices.Equal(limits.keys[6:8], limits.keys[11:13]) || limits.keys[0] != limits.keys[6] {
		t.Fatal("native bypassed shared user guessing budgets")
	}
}

func TestNativeTargetAdmission(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*mfaservice.PrimaryProof, *mfaservice.NativeTarget, *string)
	}{
		{"admin", func(p *mfaservice.PrimaryProof, _ *mfaservice.NativeTarget, _ *string) { p.Administrative = true }},
		{"OIDC", func(p *mfaservice.PrimaryProof, _ *mfaservice.NativeTarget, _ *string) { p.Method = "oidc" }},
		{"empty audience", func(_ *mfaservice.PrimaryProof, t *mfaservice.NativeTarget, _ *string) { t.Audience = "" }},
		{"duplicate", func(_ *mfaservice.PrimaryProof, t *mfaservice.NativeTarget, _ *string) {
			t.Scope = append(t.Scope, t.Scope[0])
		}},
		{"too many", func(_ *mfaservice.PrimaryProof, t *mfaservice.NativeTarget, _ *string) {
			t.Scope = make([]accessdomain.PermissionKey, 65)
		}},
		{"IP zone", func(_ *mfaservice.PrimaryProof, _ *mfaservice.NativeTarget, ip *string) { *ip = "fe80::1%en0" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			login, repo, limits, proof, _ := nativeMFATestFixture(t)
			target, ip := mfaservice.NativeTarget{Audience: "orders", Scope: []accessdomain.PermissionKey{"orders.read"}}, "192.0.2.1"
			test.change(&proof, &target, &ip)
			if result, err := login.StartNative(t.Context(), proof, target, ip); result != nil || !errors.Is(err, domain.ErrProofRequired) || repo.calls != 0 || limits.calls != 0 {
				t.Fatal("invalid native challenge reached dependencies", err)
			}
		})
	}
}
