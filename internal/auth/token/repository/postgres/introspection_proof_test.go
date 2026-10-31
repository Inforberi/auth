package postgres

import (
	"testing"
	"time"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func TestAccessProofMatchesRecordedMFAMethod(t *testing.T) {
	now := time.Unix(1700000000, 0)
	verified := now.Add(-time.Minute)
	mfa := now.Unix()
	for _, method := range []mfadomain.Method{"", mfadomain.TOTP, mfadomain.RecoveryCode} {
		proof := service.SessionProof{Method: "password", VerifiedAt: verified, MFAVerifiedAt: &now, MFAMethod: method, AuthVersion: 1, Deadline: now.Add(time.Minute)}
		for _, claim := range []string{"mfa", "otp", "recovery", "email", ""} {
			claims := authjwt.Claims{Methods: []string{"pwd", claim}, AuthTime: verified.Unix(), MFATime: &mfa, AuthVersion: 1, ExpiresAt: now.Add(time.Minute).Unix()}
			if matchesAccessProof(claims, proof) != (claim == method.AuthenticationMethod()) {
				t.Fatalf("method=%q claim=%q", method, claim)
			}
		}
	}
	proof := service.SessionProof{Method: "password", VerifiedAt: verified, AuthVersion: 1, Deadline: now.Add(time.Minute)}
	claims := authjwt.Claims{Methods: []string{"pwd", "mfa"}, AuthTime: verified.Unix(), AuthVersion: 1, ExpiresAt: now.Add(time.Minute).Unix()}
	if matchesAccessProof(claims, proof) {
		t.Fatal("MFA claim accepted without a recorded proof")
	}
}
