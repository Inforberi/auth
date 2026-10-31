package service

import (
	"errors"
	"testing"
	"time"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func TestSigningPreservesMFAMethod(t *testing.T) {
	now := time.Unix(1700000000, 0)
	for _, tc := range []struct {
		method mfadomain.Method
		want   string
	}{{"", "mfa"}, {mfadomain.TOTP, "otp"}, {mfadomain.RecoveryCode, "recovery"}, {mfadomain.EmailCode, "email_otp"}, {"unknown", ""}, {"telegram", ""}} {
		signer := new(exchangeSigner)
		svc := Service{signer: signer, ttl: time.Minute}
		proof := SessionProof{Method: "password", VerifiedAt: now.Add(-time.Minute), MFAVerifiedAt: &now, MFAMethod: tc.method, Now: now, Deadline: now.Add(time.Minute)}
		_, err := svc.signSession(t.Context(), ExchangeInput{}, authjwt.Strict, proof)
		if tc.want == "" {
			if !errors.Is(err, domain.ErrUnavailable) {
				t.Fatalf("unknown factor signed: %q: %v", tc.method, err)
			}
			continue
		}
		if err != nil || len(signer.claims.Methods) != 2 || signer.claims.Methods[1] != tc.want {
			t.Fatalf("wrong assurance %q: %+v %v", tc.method, signer.claims, err)
		}
	}
}
