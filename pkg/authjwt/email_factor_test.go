package authjwt

import (
	"testing"
	"time"
)

func TestEmailFactorClaims(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		methods []string
		proof   bool
		valid   bool
	}{
		{[]string{"pwd", "email_otp"}, true, true},
		{[]string{"email_otp", "pwd"}, true, true},
		{[]string{"pwd", "email_otp"}, false, false},
		{[]string{"emailotp", "email_otp"}, true, false},
		{[]string{"oidc", "email_otp"}, true, false},
		{[]string{"email_otp"}, true, false},
		{[]string{"pwd", "email_otp", "otp"}, true, false},
	} {
		claims := testClaims(now)
		claims.Methods = tc.methods
		if tc.proof {
			at := now.Add(-30 * time.Second).Unix()
			claims.MFATime = &at
		}
		err := claims.Validate(Expectations{Issuer: claims.Issuer, Audience: claims.Audience, Mode: Strict}, now)
		if (err == nil) != tc.valid {
			t.Fatalf("methods %v, proof=%v: %v", tc.methods, tc.proof, err)
		}
	}
}
