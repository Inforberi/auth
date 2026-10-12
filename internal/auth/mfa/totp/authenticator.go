package totp

import (
	"crypto/rand"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type Authenticator struct{}

func (Authenticator) Generate(issuer, account string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: issuer, AccountName: account,
		SecretSize: 32, Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1, Rand: rand.Reader,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

func (Authenticator) Match(secret, code string, now time.Time, lastStep int64) (int64, error) {
	if now.Unix() < 30 {
		return 0, domain.ErrInvalidCode
	}
	step := now.Unix() / 30
	matched := int64(-1)
	// Check every candidate, choosing the highest matching step; SQL persists it to prevent replay.
	for candidate := step - 1; candidate <= step+1; candidate++ {
		valid, err := totp.ValidateCustom(code, secret, time.Unix(candidate*30, 0),
			totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err != nil {
			return 0, domain.ErrUnavailable
		}
		if valid && candidate > lastStep {
			matched = candidate
		}
	}
	if matched < 0 {
		return 0, domain.ErrInvalidCode
	}
	return matched, nil
}
