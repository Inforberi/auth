package service

import (
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type Enrollment struct {
	Token     string `json:"-"`
	Secret    string `json:"-"`
	URI       string `json:"-"`
	ExpiresAt time.Time
}

func PrepareEnrollment(code Authenticator, cipher Cipher, issuer string, user accountdomain.UserID) (*Enrollment, []byte, error) {
	secret, uri, err := code.Generate(issuer, string(user))
	if err != nil {
		return nil, nil, domain.ErrUnavailable
	}
	encrypted, err := cipher.Seal([]byte(string(user) + "\x00" + secret))
	if err != nil {
		return nil, nil, domain.ErrUnavailable
	}
	token, err := RandomToken()
	if err != nil {
		return nil, nil, err
	}
	return &Enrollment{Token: token, Secret: secret, URI: uri}, encrypted, nil
}
