package service

import (
	"crypto/rand"
	"encoding/hex"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type RecoveryCodes struct {
	Codes []string `json:"-"`
}

func GenerateRecoveryCodes(cipher Cipher, user accountdomain.UserID) ([]string, []string, error) {
	codes, digests := make([]string, domain.RecoveryCodeCount), make([]string, domain.RecoveryCodeCount)
	for index := range codes {
		var entropy [16]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return nil, nil, err
		}
		codes[index] = hex.EncodeToString(entropy[:])
		digests[index] = cipher.Digest("recovery:" + string(user) + ":" + codes[index])
	}
	return codes, digests, nil
}
