package service

import (
	"encoding/hex"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type Proof struct {
	UserID      accountdomain.UserID
	TokenHash   string
	AuthVersion int64
}

func (p Proof) Validate() error {
	if !ValidProof(p) {
		return domain.ErrProofRequired
	}
	return nil
}

func ValidProof(proof Proof) bool {
	if len(proof.TokenHash) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(proof.TokenHash)
	return accountdomain.ValidUserID(proof.UserID) && proof.AuthVersion > 0 && err == nil && len(decoded) == 32
}
