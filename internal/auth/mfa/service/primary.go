package service

import (
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

// PrimaryProof comes from a verified method adapter, never from an HTTP request.
type PrimaryProof struct {
	ProviderVersion int64
	Administrative  bool
	UserID          accountdomain.UserID
	AuthVersion     int64
	Method          string
	Reference       string
	Issuer          string
	VerifiedAt      time.Time
}

func ValidPrimary(p PrimaryProof) bool {
	if p.Administrative && p.Method != "password" {
		return false
	}
	if !accountdomain.ValidUserID(p.UserID) || p.AuthVersion < 1 || p.VerifiedAt.IsZero() {
		return false
	}
	switch p.Method {
	case "password":
		return p.Issuer == "" && len(p.Reference) > 0 && len(p.Reference) <= 1024
	case "emailotp":
		return p.Issuer == "" && accountdomain.ValidUserID(accountdomain.UserID(p.Reference))
	case "oidc":
		return (accountdomain.IdentityKey{Issuer: p.Issuer, Subject: p.Reference}).Validate() == nil
	default:
		return false
	}
}
